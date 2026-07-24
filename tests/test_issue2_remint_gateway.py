#!/usr/bin/env python3
"""issue#2: remint uses resolve_gateway (regional CAG+csapip), not stock GZ4.

- empty / DEFAULT_CAG_HOST → cloud_pc regional CAG wins
- MintRequest carries cag_port + csapip
- CCA- instance_id rejected as vmid
- main.py --host default is empty for keepalive CLIs
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from l3.connectstr_mint import MintRequest, MintResult  # noqa: E402
from l3.gateway_config import DEFAULT_CAG_HOST, GatewayEndpoints  # noqa: E402
import l3.connectstr_mint as cm  # noqa: E402
import l3.gateway_config as gc  # noqa: E402
import l3.spice_oracle_keepalive_loop as sok  # noqa: E402

REGIONAL_CAG = "36.212.224.100"
REGIONAL_PORT = 8899
REGIONAL_CSAP = "192.168.1.200:30087"
MACHINE_UUID = "c0d88cfc-9135-4e24-8fe9-8a3e2af49172"
INSTANCE_CCA = "CCA-49d403ad5163434db17bec551eea4a99"


def _gw() -> GatewayEndpoints:
    return GatewayEndpoints(
        cag_host=REGIONAL_CAG,
        cag_port=REGIONAL_PORT,
        csapip=REGIONAL_CSAP,
        source="cloud_pc:cloud_pc.json",
    )


def _ok_mint(req, *, plain_path=None, write_plain=True, dry_run=False):
    if plain_path and write_plain and not dry_run:
        Path(plain_path).write_text("NEWPLAIN-ISSUE2", encoding="utf-8")
    return MintResult(
        ok=True,
        plain_path=str(plain_path) if plain_path else None,
        plain_fields={"plain_sha16": "deadbeefcafebabe"},
        written=bool(write_plain and plain_path and not dry_run),
        vmid=req.vmid,
        csapip=req.csapip,
        url=f"https://{req.cag_host}:{req.cag_port}/x",
    )


def test_default_gz4_host_does_not_override_cloud_pc(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("STALE", encoding="utf-8")
    captured: list[MintRequest] = []

    def capture(req, **kw):
        captured.append(req)
        return _ok_mint(req, **kw)

    with mock.patch.object(gc, "resolve_gateway", return_value=_gw()) as m_rg, mock.patch.object(
        cm, "mint_connectstr", side_effect=capture
    ), mock.patch.object(cm, "load_vmid_from_cloud_pc", return_value=MACHINE_UUID):
        out = sok._try_remint_connectstr(
            plain=plain,
            host=DEFAULT_CAG_HOST,  # stock GZ4 must not pin
            vmid_hint=MACHINE_UUID,
            timeout_s=5.0,
        )

    assert m_rg.called
    assert m_rg.call_args.kwargs.get("cag_host") is None
    assert out.get("ok") is True, out
    assert out.get("cag_host") == REGIONAL_CAG, out
    assert out.get("gateway_source", "").startswith("cloud_pc")
    assert captured, "mint not called"
    req = captured[0]
    assert req.cag_host == REGIONAL_CAG
    assert req.cag_port == REGIONAL_PORT
    assert req.csapip == REGIONAL_CSAP
    assert req.vmid == MACHINE_UUID


def test_empty_host_uses_regional(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("STALE", encoding="utf-8")
    captured: list[MintRequest] = []

    def capture(req, **kw):
        captured.append(req)
        return _ok_mint(req, **kw)

    with mock.patch.object(gc, "resolve_gateway", return_value=_gw()), mock.patch.object(
        cm, "mint_connectstr", side_effect=capture
    ), mock.patch.object(cm, "load_vmid_from_cloud_pc", return_value=MACHINE_UUID):
        out = sok._try_remint_connectstr(plain=plain, host="", vmid_hint=MACHINE_UUID)

    assert out.get("ok") is True, out
    assert out.get("cag_host") == REGIONAL_CAG
    assert captured[0].cag_host == REGIONAL_CAG
    assert captured[0].csapip == REGIONAL_CSAP


def test_explicit_nondefault_host_overrides(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("STALE", encoding="utf-8")
    explicit = "1.2.3.4"
    captured: list[MintRequest] = []

    def capture(req, **kw):
        captured.append(req)
        return _ok_mint(req, **kw)

    gw = GatewayEndpoints(
        cag_host=explicit, cag_port=8899, csapip=REGIONAL_CSAP, source="explicit"
    )
    with mock.patch.object(gc, "resolve_gateway", return_value=gw) as m_rg, mock.patch.object(
        cm, "mint_connectstr", side_effect=capture
    ), mock.patch.object(cm, "load_vmid_from_cloud_pc", return_value=MACHINE_UUID):
        out = sok._try_remint_connectstr(plain=plain, host=explicit, vmid_hint=MACHINE_UUID)

    assert m_rg.call_args.kwargs.get("cag_host") == explicit
    assert out.get("cag_host") == explicit
    assert captured[0].cag_host == explicit


def test_rejects_cca_without_machine_fallback(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("STALE", encoding="utf-8")
    mint_n = {"n": 0}

    def boom(*a, **k):
        mint_n["n"] += 1
        raise AssertionError("must not mint with CCA- vmid")

    with mock.patch.object(gc, "resolve_gateway", return_value=_gw()), mock.patch.object(
        cm, "mint_connectstr", side_effect=boom
    ), mock.patch.object(cm, "load_vmid_from_cloud_pc", return_value=None):
        out = sok._try_remint_connectstr(plain=plain, host="", vmid_hint=INSTANCE_CCA)

    assert mint_n["n"] == 0
    assert out.get("ok") is False
    assert out.get("error") in (
        "mint_vmid_is_instance_id_not_machine_id",
        "mint_vmid_missing",
    ), out


def test_cca_hint_falls_back_to_machine_id(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("STALE", encoding="utf-8")
    captured: list[MintRequest] = []

    def capture(req, **kw):
        captured.append(req)
        return _ok_mint(req, **kw)

    with mock.patch.object(gc, "resolve_gateway", return_value=_gw()), mock.patch.object(
        cm, "mint_connectstr", side_effect=capture
    ), mock.patch.object(cm, "load_vmid_from_cloud_pc", return_value=MACHINE_UUID):
        out = sok._try_remint_connectstr(plain=plain, host="", vmid_hint=INSTANCE_CCA)

    assert out.get("ok") is True, out
    assert captured[0].vmid == MACHINE_UUID
    assert not captured[0].vmid.upper().startswith("CCA-")


def test_main_cli_host_default_empty() -> None:
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'default="36.212.224.105"' not in src
    # path-b and spice keepalive host defaults are empty strings
    assert src.count('default="",') >= 1 or src.count("default='',") >= 1
    assert "CAG host override (empty=resolve from cloud_pc" in src


if __name__ == "__main__":
    import tempfile
    import shutil

    td = Path(tempfile.mkdtemp(prefix="issue2_"))
    try:
        for name, fn in [
            ("a", test_default_gz4_host_does_not_override_cloud_pc),
            ("b", test_empty_host_uses_regional),
            ("c", test_explicit_nondefault_host_overrides),
            ("d", test_rejects_cca_without_machine_fallback),
            ("e", test_cca_hint_falls_back_to_machine_id),
        ]:
            p = td / name
            p.mkdir()
            fn(p)
        test_main_cli_host_default_empty()
        print("test_issue2_remint_gateway OK")
    finally:
        shutil.rmtree(td, ignore_errors=True)
