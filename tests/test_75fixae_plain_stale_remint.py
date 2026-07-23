#!/usr/bin/env python3
"""#75fixae: after power cycle, stale plain must remint; mint501 recover without do_power."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "l3"))

from l3.product_setup import (  # noqa: E402
    DEFAULT_POWER_WAIT_S,
    _is_recoverable_mint_err,
    run_product_setup,
)
from l3.connectstr_mint import MintResult  # noqa: E402
from l3.gateway_config import GatewayEndpoints  # noqa: E402
from web.keepalive_manager import KeepaliveManager  # noqa: E402


def test_default_power_wait_is_at_least_60() -> None:
    assert float(DEFAULT_POWER_WAIT_S) >= 60.0


def test_plain_stale_after_power_no_marker(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("old")
    # no power_on_at → not "stale after power" (avoid always remint)
    assert KeepaliveManager._plain_stale_after_power(plain, {}) is False


def test_plain_stale_when_older_than_power_on_at(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("old")
    # plain older than power_on_at
    old = time.time() - 3600
    import os

    os.utime(plain, (old, old))
    cfg = {"power_on_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    assert KeepaliveManager._plain_stale_after_power(plain, cfg) is True


def test_plain_fresh_after_power(tmp_path: Path) -> None:
    plain = tmp_path / "connectstr.plain"
    plain.write_text("fresh")
    # power_on_at in the past relative to plain mtime
    past = time.localtime(time.time() - 120)
    cfg = {"power_on_at": time.strftime("%Y-%m-%dT%H:%M:%S", past)}
    assert KeepaliveManager._plain_stale_after_power(plain, cfg) is False


def test_recoverable_mint_errs() -> None:
    assert _is_recoverable_mint_err("CAG result=501 no_connectStr") is True
    assert _is_recoverable_mint_err("no_connectStr from server") is True
    assert _is_recoverable_mint_err("Read timed out") is False


class _FakeDesktop:
    instance_id = "inst-ae"
    machine_id = "mach-ae"
    machine_name = "desk-ae"
    custom_login_params = None


def test_mint_recover_wait_only_when_do_power_false(tmp_path: Path) -> None:
    """do_power=False + mint501 → wait_only remint (no force power)."""
    plain = tmp_path / "connectstr.plain"
    sleeps: list[float] = []
    mint_calls = {"n": 0}

    def fake_mint(req, *, plain_path=None, write_plain=True, dry_run=False):
        mint_calls["n"] += 1
        if mint_calls["n"] == 1:
            return MintResult(ok=False, error="CAG result=501 no_connectStr")
        plain_path = Path(plain_path) if plain_path else plain
        plain_path.write_text("NEWPLAIN")
        return MintResult(ok=True, error=None, plain_path=str(plain_path), written=True)

    gw = GatewayEndpoints(
        cag_host="1.2.3.4", cag_port=443, csapip="https://x", source="test"
    )
    cfg = {
        "access_token": "tok",
        "instance_id": "inst-ae",
        "machine_id": "mach-ae",
    }
    saved: list = []

    with mock.patch("l3.product_setup.resolve_gateway", return_value=gw), mock.patch(
        "l3.product_setup.merge_gateway_into_cloud_pc", side_effect=lambda c, *a, **k: c
    ), mock.patch(
        "l3.product_setup._pick_desktop", return_value=(_FakeDesktop(), [_FakeDesktop()])
    ), mock.patch(
        "l3.product_setup.mint_connectstr", side_effect=fake_mint
    ), mock.patch(
        "l3.product_setup.time.sleep", side_effect=lambda s: sleeps.append(float(s))
    ), mock.patch(
        "l3.product_setup.gateway_from_custom_login_params", return_value=None
    ):
        # gateway imports are inside function; patch modules used after import
        with mock.patch(
            "l3.gateway_config.resolve_gateway", return_value=gw
        ), mock.patch(
            "l3.gateway_config.merge_gateway_into_cloud_pc",
            side_effect=lambda c, *a, **k: c,
        ), mock.patch(
            "l3.gateway_config.gateway_from_custom_login_params", return_value=None
        ), mock.patch(
            "l3.connectstr_mint.mint_connectstr", side_effect=fake_mint
        ):
            # ensure mint is the one product_setup binds
            import l3.product_setup as ps

            with mock.patch.object(ps, "mint_connectstr", side_effect=fake_mint), mock.patch.object(
                ps.time, "sleep", side_effect=lambda s: sleeps.append(float(s))
            ):
                r = run_product_setup(
                    cfg=cfg,
                    client=object(),
                    save_config=lambda c: saved.append(dict(c)),
                    plain_path=plain,
                    do_power=False,
                    force_power=False,
                    do_mint=True,
                    do_path_b=False,
                    mint_power_retry=True,
                    power_wait_s=3.0,
                )

    assert mint_calls["n"] == 2, mint_calls
    assert sleeps and sleeps[0] >= 3.0, sleeps
    assert r.ok is True
    notes = " ".join(r.notes or [])
    assert "wait_only" in notes or "do_power=false" in notes, notes
    assert (r.power or {}).get("retry", {}).get("skipped_reason") == "mint_recover_wait_only"


if __name__ == "__main__":
    td = Path("/tmp/test_75fixae_plain")
    td.mkdir(parents=True, exist_ok=True)
    test_default_power_wait_is_at_least_60()
    test_plain_stale_after_power_no_marker(td / "a")
    (td / "a").mkdir(exist_ok=True)
    test_plain_stale_after_power_no_marker(td / "a")
    test_plain_stale_when_older_than_power_on_at(td / "b")
    (td / "b").mkdir(exist_ok=True)
    # recreate subdirs cleanly
    import shutil

    for name, fn in [
        ("a", test_plain_stale_after_power_no_marker),
        ("b", test_plain_stale_when_older_than_power_on_at),
        ("c", test_plain_fresh_after_power),
        ("d", test_mint_recover_wait_only_when_do_power_false),
    ]:
        p = td / name
        if p.exists():
            shutil.rmtree(p)
        p.mkdir()
        fn(p)
    test_recoverable_mint_errs()
    print("test_75fixae_plain_stale_remint OK")
