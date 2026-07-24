#!/usr/bin/env python3
"""issue#2 follow-up: proxy bypass + device CLP region CAG on CLI.

Covers:
- ecloud_client.trust_env_enabled default False; ECLOUD_TRUST_ENV=1 opt-in
- gateway_source_is_weak matrix
- apply_device_gateway_from_clp overwrites default GZ4; preserves explicit
- main._resolve_desktop_for_spice with cached instance_id still fetches CLP
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from l3.gateway_config import (  # noqa: E402
    DEFAULT_CAG_HOST,
    apply_device_gateway_from_clp,
    gateway_source_is_weak,
)
import ecloud_client as ec  # noqa: E402
import main as main_mod  # noqa: E402
import desktop_list  # noqa: E402

REGIONAL_CAG = "36.212.224.100"
REGIONAL_PORT = 8899
REGIONAL_CSAP = "192.168.1.200:30087"
MACHINE_UUID = "c0d88cfc-9135-4e24-8fe9-8a3e2af49172"
INSTANCE_CCA = "CCA-49d403ad5163434db17bec551eea4a99"

CLP = {
    "cagList": [{"addr": REGIONAL_CAG, "port": REGIONAL_PORT}],
    "csapip": REGIONAL_CSAP,
}


def test_trust_env_default_false() -> None:
    old = os.environ.pop("ECLOUD_TRUST_ENV", None)
    try:
        assert ec.trust_env_enabled() is False
        util = ec.EcloudHttpUtil(common_params={})
        assert util._session.trust_env is False
    finally:
        if old is not None:
            os.environ["ECLOUD_TRUST_ENV"] = old


def test_trust_env_opt_in() -> None:
    old = os.environ.get("ECLOUD_TRUST_ENV")
    try:
        os.environ["ECLOUD_TRUST_ENV"] = "1"
        assert ec.trust_env_enabled() is True
        util = ec.EcloudHttpUtil(common_params={})
        assert util._session.trust_env is True
        os.environ["ECLOUD_TRUST_ENV"] = "0"
        assert ec.trust_env_enabled() is False
    finally:
        if old is None:
            os.environ.pop("ECLOUD_TRUST_ENV", None)
        else:
            os.environ["ECLOUD_TRUST_ENV"] = old


def test_gateway_source_is_weak_matrix() -> None:
    assert gateway_source_is_weak("default", DEFAULT_CAG_HOST) is True
    assert gateway_source_is_weak("", "") is True
    assert gateway_source_is_weak("cloud_pc:x", DEFAULT_CAG_HOST) is True
    assert gateway_source_is_weak("account_weak", REGIONAL_CAG) is True
    assert gateway_source_is_weak("device_customLoginParams", REGIONAL_CAG) is False
    assert gateway_source_is_weak("explicit:cli", REGIONAL_CAG) is False
    assert gateway_source_is_weak("cli", REGIONAL_CAG) is False


def test_apply_clp_overwrites_default_gz4() -> None:
    cfg = {
        "cag_host": DEFAULT_CAG_HOST,
        "cag_port": 443,
        "gateway_source": "default",
    }
    cfg2, gw = apply_device_gateway_from_clp(cfg, CLP, only_missing=False)
    assert gw is not None
    assert cfg2["cag_host"] == REGIONAL_CAG
    assert int(cfg2["cag_port"]) == REGIONAL_PORT
    assert REGIONAL_CSAP in str(cfg2.get("csapip") or "")


def test_apply_clp_preserves_explicit() -> None:
    cfg = {
        "cag_host": "1.2.3.4",
        "cag_port": 9999,
        "gateway_source": "explicit:cli",
        "csapip": "9.9.9.9:1",
    }
    cfg2, gw = apply_device_gateway_from_clp(cfg, CLP, only_missing=False)
    assert gw is None
    assert cfg2["cag_host"] == "1.2.3.4"
    assert int(cfg2["cag_port"]) == 9999


def test_apply_clp_force_overwrites_explicit() -> None:
    cfg = {
        "cag_host": "1.2.3.4",
        "cag_port": 9999,
        "gateway_source": "explicit:cli",
    }
    cfg2, gw = apply_device_gateway_from_clp(cfg, CLP, only_missing=False, force=True)
    assert gw is not None
    assert cfg2["cag_host"] == REGIONAL_CAG


def test_resolve_cached_instance_applies_clp() -> None:
    """Cached instance_id must still list desktops and write region CAG."""
    desktop = SimpleNamespace(
        instance_id=INSTANCE_CCA,
        machine_id=MACHINE_UUID,
        origin_company_code="CMSSZTE",
        custom_login_params=CLP,
    )
    cfg = {
        "instance_id": INSTANCE_CCA,
        "machine_id": MACHINE_UUID,
        "origin_company_code": "CMSSZTE",
        "cag_host": DEFAULT_CAG_HOST,
        "cag_port": 443,
        "gateway_source": "default",
    }
    args = SimpleNamespace(instance_id="", machine_id="", no_auto_select=False)
    saved: dict = {}

    def fake_save(c):
        saved.clear()
        saved.update(c)

    with mock.patch.object(
        desktop_list, "get_desktop_list", return_value=[desktop]
    ), mock.patch.object(main_mod, "save_config", side_effect=fake_save):
        iid, mid, origin = main_mod._resolve_desktop_for_spice(
            args, cfg, client=object(), relogin_fn=None
        )

    assert iid == INSTANCE_CCA
    assert mid == MACHINE_UUID
    assert origin == "CMSSZTE"
    assert cfg["cag_host"] == REGIONAL_CAG
    assert int(cfg["cag_port"]) == REGIONAL_PORT
    assert saved.get("cag_host") == REGIONAL_CAG


def test_resolve_skips_clp_when_explicit_gateway() -> None:
    desktop = SimpleNamespace(
        instance_id=INSTANCE_CCA,
        machine_id=MACHINE_UUID,
        origin_company_code="CMSSZTE",
        custom_login_params=CLP,
    )
    cfg = {
        "instance_id": INSTANCE_CCA,
        "machine_id": MACHINE_UUID,
        "origin_company_code": "CMSSZTE",
        "cag_host": "1.2.3.4",
        "cag_port": 9999,
        "gateway_source": "explicit:cli",
    }
    args = SimpleNamespace(instance_id="", machine_id="", no_auto_select=False)
    with mock.patch.object(
        desktop_list, "get_desktop_list", return_value=[desktop]
    ), mock.patch.object(main_mod, "save_config"):
        main_mod._resolve_desktop_for_spice(
            args, cfg, client=object(), relogin_fn=None
        )
    assert cfg["cag_host"] == "1.2.3.4"
    assert int(cfg["cag_port"]) == 9999


if __name__ == "__main__":
    test_trust_env_default_false()
    test_trust_env_opt_in()
    test_gateway_source_is_weak_matrix()
    test_apply_clp_overwrites_default_gz4()
    test_apply_clp_preserves_explicit()
    test_apply_clp_force_overwrites_explicit()
    test_resolve_cached_instance_applies_clp()
    test_resolve_skips_clp_when_explicit_gateway()
    print("test_issue2_followup_proxy_clp OK")
