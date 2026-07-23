#!/usr/bin/env python3
"""#75fixac: power_on_done must not block re-power when status is stopped."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "l3"))

from l3.desktop_power_once import (  # noqa: E402
    KEY_POWER_ON_DONE,
    ensure_powered_once,
    _status_is_running,
    _status_is_stopped,
)


class _FakeDesktop:
    def __init__(self, mid="m1", iid="i1", name="desk"):
        self.machine_id = mid
        self.instance_id = iid
        self.machine_name = name
        self.resource_pool_uid = ""


def test_status_hints():
    assert _status_is_stopped("关机")
    assert _status_is_stopped("STOPPED")
    assert _status_is_stopped("shutdown")
    assert not _status_is_stopped("running")
    assert _status_is_running("运行中")
    assert _status_is_running("running")
    assert not _status_is_running("已关机")


def test_power_on_done_skips_when_running():
    cfg = {KEY_POWER_ON_DONE: True, "machine_id": "m1", "instance_id": "i1"}
    saved = []
    ops = []

    def status_fn(http, ds):
        return {"i1": "running"}

    def operate_fn(http, **kw):
        ops.append(kw)
        return {"ok": True}

    r = ensure_powered_once(
        None,
        cfg,
        desktop=_FakeDesktop(),
        status_fn=status_fn,
        operate_fn=operate_fn,
        save_cfg_fn=lambda c: saved.append(dict(c)),
        force=False,
    )
    assert r.acted is False
    assert r.skipped_reason == "already_running"
    assert not ops


def test_power_on_done_repowers_when_stopped():
    cfg = {KEY_POWER_ON_DONE: True, "machine_id": "m1", "instance_id": "i1"}
    ops = []
    saved = []

    def status_fn(http, ds):
        # after operate, still return stopped once (poll_status path may re-query)
        return {"i1": "关机"}

    def operate_fn(http, **kw):
        ops.append(kw)
        return {"ok": True}

    r = ensure_powered_once(
        None,
        cfg,
        desktop=_FakeDesktop(),
        status_fn=status_fn,
        operate_fn=operate_fn,
        save_cfg_fn=lambda c: saved.append(dict(c)),
        wait_s=0.0,
        force=False,
    )
    assert r.acted is True
    assert len(ops) == 1
    assert ops[0].get("operate") == "available" or "available" in str(ops)
    assert any("stopped" in n or "关机" in n or "75fixac" in n for n in r.notes)
    assert cfg.get(KEY_POWER_ON_DONE) is True
    assert saved, "cfg should be saved after re-power"


def test_power_on_done_skips_when_unknown_status():
    """Empty status + power_on_done → still skip (avoid spam); preflight uses force=True."""
    cfg = {KEY_POWER_ON_DONE: True, "machine_id": "m1", "instance_id": "i1"}
    ops = []

    def status_fn(http, ds):
        return {"i1": ""}

    def operate_fn(http, **kw):
        ops.append(kw)
        return {"ok": True}

    r = ensure_powered_once(
        None,
        cfg,
        desktop=_FakeDesktop(),
        status_fn=status_fn,
        operate_fn=operate_fn,
        force=False,
        poll_status=True,
    )
    assert r.acted is False
    assert r.skipped_reason == "power_on_done"
    assert not ops


def test_force_true_ignores_power_on_done():
    cfg = {KEY_POWER_ON_DONE: True, "machine_id": "m1", "instance_id": "i1"}
    ops = []

    def status_fn(http, ds):
        return {"i1": "running"}

    def operate_fn(http, **kw):
        ops.append(kw)
        return {"ok": True}

    r = ensure_powered_once(
        None,
        cfg,
        desktop=_FakeDesktop(),
        status_fn=status_fn,
        operate_fn=operate_fn,
        wait_s=0.0,
        force=True,
    )
    assert r.acted is True
    assert len(ops) == 1


if __name__ == "__main__":
    test_status_hints()
    test_power_on_done_skips_when_running()
    test_power_on_done_repowers_when_stopped()
    test_power_on_done_skips_when_unknown_status()
    test_force_true_ignores_power_on_done()
    print("ALL PASS")
