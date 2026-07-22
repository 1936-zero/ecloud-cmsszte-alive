#!/usr/bin/env python3
"""Ensure desktop is powered on for Path B / mint (public ecloud).

User requirement (#70): Path B keepalive needs a running VM.
- First setup: call SaaS operate=available once, mark power_on_done.
- Subsequent rounds while still running: MUST NOT re-call power-on.
- #75fixac: if power_on_done but SaaS status is clearly **stopped/关机**,
  re-call operate=available so WebUI/CLI「启保活」能自动拉起已关机桌面.

PIN: public_ecloud · production_claim=false · ban jtydn
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

# cloud_pc.json keys (persisted by caller via save_config)
KEY_POWER_ON_DONE = "power_on_done"
KEY_POWER_ON_AT = "power_on_at"
KEY_POWER_ON_MACHINE = "power_on_machine_id"
KEY_POWER_ON_RESULT = "power_on_last_status"

# resourceStatus strings observed in public ecloud (best-effort)
_RUNNING_HINTS = (
    "running",
    "run",
    "online",
    "active",
    "available",
    "开机",
    "运行",
    "使用中",
    "已连接",
)
_STOPPED_HINTS = (
    "stop",
    "shut",
    "offline",
    "halt",
    "关机",
    "已关机",
    "停止",
)


@dataclass
class PowerOnceResult:
    acted: bool
    skipped_reason: str = ""
    operate_resp: Any = None
    status_before: str = ""
    status_after: str = ""
    machine_id: str = ""
    instance_id: str = ""
    notes: list[str] = field(default_factory=list)

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "acted": self.acted,
            "skipped_reason": self.skipped_reason,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "machine_id": self.machine_id,
            "instance_id": self.instance_id,
            "notes": list(self.notes),
            # never dump full operate_resp (may contain noisy vendor fields)
            "operate_ok": bool(self.operate_resp) if self.acted else None,
        }


def _status_is_running(st: str) -> bool:
    s = (st or "").strip().lower()
    if not s:
        return False
    if any(h in s for h in _STOPPED_HINTS):
        return False
    return any(h in s for h in _RUNNING_HINTS)


def _status_is_stopped(st: str) -> bool:
    s = (st or "").strip().lower()
    return any(h in s for h in _STOPPED_HINTS)


def ensure_powered_once(
    http,
    cfg: dict,
    *,
    desktop=None,
    machine_id: str = "",
    machine_name: str = "",
    instance_id: str = "",
    resource_pool_uid: str = "",
    force: bool = False,
    wait_s: float = 0.0,
    poll_status: bool = True,
    operate_fn: Optional[Callable[..., Any]] = None,
    status_fn: Optional[Callable[..., dict]] = None,
    save_cfg_fn: Optional[Callable[[dict], None]] = None,
) -> PowerOnceResult:
    """Power on desktop when needed for Path B / mint.

    - force=False + status already running → mark done, do not operate.
    - force=False + cfg[power_on_done] + status still running / unknown → skip
      (keepalive rounds must not spam power API).
    - force=False + cfg[power_on_done] + status clearly **stopped** → re-operate
      available (#75fixac: 用户关机后再启保活应自动开机).
    - force=True: ignore power_on_done and already_running; re-call operate=available
      (#75fixw: SaaS running ≠ CAG mint-ready; mint 501 recovery needs this).
    - Else call operate=available once, set power_on_done=True, save cfg.

    ``http`` is EcloudHttpUtil-like; desktop is optional Desktop dataclass.
    """
    notes: list[str] = []
    mid = machine_id or (getattr(desktop, "machine_id", None) or "")
    mname = machine_name or (getattr(desktop, "machine_name", None) or "")
    iid = instance_id or (getattr(desktop, "instance_id", None) or "")
    pool = resource_pool_uid or (getattr(desktop, "resource_pool_uid", None) or "")
    # Desktop may store origin fields under different names
    if not pool and desktop is not None:
        pool = getattr(desktop, "origin_company_code", None) or ""

    if not mid:
        # try cfg
        mid = str(cfg.get("machine_id") or "")
        mname = mname or str(cfg.get("machine_name") or cfg.get("username") or "desktop")
        iid = iid or str(cfg.get("instance_id") or "")

    # #75fixac: do NOT early-return on power_on_done before status poll —
    # stopped desktops must be allowed to re-power.

    status_before = ""
    statuses: dict = {}
    if poll_status and iid:
        try:
            if status_fn is None:
                from desktop_list import get_desktop_status  # local import

                status_fn = lambda h, ds: get_desktop_status(h, ds)  # noqa: E731
            # Build a minimal desktop list object if needed
            if desktop is not None:
                statuses = status_fn(http, [desktop])  # type: ignore[misc]
            else:
                # status API wants Desktop list; try instance-only path via operate skip
                from desktop_list import Desktop

                fake = Desktop(
                    machine_id=mid,
                    instance_id=iid,
                    machine_name=mname or "desktop",
                )
                statuses = status_fn(http, [fake])  # type: ignore[misc]
            status_before = str(statuses.get(iid) or statuses.get(mid) or "")
            notes.append(f"status_before={status_before or 'empty'}")
        except Exception as e:
            notes.append(f"status_query_failed:{type(e).__name__}")
            log.warning("power_once status query failed: %s", e)

    # force=True：即便 SaaS 报 running 也再调 operate=available
    # （#75fixw：SaaS running ≠ CAG 可 mint；mint 501 恢复路径依赖此行为）
    if (not force) and status_before and _status_is_running(status_before):
        cfg[KEY_POWER_ON_DONE] = True
        cfg[KEY_POWER_ON_AT] = time.strftime("%Y-%m-%dT%H:%M:%S")
        cfg[KEY_POWER_ON_MACHINE] = mid
        cfg[KEY_POWER_ON_RESULT] = "already_running"
        if save_cfg_fn:
            save_cfg_fn(cfg)
        return PowerOnceResult(
            acted=False,
            skipped_reason="already_running",
            status_before=status_before,
            status_after=status_before,
            machine_id=mid,
            instance_id=iid,
            notes=notes,
        )

    # #75fixac: power_on_done only blocks when NOT clearly stopped
    if (not force) and cfg.get(KEY_POWER_ON_DONE):
        if status_before and _status_is_stopped(status_before):
            notes.append(
                "power_on_done but status stopped → re-operate available (#75fixac)"
            )
            log.info(
                "power_once: power_on_done ignored (stopped status=%s) machine_id=%s",
                status_before,
                mid or "-",
            )
            # fall through to operate=available
        else:
            return PowerOnceResult(
                acted=False,
                skipped_reason="power_on_done",
                status_before=status_before,
                status_after=status_before,
                machine_id=mid,
                instance_id=iid,
                notes=notes
                + ["already marked; keepalive must not re-power while not stopped"],
            )

    if force and status_before and _status_is_running(status_before):
        notes.append("force=True: ignore already_running, re-operate available")
    if not mid:
        return PowerOnceResult(
            acted=False,
            skipped_reason="no_machine_id",
            status_before=status_before,
            notes=notes + ["cannot operate without machine_id"],
        )

    if operate_fn is None:
        from desktop_list import operate_desktop

        operate_fn = operate_desktop

    log.info(
        "power_once: operate=available machine_id=%s name=%s (first-only)",
        mid,
        mname or "-",
    )
    try:
        resp = operate_fn(
            http,
            machine_id=mid,
            machine_name=mname or mid,
            operate="available",
            resource_pool_uid=pool or "",
        )
    except Exception as e:
        log.error("power_once operate failed: %s", e)
        return PowerOnceResult(
            acted=False,
            skipped_reason=f"operate_error:{type(e).__name__}",
            status_before=status_before,
            machine_id=mid,
            instance_id=iid,
            notes=notes + [str(e)[:200]],
        )

    cfg[KEY_POWER_ON_DONE] = True
    cfg[KEY_POWER_ON_AT] = time.strftime("%Y-%m-%dT%H:%M:%S")
    cfg[KEY_POWER_ON_MACHINE] = mid
    cfg[KEY_POWER_ON_RESULT] = "operated_available"
    if save_cfg_fn:
        save_cfg_fn(cfg)

    status_after = status_before
    if wait_s > 0 and poll_status and iid:
        time.sleep(min(wait_s, 120.0))
        try:
            from desktop_list import Desktop, get_desktop_status

            fake = desktop or Desktop(
                machine_id=mid, instance_id=iid, machine_name=mname or "desktop"
            )
            st2 = get_desktop_status(http, [fake])
            status_after = str(st2.get(iid) or st2.get(mid) or "")
            notes.append(f"status_after={status_after or 'empty'}")
        except Exception as e:
            notes.append(f"status_after_failed:{type(e).__name__}")

    return PowerOnceResult(
        acted=True,
        operate_resp=resp,
        status_before=status_before,
        status_after=status_after,
        machine_id=mid,
        instance_id=iid,
        notes=notes,
    )


def selfcheck() -> dict[str, Any]:
    """Offline unit selfcheck with fakes (no network)."""
    calls: list[tuple] = []

    class FakeHttp:
        common_params = {"deviceUid": "dev-test"}

    def fake_operate(http, machine_id, machine_name, operate, resource_pool_uid=""):
        calls.append((machine_id, operate))
        return {"code": 0, "msg": "ok"}

    cfg: dict = {}
    # first call acts
    r1 = ensure_powered_once(
        FakeHttp(),
        cfg,
        machine_id="m1",
        machine_name="d1",
        instance_id="i1",
        poll_status=False,
        operate_fn=fake_operate,
    )
    assert r1.acted and cfg.get(KEY_POWER_ON_DONE) is True
    # second call skips
    r2 = ensure_powered_once(
        FakeHttp(),
        cfg,
        machine_id="m1",
        machine_name="d1",
        instance_id="i1",
        poll_status=False,
        operate_fn=fake_operate,
    )
    assert not r2.acted and r2.skipped_reason == "power_on_done"
    assert len(calls) == 1

    # #75fixw: force=True ignores power_on_done
    r3 = ensure_powered_once(
        FakeHttp(),
        cfg,
        machine_id="m1",
        machine_name="d1",
        instance_id="i1",
        force=True,
        poll_status=False,
        operate_fn=fake_operate,
        wait_s=0,
    )
    assert r3.acted and len(calls) == 2

    # force=True also ignores already_running status
    def fake_status(_http, _ds):
        return {"i1": "running"}

    calls.clear()
    cfg_run: dict = {}
    r4 = ensure_powered_once(
        FakeHttp(),
        cfg_run,
        machine_id="m1",
        machine_name="d1",
        instance_id="i1",
        force=True,
        poll_status=True,
        status_fn=fake_status,
        operate_fn=fake_operate,
        wait_s=0,
    )
    assert r4.acted and len(calls) == 1
    assert any("ignore already_running" in n for n in (r4.notes or []))

    # without force, already_running skips
    calls.clear()
    cfg_skip: dict = {}
    r5 = ensure_powered_once(
        FakeHttp(),
        cfg_skip,
        machine_id="m1",
        machine_name="d1",
        instance_id="i1",
        force=False,
        poll_status=True,
        status_fn=fake_status,
        operate_fn=fake_operate,
        wait_s=0,
    )
    assert not r5.acted and r5.skipped_reason == "already_running"
    assert len(calls) == 0

    return {
        "ok": True,
        "calls_after_force": 2,
        "r1": r1.as_public_dict(),
        "r2": r2.as_public_dict(),
        "force_power_on_done": r3.as_public_dict(),
        "force_already_running": r4.as_public_dict(),
        "skip_already_running": r5.as_public_dict(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import json

    print(json.dumps(selfcheck(), indent=2, ensure_ascii=False))
