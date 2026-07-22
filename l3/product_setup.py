#!/usr/bin/env python3
"""Product setup chain for public ecloud Path B (claim=false).

Flow: resolve gateway → (optional login cfg present) list desktops →
power_once → mint connectStr → optional 1-round path_B.

No official client / no CDP. Customers use their own account + cloud_pc.json.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

PRODUCTION_CLAIM = False
PIN_PRODUCT_LINE = "public_ecloud_9222"
DEFAULT_PLAIN = os.environ.get(
    "SHORT_CONNECT_PLAIN_FILE",
    str(Path.home() / ".cache/ecloud-pathb/connectstr.plain"),
)
# Durable templates shipped under assets/ (restored by bin restore-templates)
_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRE = str(_REPO_ROOT / "assets/templates/pre")
DEFAULT_POST = str(_REPO_ROOT / "assets/templates/post")
# Fallback nest capture if assets missing
_NEST_PRE = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/pre"
_NEST_POST = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/post"
# #75fixw/#75fixad: after operate=available wait before mint (SaaS running ≠ CAG ready)
# Cold boot often needs >15s; default 60. Override with CLOUD_PC_POWER_WAIT.
DEFAULT_POWER_WAIT_S = float(os.environ.get("CLOUD_PC_POWER_WAIT", "60") or 60)
# mint 501/no_connectStr recovery: force power + wait + remint once (CLI/WebUI shared)
DEFAULT_MINT_POWER_RETRY = True


def _is_recoverable_mint_err(err: str) -> bool:
    """CAG 501 no_connectStr / desktop not ready for mint → worth force-power once."""
    e = (err or "").lower()
    if "no_connectstr" in e:
        return True
    if "result=501" in e or "result_code=501" in e:
        return True
    # loose: 501 + connect context
    if "501" in e and "connect" in e:
        return True
    return False


@dataclass
class SetupResult:
    ok: bool
    stage: str
    gateway: dict = field(default_factory=dict)
    desktop: dict = field(default_factory=dict)
    power: dict = field(default_factory=dict)
    mint: dict = field(default_factory=dict)
    path_b: dict = field(default_factory=dict)
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "gateway": self.gateway,
            "desktop": self.desktop,
            "power": self.power,
            "mint": self.mint,
            "path_b": self.path_b,
            "error": self.error,
            "notes": list(self.notes),
            "production_claim": PRODUCTION_CLAIM,
            "pin_product_line": PIN_PRODUCT_LINE,
            "dual_evidence_ok": False,
        }


def _template_dirs() -> tuple[str, str]:
    pre, post = DEFAULT_PRE, DEFAULT_POST
    if not Path(pre).is_dir() and _NEST_PRE.is_dir():
        pre = str(_NEST_PRE)
    if not Path(post).is_dir() and _NEST_POST.is_dir():
        post = str(_NEST_POST)
    return pre, post


def _pick_desktop(http, instance_id: str = "", machine_id: str = ""):
    from desktop_list import get_desktop_list, select_running_desktop

    desktops = get_desktop_list(http)
    if not desktops:
        return None, desktops
    if instance_id:
        for d in desktops:
            if d.instance_id == instance_id:
                return d, desktops
    if machine_id:
        for d in desktops:
            if d.machine_id == machine_id:
                return d, desktops
    # prefer running; else first
    d = select_running_desktop(http)
    if d is None:
        d = desktops[0]
    return d, desktops


def run_product_setup(
    *,
    cfg: dict,
    client,
    save_config: Callable[[dict], None],
    plain_path: str | Path = DEFAULT_PLAIN,
    do_power: bool = True,
    force_power: bool = False,
    do_mint: bool = True,
    do_path_b: bool = False,
    path_b_rounds: int = 1,
    heart_listen: float = 30.0,
    cag_host: Optional[str] = None,
    cag_port: Optional[int] = None,
    csapip: Optional[str] = None,
    instance_id: str = "",
    machine_id: str = "",
    mint_timeout: float = 25.0,
    power_wait_s: float = DEFAULT_POWER_WAIT_S,
    mint_power_retry: bool = DEFAULT_MINT_POWER_RETRY,
    dry_run: bool = False,
    path_b_out_dir: str | Path | None = None,
) -> SetupResult:
    """Run customer-facing setup chain. Never logs plain/token secrets.

    #75fixw recovery (CLI + WebUI shared):
    if first mint fails with CAG 501/no_connectStr and mint_power_retry:
      do_power=True  → force ensure_powered_once → wait → remint once
      do_power=False → wait only → remint once (#75fixae; WebUI already powered)
    #75fixac: power_on_done still skips while running/unknown; clearly stopped
    status re-allows operate=available (WebUI preflight + _ensure_plain share this).
    """
    notes: list[str] = []
    from l3.gateway_config import (
        merge_gateway_into_cloud_pc,
        resolve_gateway,
    )

    # --- gateway ---
    gw = resolve_gateway(
        cag_host=cag_host,
        cag_port=cag_port,
        csapip=csapip,
        cfg=cfg,
        try_client_discovery=True,
    )
    cfg = merge_gateway_into_cloud_pc(cfg, gw, only_missing=True)
    save_config(cfg)
    notes.append(f"gateway_source={gw.source}")

    result = SetupResult(ok=False, stage="gateway", gateway=gw.as_public_dict(), notes=notes)

    if not cfg.get("access_token"):
        result.error = "no access_token; run: python3 main.py login"
        result.stage = "auth"
        return result

    # --- desktop list ---
    try:
        desktop, all_d = _pick_desktop(
            client,
            instance_id=instance_id or str(cfg.get("instance_id") or ""),
            machine_id=machine_id or str(cfg.get("machine_id") or ""),
        )
    except Exception as e:
        result.error = f"list_desktops_failed:{type(e).__name__}:{e}"
        result.stage = "list"
        return result

    if desktop is None:
        result.error = "no_desktop"
        result.stage = "list"
        return result

    dinfo = {
        "instance_id": desktop.instance_id,
        "machine_id": desktop.machine_id,
        "machine_name": getattr(desktop, "machine_name", "") or "",
        "count": len(all_d),
    }
    result.desktop = dinfo
    result.stage = "list"
    # persist selection
    cfg["instance_id"] = desktop.instance_id
    cfg["machine_id"] = desktop.machine_id
    if getattr(desktop, "machine_name", None):
        cfg["machine_name"] = desktop.machine_name
    save_config(cfg)

    # --- #75fixx region CAG from device customLoginParams ---
    # Default/stock CAG is GZ4 (36.212.224.105). HHHT3 / other regions ship
    # their own cagList; minting against the wrong CAG → result=501
    # 「查询虚机状态异常，请确认虚机是否存在！」. Device list is authoritative
    # over default / stale cloud_pc; never override explicit/env.
    try:
        from l3.gateway_config import gateway_from_custom_login_params

        clp = getattr(desktop, "custom_login_params", None)
        dev_gw = gateway_from_custom_login_params(clp) if clp else None
        src = (gw.source or "")
        allow_device = not (
            src.startswith("explicit") or src.startswith("env")
        )
        if dev_gw and allow_device:
            if (
                src == "default"
                or src.startswith("client_config")
                or src.startswith("cloud_pc")
                or (dev_gw.cag_host and dev_gw.cag_host != gw.cag_host)
            ):
                gw = dev_gw
                cfg = merge_gateway_into_cloud_pc(cfg, gw, only_missing=False)
                save_config(cfg)
                notes.append(
                    f"gateway_device={gw.cag_host}:{gw.cag_port} src={gw.source}"
                )
                result.gateway = gw.as_public_dict()
                result.notes = notes
    except Exception as e:
        notes.append(f"gateway_device_skip:{type(e).__name__}")
        result.notes = notes

    # --- power once ---
    if do_power:
        from l3.desktop_power_once import ensure_powered_once

        if dry_run:
            result.power = {"acted": False, "skipped_reason": "dry_run"}
        else:
            pr = ensure_powered_once(
                client,
                cfg,
                desktop=desktop,
                force=force_power,
                wait_s=power_wait_s,
                save_cfg_fn=save_config,
            )
            result.power = pr.as_public_dict()
            notes.extend(pr.notes)
        result.stage = "power"
    else:
        result.power = {"acted": False, "skipped_reason": "do_power=false"}

    # --- mint ---
    plain = Path(plain_path)
    plain.parent.mkdir(parents=True, exist_ok=True)
    if do_mint:
        from l3.connectstr_mint import MintRequest, mint_connectstr, load_vmid_from_cloud_pc

        # suOper vmid = machine_id (UUID). instance_id (CCA-*) → CAG 501 no_connectStr.
        vmid = (
            (desktop.machine_id or "").strip()
            or (cfg.get("machine_id") or "").strip()
            or (load_vmid_from_cloud_pc() or "").strip()
            or (desktop.instance_id or "").strip()
        )
        req = MintRequest(
            vmid=vmid,
            cag_host=gw.cag_host,
            cag_port=gw.cag_port,
            csapip=gw.csapip,
            timeout_s=float(mint_timeout),
        )
        if dry_run:
            result.mint = {
                "ok": True,
                "dry_run": True,
                "vmid": vmid,
                "cag": f"{gw.cag_host}:{gw.cag_port}",
                "plain": str(plain),
            }
        else:
            mr = mint_connectstr(req, plain_path=plain, write_plain=True, dry_run=False)
            # MintResult public fields only
            result.mint = {
                "ok": bool(getattr(mr, "ok", False)),
                "error": getattr(mr, "error", "") or "",
                "plain_path": str(plain),
                "plain_bytes": plain.stat().st_size if plain.is_file() else 0,
                "vmid": vmid,
                "cag": f"{gw.cag_host}:{gw.cag_port}",
            }
            if not result.mint["ok"]:
                mint_err = result.mint["error"] or "mint_failed"
                # #75fixw: SaaS already_running skip may leave CAG unready → force power once
                # #75fixae: do_power=False (WebUI preflight/已开机 remint) 时仍 wait+remint；
                #           不再被 do_power 门闩关掉恢复路径
                if mint_power_retry and _is_recoverable_mint_err(mint_err):
                    wait_rec = (
                        float(power_wait_s)
                        if float(power_wait_s or 0) > 0
                        else DEFAULT_POWER_WAIT_S
                    )
                    power_initial = dict(result.power or {})
                    if do_power:
                        notes.append(
                            f"mint_recover: first mint failed ({mint_err[:120]}); "
                            f"force operate=available + wait {wait_rec}s + remint once"
                        )
                        log.warning(
                            "mint recoverable fail → force power + wait %.1fs + remint: %s",
                            wait_rec,
                            mint_err[:160],
                        )
                        from l3.desktop_power_once import ensure_powered_once

                        pr2 = ensure_powered_once(
                            client,
                            cfg,
                            desktop=desktop,
                            force=True,
                            wait_s=wait_rec,
                            save_cfg_fn=save_config,
                        )
                        result.power = {
                            "initial": power_initial,
                            "retry": pr2.as_public_dict(),
                        }
                        notes.extend(
                            [f"mint_recover_power:{n}" for n in (pr2.notes or [])]
                        )
                    else:
                        # already powered (or power skipped): CAG still warming → wait only
                        notes.append(
                            f"mint_recover: first mint failed ({mint_err[:120]}); "
                            f"do_power=false → wait {wait_rec}s + remint once (#75fixae)"
                        )
                        log.warning(
                            "mint recoverable fail (no re-power) → wait %.1fs + remint: %s",
                            wait_rec,
                            mint_err[:160],
                        )
                        try:
                            time.sleep(max(0.0, float(wait_rec)))
                        except Exception:
                            pass
                        result.power = {
                            "initial": power_initial,
                            "retry": {
                                "acted": False,
                                "skipped_reason": "mint_recover_wait_only",
                                "wait_s": wait_rec,
                            },
                        }
                    mr2 = mint_connectstr(
                        req, plain_path=plain, write_plain=True, dry_run=False
                    )
                    result.mint = {
                        "ok": bool(getattr(mr2, "ok", False)),
                        "error": getattr(mr2, "error", "") or "",
                        "plain_path": str(plain),
                        "plain_bytes": plain.stat().st_size if plain.is_file() else 0,
                        "vmid": vmid,
                        "cag": f"{gw.cag_host}:{gw.cag_port}",
                        "recovered": True,
                        "first_error": mint_err,
                        "recover_mode": "force_power" if do_power else "wait_only",
                    }
                    if not result.mint["ok"]:
                        result.error = result.mint["error"] or mint_err
                        result.stage = "mint"
                        result.notes = notes
                        return result
                    notes.append(
                        "mint_recover: remint OK after "
                        + ("force power" if do_power else "wait_only")
                    )
                else:
                    result.error = mint_err
                    result.stage = "mint"
                    result.notes = notes
                    return result
        result.stage = "mint"
        cfg["plain_path"] = str(plain)
        save_config(cfg)
    else:
        result.mint = {"ok": False, "skipped": True}

    # --- optional path_B 1r ---
    if do_path_b:
        pre, post = _template_dirs()
        if not Path(pre).is_dir() or not Path(post).is_dir():
            result.path_b = {
                "ok": False,
                "error": "templates_missing",
                "pre": pre,
                "post": post,
                "hint": "run: ./bin/public-spice-keepalive restore-templates",
            }
            result.error = "templates_missing"
            result.stage = "path_b"
            result.notes = notes
            return result
        if dry_run:
            result.path_b = {
                "ok": True,
                "dry_run": True,
                "rounds": path_b_rounds,
                "pre": pre,
                "post": post,
            }
        else:
            try:
                from l3.spice_oracle_keepalive_loop import run_spice_oracle_keepalive_loop

                # 1-round smoke; claim=false; independent out_dir (never share systemd out)
                out = Path(
                    path_b_out_dir
                    or (
                        _REPO_ROOT
                        / "reports/r26_live/product_setup_pathb"
                    )
                )
                out.mkdir(parents=True, exist_ok=True)
                summary = run_spice_oracle_keepalive_loop(
                    http=client,
                    instance_id=desktop.instance_id,
                    machine_id=desktop.machine_id,
                    host=gw.cag_host,
                    plain=Path(plain),
                    pre=Path(pre),
                    post=Path(post),
                    heart_listen=float(heart_listen),
                    ticket_mode="zeros",
                    max_rounds=int(path_b_rounds),
                    out_dir=out,
                    auto_remint=True,
                    remint_timeout_s=float(mint_timeout),
                    mid_session_reconnect=False,
                    do_account_ping=False,
                )
                if isinstance(summary, dict):
                    # spice_oracle summary has no top-level "ok"; use heart rounds.
                    ok_heart = int(summary.get("ok_heart_rounds") or 0)
                    fail_rounds = int(summary.get("fail_rounds") or 0)
                    heart_ok = ok_heart > 0 and fail_rounds == 0
                    explicit = summary.get("ok")
                    path_ok = bool(explicit) if explicit is not None else heart_ok
                    result.path_b = {
                        "ok": path_ok,
                        "ok_heart_rounds": ok_heart,
                        "fail_rounds": fail_rounds,
                        "rounds": summary.get("rounds") or path_b_rounds,
                        "run_id": summary.get("run_id"),
                        "out_dir": str(out),
                    }
                    if not path_ok:
                        result.error = "path_b_heart_fail"
                        result.stage = "path_b"
                        result.notes = notes
                        return result
                else:
                    result.path_b = {"ok": True, "summary_type": type(summary).__name__}
            except TypeError:
                # signature drift — call with minimal kwargs
                try:
                    from l3.path_b_keepalive_package import run_path_b_live

                    pb = run_path_b_live(
                        host=gw.cag_host,
                        plain=str(plain),
                        pre=pre,
                        post=post,
                        heart_listen=float(heart_listen),
                        ticket_mode="zeros",
                    )
                    result.path_b = {
                        "ok": bool(pb.get("ok", True)) if isinstance(pb, dict) else True,
                        "detail": "path_b_keepalive_package",
                    }
                except Exception as e2:
                    result.path_b = {"ok": False, "error": f"{type(e2).__name__}:{e2}"}
                    result.error = str(e2)[:200]
                    result.stage = "path_b"
                    result.notes = notes
                    return result
            except Exception as e:
                result.path_b = {"ok": False, "error": f"{type(e).__name__}:{e}"}
                result.error = str(e)[:200]
                result.stage = "path_b"
                result.notes = notes
                return result
        result.stage = "path_b"

    result.ok = True
    result.notes = notes
    if result.stage in ("mint", "power", "list") and not do_path_b:
        result.stage = "done_no_path_b" if do_mint else result.stage
    if do_path_b:
        result.stage = "done"
    return result


def selfcheck() -> dict[str, Any]:
    # allow `python3 l3/product_setup.py` without package install
    import sys as _sys
    from pathlib import Path as _P

    _root = str(_P(__file__).resolve().parents[1])
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    from l3.gateway_config import selfcheck as gw_sc
    from l3.desktop_power_once import selfcheck as pw_sc

    g = gw_sc()
    p = pw_sc()
    pre, post = _template_dirs()
    rec_ok = all(
        _is_recoverable_mint_err(e)
        for e in (
            "result=501 no_connectStr",
            "CAG result_code=501",
            "mint failed: no_connectStr from server",
        )
    )
    rec_no = not _is_recoverable_mint_err("Read timed out")
    return {
        "ok": bool(g.get("ok") and p.get("ok") and rec_ok and rec_no),
        "gateway": g,
        "power": p,
        "templates": {"pre": pre, "post": post, "pre_exists": Path(pre).is_dir()},
        "production_claim": PRODUCTION_CLAIM,
        "defaults": {
            "plain": DEFAULT_PLAIN,
            "power_wait_s": DEFAULT_POWER_WAIT_S,
            "mint_power_retry": DEFAULT_MINT_POWER_RETRY,
        },
        "mint_recover_detect": {"ok": rec_ok and rec_no},
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(selfcheck(), indent=2, ensure_ascii=False))
