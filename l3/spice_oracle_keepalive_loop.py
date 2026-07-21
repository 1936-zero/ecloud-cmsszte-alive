#!/usr/bin/env python3
"""SPICE path_B keepalive + HTTP status/uptime oracle (claim=false).

Primary keepalive plane: path_B SPICE HEART (reconnect-style each interval).
Oracle plane (NOT keepalive): getDesktopStatus + desktopUptime each round,
so long-soak logs prove whether the desktop stayed running / how long uptime grew.

Hard pins (public ecloud-computer :9222 only):
  - production_claim=false forever
  - dual_evidence_ok=false / agent_dual_ok=false
  - no jtydn / no cmcc-jtydn
  - never log/dump -k or plain connectStr contents
  - freeze_cite must match path_b package (a46d55cd…)

Usage (from repo root via main.py):
  python main.py keepalive --interval 300
  python main.py desktop-keepalive --rounds 2 --heart-listen 30
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_L3 = Path(__file__).resolve().parent
_ROOT = _L3.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

try:
    from .path_b_keepalive_package import (  # type: ignore
        DEFAULT_CAG_HOST,
        DEFAULT_HEART_LISTEN_S,
        DEFAULT_PLAIN,
        DEFAULT_POST,
        DEFAULT_PRE,
        DEFAULT_TICKET_MODE,
        FREEZE_CITE,
        run_path_b_keepalive,
    )
except ImportError:
    from path_b_keepalive_package import (  # type: ignore
        DEFAULT_CAG_HOST,
        DEFAULT_HEART_LISTEN_S,
        DEFAULT_PLAIN,
        DEFAULT_POST,
        DEFAULT_PRE,
        DEFAULT_TICKET_MODE,
        FREEZE_CITE,
        run_path_b_keepalive,
    )

log = logging.getLogger("spice_oracle_ka")

# Public-path only. Never route jtydn.
_PUBLIC_HOST_DEFAULT = DEFAULT_CAG_HOST  # 36.212.224.105
_JTYDN_MARKERS = ("jtydn", "cmcc-jtydn", "9223", "爱家")


def _assert_public_host(host: str) -> str:
    h = (host or "").strip() or _PUBLIC_HOST_DEFAULT
    low = h.lower()
    for m in _JTYDN_MARKERS:
        if m in low:
            raise ValueError(f"jtydn/爱家 host forbidden (public:9222 only): marker={m}")
    return h


def _oracle_once(
    http: Any,
    *,
    instance_id: str,
    machine_id: str = "",
) -> Dict[str, Any]:
    """Read-only HTTP oracle: desktop status + uptime. Never used as keepalive."""
    out: Dict[str, Any] = {
        "oracle_ok": False,
        "resource_status": "",
        "uptime": "",
        "error": None,
        "token_expired": False,
    }
    if not instance_id:
        out["error"] = "no_instance_id"
        return out

    # Lazy imports so pure path_B tests need no ecloud client.
    import desktop_list  # noqa: WPS433
    import desktop_session  # noqa: WPS433
    from ecloud_client import EcloudError  # noqa: WPS433

    # 1) status
    try:
        # Build a minimal Desktop-like list for get_desktop_status
        d = desktop_list.Desktop(
            instance_id=instance_id,
            machine_id=machine_id or "",
            machine_name="",
            origin_company_code="",
        )
        statuses = desktop_list.get_desktop_status(http, [d])
        st = statuses.get(instance_id) or statuses.get(machine_id) or ""
        if not st and statuses:
            # some responses key by other id; take first value for this instance if only one
            if len(statuses) == 1:
                st = next(iter(statuses.values()))
        out["resource_status"] = str(st or "")
        out["status_map_n"] = len(statuses)
    except Exception as e:  # noqa: BLE001 — oracle must not kill SPICE loop
        out["error"] = f"status:{type(e).__name__}:{e}"
        try:
            from ecloud_client import EcloudError as _EE

            if isinstance(e, _EE):
                msg = (e.message or "").lower()
                out["token_expired"] = any(
                    h in msg for h in ("token", "失效", "未登录", "expire", "401", "授权")
                )
        except Exception:
            pass

    # 2) uptime
    try:
        sess = desktop_session.DesktopSession(
            http, instance_id, machine_id or "", ticket=""
        )
        uptime = sess.report_uptime()
        out["uptime"] = str(uptime or sess.last_uptime or "")
        out["oracle_ok"] = True
    except Exception as e:  # noqa: BLE001
        err_s = f"uptime:{type(e).__name__}:{e}"
        out["error"] = (out["error"] + ";" + err_s) if out["error"] else err_s
        try:
            from ecloud_client import EcloudError as _EE

            if isinstance(e, _EE):
                msg = (e.message or "").lower()
                if any(
                    h in msg for h in ("token", "失效", "未登录", "expire", "401", "授权")
                ):
                    out["token_expired"] = True
        except Exception:
            pass
        # status alone still partial-ok
        if out.get("resource_status"):
            out["oracle_ok"] = True

    return out


def _account_ping(http: Any) -> Dict[str, Any]:
    """Lightweight L1 token touch (not desktop keepalive)."""
    out = {"ok": False, "error": None, "token_expired": False}
    try:
        import config  # noqa: WPS433
        from ecloud_client import EcloudError  # noqa: WPS433

        http.post(config.Endpoint.USER_GET_INFO)
        out["ok"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}:{e}"
        try:
            from ecloud_client import EcloudError as _EE

            if isinstance(e, _EE):
                msg = (e.message or "").lower()
                out["token_expired"] = any(
                    h in msg for h in ("token", "失效", "未登录", "expire", "401", "授权")
                )
        except Exception:
            pass
    return out


def _plain_age_s(plain: Path) -> Optional[float]:
    """Seconds since plain mtime; None if missing/unreadable. No content read."""
    try:
        p = Path(plain)
        if not p.is_file():
            return None
        return max(0.0, time.time() - float(p.stat().st_mtime))
    except OSError:
        return None


def _is_mid_session_drop(spice: Dict[str, Any], spice_err: Optional[str] = None) -> bool:
    """auth/tls already ok but heart/redq dropped — remint won't help; reconnect may."""
    if bool(spice.get("ok_heart_keepalive")):
        return False
    if spice.get("ok_auth220") is True:
        return True
    # redq without heart after handshake also mid-session
    if spice.get("ok_tls") is True and spice.get("ok_ztec50") is True:
        if not bool(spice.get("ok_redq_s2c")) or not bool(spice.get("ok_heart_keepalive")):
            # only if not a pre-auth class error
            err = str(spice.get("error") or spice_err or "").lower()
            if any(h in err for h in ("auth220", "connectstr", "ticket", "handshake")):
                return False
            return True
    return False


def _need_remint(spice: Dict[str, Any], spice_err: Optional[str] = None) -> bool:
    """True when path_B failed in a way that a fresh connectStr may fix.

    Hard pin: only auth/handshake pre-heart failures (auth220 / ztec50 / tls),
    not a pure mid-session heart drop after ok_auth220.
    """
    if bool(spice.get("ok_heart_keepalive")):
        return False
    # auth already passed → heart/redq drop is mid-session; remint won't help
    if spice.get("ok_auth220") is True:
        return False
    # explicit auth / pre-TLS fail
    if spice.get("ok_auth220") is False:
        return True
    if spice.get("ok_ztec50") is False:
        return True
    if spice.get("ok_tls") is False:
        return True
    err = str(spice.get("error") or spice_err or "").lower()
    if any(
        h in err
        for h in (
            "auth220",
            "auth",
            "timeout",
            "connectstr",
            "ticket",
            "handshake",
            "ztec",
            "plain",
        )
    ):
        return True
    # total fail with no redq either and auth unknown → likely stale plain
    if (
        spice.get("ok_auth220") is None
        and not bool(spice.get("ok_redq_s2c"))
        and not bool(spice.get("ok_heart_keepalive"))
    ):
        return True
    return False


def _try_remint_connectstr(
    *,
    plain: Path,
    host: str,
    vmid_hint: str = "",
    timeout_s: float = 20.0,
) -> Dict[str, Any]:
    """Mint/refresh connectStr into plain. Public meta only (no -k/plain dump)."""
    out: Dict[str, Any] = {
        "ok": False,
        "error": None,
        "vmid_prefix": "",
        "plain_sha16": None,
        "production_claim": False,
    }
    try:
        try:
            from .connectstr_mint import (  # type: ignore
                MintRequest,
                load_vmid_from_cloud_pc,
                mint_connectstr,
            )
        except ImportError:
            from connectstr_mint import (  # type: ignore
                MintRequest,
                load_vmid_from_cloud_pc,
                mint_connectstr,
            )
    except Exception as e:  # noqa: BLE001
        out["error"] = f"mint_import_fail:{type(e).__name__}"
        return out

    vmid = (vmid_hint or "").strip()
    if not vmid:
        try:
            vmid = load_vmid_from_cloud_pc() or ""
        except Exception:
            vmid = ""
    if not vmid:
        try:
            import re as _re

            _pt = Path(plain).read_text(encoding="utf-8", errors="ignore")
            _m = _re.search(r"--vmid\s+(\S+)", _pt)
            if _m:
                vmid = _m.group(1)
        except Exception:
            pass
    if not vmid:
        out["error"] = "mint_vmid_missing"
        return out

    out["vmid_prefix"] = vmid[:16]
    try:
        mres = mint_connectstr(
            MintRequest(vmid=vmid, cag_host=host, timeout_s=float(timeout_s)),
            plain_path=Path(plain),
            write_plain=True,
            dry_run=False,
        )
    except Exception as e:  # noqa: BLE001
        out["error"] = f"mint_exc:{type(e).__name__}:{e}"
        return out

    pub = mres.as_public_dict() if hasattr(mres, "as_public_dict") else {}
    out["ok"] = bool(getattr(mres, "ok", False) or pub.get("ok"))
    out["error"] = getattr(mres, "error", None) or pub.get("error")
    # never copy plain/k; only public fields
    pf = pub.get("plain_fields") or {}
    out["plain_sha16"] = pf.get("plain_sha16") or pub.get("plain_sha16")
    out["production_claim"] = False
    out["dual_evidence_ok"] = False
    return out


def run_spice_oracle_keepalive_loop(
    *,
    http: Any = None,
    instance_id: str = "",
    machine_id: str = "",
    host: str = DEFAULT_CAG_HOST,
    plain: Path = Path(DEFAULT_PLAIN),
    pre: Path = Path(DEFAULT_PRE),
    post: Path = Path(DEFAULT_POST),
    heart_listen: float = DEFAULT_HEART_LISTEN_S,
    ticket_mode: str = DEFAULT_TICKET_MODE,
    session_nudge: Optional[bool] = None,
    agent_hb_every: float = 0.0,
    interval: int = 300,
    max_rounds: Optional[int] = None,
    out_dir: Optional[Path] = None,
    relogin_fn: Optional[Callable[[], Optional[str]]] = None,
    do_account_ping: bool = True,
    stop_on_fatal: bool = False,
    auto_remint: bool = True,
    remint_timeout_s: float = 20.0,
    plain_ttl_s: float = 0.0,
    mid_session_reconnect: bool = True,
) -> Dict[str, Any]:
    """Login-state HTTP + SPICE HEART + status/uptime oracle loop.

    auto_remint (default True): on auth220/handshake fail, mint once and
    retry path_B in the same round (frozen plain lifecycle after power-on).

    plain_ttl_s (>0): proactive remint when plain mtime age >= TTL
    (pre-path_B; frozen plain lifecycle / power-on remint family).

    mid_session_reconnect (default True): if auth/tls ok but heart/redq
    dropped, re-run path_B once without remint (mid-session only).

    Returns public summary dict (no secrets). production_claim always false.
    """
    host = _assert_public_host(host)
    plain = Path(plain)
    if not plain.is_file():
        raise FileNotFoundError(
            "plain missing (path not logged). Set SHORT_CONNECT_PLAIN_FILE "
            "or --plain to a connectStr plain file."
        )

    if out_dir is None:
        import os as _os
        env_out = (_os.environ.get("OUT_DIR") or _os.environ.get("SPICE_ORACLE_OUT_DIR") or "").strip()
        if env_out:
            out_dir = Path(env_out)
        else:
            out_dir = _ROOT / "reports" / "r26_live" / "spice_oracle_soak"
    out_dir = Path(out_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Docker uid often cannot write /app/reports
        out_dir = Path("/tmp/ecloud-pathb/reports/spice_oracle_soak")
        out_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now().strftime("%Y%m%dT%H%M%S")
    summary_path = out_dir / f"spice_oracle_{run_id}.jsonl"
    meta_path = out_dir / f"spice_oracle_{run_id}_meta.json"

    meta: Dict[str, Any] = {
        "run_id": run_id,
        "started": datetime.now().isoformat(timespec="seconds"),
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "freeze_cite": FREEZE_CITE,
        "host": host,
        "plain_exists": plain.is_file(),
        "plain_size": plain.stat().st_size if plain.is_file() else 0,
        "interval": int(interval),
        "max_rounds": max_rounds,
        "heart_listen": float(heart_listen),
        "ticket_mode": str(ticket_mode),
        "instance_id_prefix": (instance_id or "")[:16],
        "machine_id_set": bool(machine_id),
        "oracle": "getDesktopStatus+desktopUptime",
        "keepalive_plane": "path_B_SPICE_HEART",
        "public_path_only": True,
        "jtydn_forbidden": True,
        "auto_remint": bool(auto_remint),
        "plain_ttl_s": float(plain_ttl_s),
        "mid_session_reconnect": bool(mid_session_reconnect),
    }
    meta_path.write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    log.info(
        "spice+oracle start run_id=%s interval=%ds max_rounds=%s heart=%ss "
        "instance=%s plain_ttl=%ss mid_reconnect=%s claim=false host=%s",
        run_id,
        interval,
        max_rounds if max_rounds is not None else "inf",
        heart_listen,
        (instance_id or "")[:16] or "-",
        float(plain_ttl_s),
        bool(mid_session_reconnect),
        host,
    )

    rows: List[Dict[str, Any]] = []
    rounds = 0
    ok_heart = 0
    ok_redq = 0
    fail = 0
    oracle_ok_n = 0
    last_uptime = ""
    last_status = ""
    proactive_remint_n = 0
    mid_session_retry_n = 0

    try:
        while max_rounds is None or rounds < max_rounds:
            rounds += 1
            t0 = time.time()
            row: Dict[str, Any] = {
                "round": rounds,
                "ts": datetime.now().isoformat(timespec="seconds"),
                "production_claim": False,
                "dual_evidence_ok": False,
            }

            # --- L1 token ping (optional) ---
            if http is not None and do_account_ping:
                ap = _account_ping(http)
                row["account_ping_ok"] = bool(ap.get("ok"))
                if ap.get("token_expired") and relogin_fn:
                    log.warning("[%d] token expired on account ping → relogin", rounds)
                    tok = relogin_fn()
                    if tok and hasattr(http, "set_token"):
                        http.set_token(tok)
                        row["relogin"] = True
                    else:
                        row["relogin"] = False
                        log.error("[%d] relogin failed", rounds)

            # --- L3 SPICE path_B HEART (primary keepalive) ---
            spice_err = None
            spice: Dict[str, Any] = {}
            remint_meta: Optional[Dict[str, Any]] = None
            plain_age = _plain_age_s(plain)
            row["plain_age_s"] = (
                round(plain_age, 1) if plain_age is not None else None
            )

            # proactive remint when plain mtime age >= TTL (power-on / freeze lifecycle)
            if (
                auto_remint
                and float(plain_ttl_s) > 0
                and plain_age is not None
                and plain_age >= float(plain_ttl_s)
            ):
                log.warning(
                    "[%d] plain_age=%.0fs >= ttl=%.0fs → proactive remint",
                    rounds,
                    plain_age,
                    float(plain_ttl_s),
                )
                remint_meta = _try_remint_connectstr(
                    plain=plain,
                    host=host,
                    vmid_hint=str(machine_id or ""),
                    timeout_s=float(remint_timeout_s),
                )
                row["remint"] = {
                    "ok": bool(remint_meta.get("ok")),
                    "error": remint_meta.get("error"),
                    "vmid_prefix": remint_meta.get("vmid_prefix"),
                    "plain_sha16": remint_meta.get("plain_sha16"),
                    "reason": "plain_ttl",
                    "plain_age_s": round(plain_age, 1),
                    "production_claim": False,
                }
                if remint_meta.get("ok"):
                    proactive_remint_n += 1
                    plain_age = _plain_age_s(plain)
                    row["plain_age_s"] = (
                        round(plain_age, 1) if plain_age is not None else None
                    )
                else:
                    log.error(
                        "[%d] proactive remint failed: %s",
                        rounds,
                        remint_meta.get("error") or "unknown",
                    )

            try:
                spice = run_path_b_keepalive(
                    host=host,
                    plain=plain,
                    pre=pre,
                    post=post,
                    heart_listen=float(heart_listen),
                    ticket_mode=str(ticket_mode),
                    session_nudge=session_nudge,
                    agent_hb_every=float(agent_hb_every),
                    out=None,
                )
            except Exception as e:  # noqa: BLE001
                spice_err = f"{type(e).__name__}:{e}"
                log.exception("[%d] path_B SPICE failed: %s", rounds, e)
                spice = {
                    "ok_heart_keepalive": False,
                    "ok_redq_s2c": False,
                    "ok_auth220": False,
                    "ok_ztec50": False,
                    "ok_tls": False,
                    "heart_count": 0,
                    "error": spice_err,
                    "production_claim": False,
                }

            # auto-remint once per round on auth/handshake fail (frozen plain lifecycle)
            if auto_remint and _need_remint(spice, spice_err):
                log.warning(
                    "[%d] path_B need remint (auth220=%s ztec50=%s heart=%s) → mint",
                    rounds,
                    spice.get("ok_auth220"),
                    spice.get("ok_ztec50"),
                    spice.get("ok_heart_keepalive"),
                )
                remint_meta = _try_remint_connectstr(
                    plain=plain,
                    host=host,
                    vmid_hint=str(machine_id or ""),
                    timeout_s=float(remint_timeout_s),
                )
                row["remint"] = {
                    "ok": bool(remint_meta.get("ok")),
                    "error": remint_meta.get("error"),
                    "vmid_prefix": remint_meta.get("vmid_prefix"),
                    "plain_sha16": remint_meta.get("plain_sha16"),
                    "reason": "auth_fail",
                    "production_claim": False,
                }
                if remint_meta.get("ok"):
                    log.info(
                        "[%d] remint ok plain_sha16=%s → retry path_B",
                        rounds,
                        remint_meta.get("plain_sha16") or "-",
                    )
                    spice_err = None
                    try:
                        spice = run_path_b_keepalive(
                            host=host,
                            plain=plain,
                            pre=pre,
                            post=post,
                            heart_listen=float(heart_listen),
                            ticket_mode=str(ticket_mode),
                            session_nudge=session_nudge,
                            agent_hb_every=float(agent_hb_every),
                            out=None,
                        )
                        row["remint"]["retry"] = True
                    except Exception as e:  # noqa: BLE001
                        spice_err = f"{type(e).__name__}:{e}"
                        log.exception(
                            "[%d] path_B SPICE retry after remint failed: %s",
                            rounds,
                            e,
                        )
                        spice = {
                            "ok_heart_keepalive": False,
                            "ok_redq_s2c": False,
                            "ok_auth220": False,
                            "ok_ztec50": False,
                            "ok_tls": False,
                            "heart_count": 0,
                            "error": spice_err,
                            "production_claim": False,
                        }
                        row["remint"]["retry"] = False
                        row["remint"]["retry_error"] = spice_err
                else:
                    log.error(
                        "[%d] remint failed: %s",
                        rounds,
                        remint_meta.get("error") or "unknown",
                    )

            # mid-session drop: auth/tls ok but heart/redq lost → reconnect once (no remint)
            if (
                mid_session_reconnect
                and not bool(spice.get("ok_heart_keepalive"))
                and _is_mid_session_drop(spice, spice_err)
            ):
                log.warning(
                    "[%d] mid-session drop (auth220=%s heart=%s redq=%s) → reconnect path_B",
                    rounds,
                    spice.get("ok_auth220"),
                    spice.get("ok_heart_keepalive"),
                    spice.get("ok_redq_s2c"),
                )
                mid_meta: Dict[str, Any] = {
                    "triggered": True,
                    "reason": "mid_session_drop",
                    "production_claim": False,
                }
                spice_err = None
                try:
                    spice = run_path_b_keepalive(
                        host=host,
                        plain=plain,
                        pre=pre,
                        post=post,
                        heart_listen=float(heart_listen),
                        ticket_mode=str(ticket_mode),
                        session_nudge=session_nudge,
                        agent_hb_every=float(agent_hb_every),
                        out=None,
                    )
                    mid_meta["retry"] = True
                    mid_meta["ok_heart_after"] = bool(
                        spice.get("ok_heart_keepalive")
                    )
                    mid_session_retry_n += 1
                except Exception as e:  # noqa: BLE001
                    spice_err = f"{type(e).__name__}:{e}"
                    log.exception(
                        "[%d] mid-session path_B reconnect failed: %s", rounds, e
                    )
                    spice = {
                        "ok_heart_keepalive": False,
                        "ok_redq_s2c": False,
                        "ok_auth220": spice.get("ok_auth220"),
                        "ok_ztec50": spice.get("ok_ztec50"),
                        "ok_tls": spice.get("ok_tls"),
                        "heart_count": 0,
                        "error": spice_err,
                        "production_claim": False,
                    }
                    mid_meta["retry"] = False
                    mid_meta["retry_error"] = spice_err
                row["mid_session"] = mid_meta

            heart_ok = bool(spice.get("ok_heart_keepalive"))
            redq_ok = bool(spice.get("ok_redq_s2c"))
            if heart_ok:
                ok_heart += 1
            elif redq_ok:
                ok_redq += 1
            else:
                fail += 1

            # dual-plane evidence fields (observe-only; never promote dual_evidence_ok)
            s2c_hist = dict(spice.get("s2c_type_hist") or {})
            hearts_raw = list(spice.get("hearts") or [])
            # hearts: keep compact public samples (t/type/serial only, no payloads)
            hearts_pub = []
            for h in hearts_raw[:16]:
                if isinstance(h, dict):
                    hearts_pub.append(
                        {
                            "t": h.get("t"),
                            "type": h.get("type"),
                            "serial": h.get("serial"),
                        }
                    )
                else:
                    hearts_pub.append(h)
            row["spice"] = {
                "ok_ztec50": spice.get("ok_ztec50"),
                "ok_auth220": spice.get("ok_auth220"),
                "ok_tls": spice.get("ok_tls"),
                "ok_redq_s2c": redq_ok,
                "ok_heart_keepalive": heart_ok,
                "heart_count": spice.get("heart_count", 0),
                "s2c_type_hist": s2c_hist,
                "s2c_frame_count": int(spice.get("s2c_frame_count") or 0),
                "hearts": hearts_pub,
                "agent_hb_count": int(spice.get("agent_hb_count") or 0),
                "error": spice.get("error") or spice_err,
                "freeze_cite": spice.get("freeze_cite") or FREEZE_CITE,
                "reminted": bool(remint_meta and remint_meta.get("ok")),
            }

            # --- HTTP oracle (status + uptime) — NOT keepalive ---
            if http is not None and instance_id:
                ora = _oracle_once(http, instance_id=instance_id, machine_id=machine_id)
                if ora.get("token_expired") and relogin_fn:
                    log.warning("[%d] token expired on oracle → relogin", rounds)
                    tok = relogin_fn()
                    if tok and hasattr(http, "set_token"):
                        http.set_token(tok)
                        row["relogin"] = True
                        # one retry after relogin
                        ora = _oracle_once(
                            http, instance_id=instance_id, machine_id=machine_id
                        )
                row["oracle"] = {
                    "ok": bool(ora.get("oracle_ok")),
                    "resource_status": ora.get("resource_status") or "",
                    "uptime": ora.get("uptime") or "",
                    "error": ora.get("error"),
                }
                if ora.get("oracle_ok"):
                    oracle_ok_n += 1
                last_status = str(ora.get("resource_status") or last_status)
                last_uptime = str(ora.get("uptime") or last_uptime)
            else:
                row["oracle"] = {
                    "ok": False,
                    "resource_status": "",
                    "uptime": "",
                    "error": "no_http_or_instance",
                    "skipped": True,
                }

            row["elapsed_s"] = round(time.time() - t0, 3)
            # dual_plane observe fields on every jsonl row (never promotes dual_ok/claim)
            _hist = spice.get("s2c_type_hist") or {}
            _s2c74 = int(_hist.get("0x74") or _hist.get(0x74) or 0)
            _ora = row.get("oracle") or {}
            _ora_ok = bool(_ora.get("ok"))
            row["dual_plane"] = {
                "s2c_0x74": _s2c74,
                "heart_count": int(spice.get("heart_count") or 0),
                "ok_heart": bool(heart_ok),
                "oracle_ok": _ora_ok,
                "resource_status": _ora.get("resource_status") or "",
                "uptime": _ora.get("uptime") or "",
                "plane_match": bool(heart_ok and _s2c74 >= 1 and _ora_ok),
                "promotes_dual_evidence_ok": False,
                "promotes_production_claim": False,
            }
            rows.append(row)

            # human-readable line (what the user asked for)
            log.info(
                "[%d] SPICE heart=%s redq=%s hearts=%s | "
                "oracle status=%s uptime=%s ok=%s | plane_match=%s | claim=false",
                rounds,
                heart_ok,
                redq_ok,
                spice.get("heart_count", 0),
                (row.get("oracle") or {}).get("resource_status") or "-",
                (row.get("oracle") or {}).get("uptime") or "-",
                (row.get("oracle") or {}).get("ok"),
                (row.get("dual_plane") or {}).get("plane_match"),
            )

            with summary_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

            if stop_on_fatal and not heart_ok and not redq_ok:
                log.error("[%d] fatal SPICE fail stop_on_fatal=1", rounds)
                break

            if max_rounds is None or rounds < max_rounds:
                # sleep remaining interval (interval = time between round starts)
                slept = time.time() - t0
                wait = max(0.0, float(interval) - slept)
                if wait > 0:
                    log.info("[%d] sleep %.1fs → next round", rounds, wait)
                    time.sleep(wait)
    except KeyboardInterrupt:
        log.info("interrupted by user after %d rounds", rounds)

    remint_ok_n = sum(
        1 for r in rows if (r.get("remint") or {}).get("ok")
    )
    remint_retry_n = sum(
        1 for r in rows if (r.get("remint") or {}).get("retry")
    )
    proactive_remint_n = sum(
        1
        for r in rows
        if (r.get("remint") or {}).get("ok")
        and (r.get("remint") or {}).get("reason") == "plain_ttl"
    )
    mid_session_retry_n = sum(
        1 for r in rows if (r.get("mid_session") or {}).get("retry")
    )
    # dual-plane observe summary (never promotes dual_evidence_ok / claim)
    dual_plane_rows: List[Dict[str, Any]] = []
    s2c_0x74_rounds = 0
    dual_plane_match_rounds = 0
    for r in rows:
        sp = r.get("spice") or {}
        ora = r.get("oracle") or {}
        hist = sp.get("s2c_type_hist") or {}
        # accept both "0x74" and 0x74 keys
        c74 = int(hist.get("0x74") or hist.get(0x74) or hist.get("116") or 0)
        has_0x74 = c74 > 0 or bool(sp.get("ok_heart_keepalive"))
        if has_0x74:
            s2c_0x74_rounds += 1
        ora_ok = bool(ora.get("ok"))
        match = bool(has_0x74 and ora_ok)
        if match:
            dual_plane_match_rounds += 1
        dual_plane_rows.append(
            {
                "round": r.get("round"),
                "s2c_0x74": c74,
                "heart_count": sp.get("heart_count"),
                "ok_heart": sp.get("ok_heart_keepalive"),
                "oracle_ok": ora_ok,
                "resource_status": ora.get("resource_status") or "",
                "uptime": ora.get("uptime") or "",
                "plane_match": match,
            }
        )
    finished: Dict[str, Any] = {
        "run_id": run_id,
        "started": meta["started"],
        "ended": datetime.now().isoformat(timespec="seconds"),
        "production_claim": False,
        "dual_evidence_ok": False,  # HARD pin — observe-only dual_plane never flips this
        "auto_remint": bool(auto_remint),
        "remint_ok_rounds": remint_ok_n,
        "remint_retry_rounds": remint_retry_n,
        "proactive_remint_rounds": proactive_remint_n,
        "mid_session_retry_rounds": mid_session_retry_n,
        "plain_ttl_s": float(plain_ttl_s),
        "mid_session_reconnect": bool(mid_session_reconnect),
        "agent_dual_ok": False,  # HARD_NEG: agent C2S HB never dual
        "freeze_cite": FREEZE_CITE,
        "host": host,
        "rounds": rounds,
        "ok_heart_rounds": ok_heart,
        "ok_redq_rounds": ok_redq,
        "fail_rounds": fail,
        "oracle_ok_rounds": oracle_ok_n,
        "last_resource_status": last_status,
        "last_uptime": last_uptime,
        "summary_path": str(summary_path),
        "meta_path": str(meta_path),
        "instance_id_prefix": (instance_id or "")[:16],
        "keepalive_plane": "path_B_SPICE_HEART",
        "oracle_plane": "getDesktopStatus+desktopUptime",
        "dual_plane": {
            "definition": "SPICE_S2C_0x74_HEART ∩ HTTP_oracle(status+uptime)",
            "s2c_0x74_rounds": s2c_0x74_rounds,
            "oracle_ok_rounds": oracle_ok_n,
            "plane_match_rounds": dual_plane_match_rounds,
            "promotes_dual_evidence_ok": False,
            "promotes_production_claim": False,
            "agent_c2s_hard_neg": True,
            "rows": dual_plane_rows[-8:],
        },
        "rows_tail": rows[-3:],
    }
    fin_text = json.dumps(finished, indent=2, ensure_ascii=False)
    fin_path = out_dir / f"spice_oracle_{run_id}_final.json"
    fin_path.write_text(fin_text + "\n", encoding="utf-8")
    finished["final_path"] = str(fin_path)
    finished["final_sha16"] = hashlib.sha256(fin_text.encode()).hexdigest()[:16]

    log.info(
        "spice+oracle end run_id=%s rounds=%d heart=%d redq=%d fail=%d "
        "oracle_ok=%d last_status=%s last_uptime=%s claim=false",
        run_id,
        rounds,
        ok_heart,
        ok_redq,
        fail,
        oracle_ok_n,
        last_status or "-",
        last_uptime or "-",
    )
    return finished


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="SPICE path_B + status/uptime oracle loop (claim=false)"
    )
    ap.add_argument("--host", default=DEFAULT_CAG_HOST)
    ap.add_argument("--plain", default=DEFAULT_PLAIN)
    ap.add_argument("--pre", default=DEFAULT_PRE)
    ap.add_argument("--post", default=DEFAULT_POST)
    ap.add_argument("--heart-listen", type=float, default=DEFAULT_HEART_LISTEN_S)
    ap.add_argument("--ticket-mode", default=DEFAULT_TICKET_MODE)
    ap.add_argument("--interval", type=int, default=300)
    ap.add_argument("--rounds", type=int, default=None)
    ap.add_argument("--instance-id", default="")
    ap.add_argument("--machine-id", default="")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--no-account-ping", action="store_true")
    ap.add_argument(
        "--no-auto-remint",
        action="store_true",
        help="disable auto remint on auth220 fail (default remint once+retry)",
    )
    ap.add_argument(
        "--remint-timeout",
        type=float,
        default=20.0,
        help="mint timeout seconds when auto-remint (default 20)",
    )
    ap.add_argument(
        "--plain-ttl",
        type=float,
        default=0.0,
        help="proactive remint when plain mtime age >= N seconds (0=off)",
    )
    ap.add_argument(
        "--no-mid-session-reconnect",
        action="store_true",
        help="disable mid-session path_B reconnect (auth ok / heart drop)",
    )
    args = ap.parse_args(argv)

    finished = run_spice_oracle_keepalive_loop(
        http=None,
        instance_id=args.instance_id,
        machine_id=args.machine_id,
        host=args.host,
        plain=Path(args.plain),
        pre=Path(args.pre),
        post=Path(args.post),
        heart_listen=float(args.heart_listen),
        ticket_mode=str(args.ticket_mode),
        interval=int(args.interval),
        max_rounds=args.rounds,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        do_account_ping=not args.no_account_ping,
        auto_remint=not bool(args.no_auto_remint),
        remint_timeout_s=float(args.remint_timeout),
        plain_ttl_s=float(args.plain_ttl),
        mid_session_reconnect=not bool(args.no_mid_session_reconnect),
    )
    print(json.dumps({k: finished[k] for k in finished if k != "rows_tail"}, indent=2))
    if finished.get("ok_heart_rounds", 0) > 0:
        return 0
    if finished.get("ok_redq_rounds", 0) > 0:
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
