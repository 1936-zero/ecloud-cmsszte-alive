#!/usr/bin/env python3
"""#26 packaging consumer for path_B CAG HEART keepalive (claim=false).

Stock-correct defaults (T41/T43/T45/T45b CLOSED):
  - ticket_mode = zeros  (Write_if g_malloc0(128); classic RSA HARD_NEG)
  - session_nudge = ON when heart_listen > 0  (1× C2S agent empty HB → S2C HEART)
  - keepalive dual = S2C 0x74 HEART + C2S 0x79 ACK only
  - agent dual_ok = HARD_NEG (C2S-only; never promote)

PIN: public ecloud :9222 ONLY · 禁 jtydn/爱家
Secrets: plain via SHORT_CONNECT_PLAIN_FILE / --plain; never log -k.
production_claim=false · dual_evidence_ok=false · agent_dual_ok=false
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

FREEZE_CITE = "a46d55cd523da9fd"
PRODUCTION_CLAIM = False
DUAL_EVIDENCE_OK = False
AGENT_DUAL_OK = False

# Stock policy pins (do not invent)
DEFAULT_CAG_HOST = "36.212.224.105"
DEFAULT_CAG_PORT = 8899
DEFAULT_TICKET_MODE = "zeros"
DEFAULT_HEART_LISTEN_S = 35.0
from l3.platform_paths import (  # noqa: E402
    DEFAULT_PLAIN as _PP_PLAIN,
    DEFAULT_POST as _PP_POST,
    DEFAULT_PRE as _PP_PRE,
)

DEFAULT_PLAIN = os.environ.get("SHORT_CONNECT_PLAIN_FILE") or _PP_PLAIN
DEFAULT_PRE = os.environ.get("PATH_B_TMPL_PRE") or _PP_PRE
DEFAULT_POST = os.environ.get("PATH_B_TMPL_POST") or _PP_POST

# HEART dual types (vendor wrap 0a01)
TYPE_HEART_S2C = 0x74
TYPE_HEART_ACK_C2S = 0x79


@dataclass
class PackagePolicy:
    """Public, secret-free policy contract for residual#26 packaging."""

    freeze_cite: str = FREEZE_CITE
    production_claim: bool = PRODUCTION_CLAIM
    dual_evidence_ok: bool = DUAL_EVIDENCE_OK
    agent_dual_ok: bool = AGENT_DUAL_OK
    ticket_mode: str = DEFAULT_TICKET_MODE
    session_nudge_default_when_heart: bool = True
    keepalive_dual: str = "HEART_0x74_ACK_0x79"
    agent_direction: str = "C2S_only"
    pin_product_line: str = "public_ecloud_9222"
    ban_lines: List[str] = field(
        default_factory=lambda: ["jtydn", "爱家", "cmcc-jtydn:9223"]
    )
    classic_rsa_ticket: str = "HARD_NEG"
    notes: List[str] = field(default_factory=list)

    def as_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


def policy_selfcheck() -> Dict[str, Any]:
    """Offline contract check — no network, no secret dump."""
    pol = PackagePolicy()
    checks: Dict[str, bool] = {}
    notes: List[str] = []

    checks["ticket_zeros"] = pol.ticket_mode == "zeros"
    checks["nudge_default_on"] = pol.session_nudge_default_when_heart is True
    checks["agent_dual_false"] = pol.agent_dual_ok is False
    checks["dual_evidence_false"] = pol.dual_evidence_ok is False
    checks["claim_false"] = pol.production_claim is False
    checks["ban_jtydn"] = "jtydn" in " ".join(pol.ban_lines)
    checks["freeze_cite"] = pol.freeze_cite == FREEZE_CITE

    # Import path_B without connecting
    try:
        import path_b_cag_posttls as pb  # noqa: WPS

        checks["import_path_b"] = True
        # CLI defaults: session_nudge None → ON when heart_listen>0
        # ticket default in package is zeros; path_b main may still say template —
        # package forces zeros on run().
        checks["path_b_has_connect"] = callable(getattr(pb, "path_b_connect", None))
        checks["path_b_has_pack_0a01"] = callable(getattr(pb, "pack_0a01", None))
    except Exception as e:  # pragma: no cover
        checks["import_path_b"] = False
        notes.append(f"import_path_b={type(e).__name__}:{e}")

    # CLI BooleanOptional presence via help text (no live)
    try:
        import path_b_cag_posttls as pb

        # inspect main defaults by re-running argparse construct if available
        # We only assert module attributes exist.
        src = Path(pb.__file__).read_text(encoding="utf-8", errors="ignore")
        checks["cli_has_session_nudge"] = "--session-nudge" in src
        checks["cli_has_no_session_nudge"] = "--no-session-nudge" in src or (
            "BooleanOptionalAction" in src and "session-nudge" in src
        )
        checks["cli_documents_default_nudge"] = "Default ON when" in src or (
            "default ON" in src.lower()
        )
    except Exception as e:  # pragma: no cover
        notes.append(f"cli_scan={type(e).__name__}:{e}")

    ok = all(checks.values())
    out = {
        "selfcheck": "PASS" if ok else "FAIL",
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "policy": pol.as_public_dict(),
        "checks": checks,
        "notes": notes,
        "module": "path_b_keepalive_package",
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    return out


def run_path_b_keepalive(
    *,
    host: str = DEFAULT_CAG_HOST,
    plain: Path = Path(DEFAULT_PLAIN),
    heart_listen: float = DEFAULT_HEART_LISTEN_S,
    ticket_mode: str = DEFAULT_TICKET_MODE,
    session_nudge: Optional[bool] = None,
    agent_hb_every: float = 0.0,
    pre: Path = Path(DEFAULT_PRE),
    post: Path = Path(DEFAULT_POST),
    extra_c2s: Optional[Path] = None,
    out: Optional[Path] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Invoke path_b_connect with stock packaging defaults. Never logs -k/plain.

    should_stop: optional callback; when True mid heart_listen, abort early
    (#75fixah WebUI stop without waiting full heart_listen).
    """
    import path_b_cag_posttls as pb

    if session_nudge is None:
        session_nudge = bool(heart_listen and heart_listen > 0)

    extra_frames: Optional[List[bytes]] = None
    if extra_c2s is not None:
        raw = Path(extra_c2s).read_bytes()
        # path_b main splits by SpiceDataHeader; package passes whole blob once
        # via extra_c2s_frames list of individual frames if multiple — keep raw
        # as single element if caller already pre-split is unknown; pass as one.
        extra_frames = [raw] if raw else None

    r = pb.path_b_connect(
        host,
        plain_file=Path(plain),
        tmpl_pre=Path(pre),
        tmpl_post=Path(post),
        heart_listen_s=float(heart_listen),
        agent_hb_every=float(agent_hb_every),
        ticket_mode=str(ticket_mode),
        extra_c2s_frames=extra_frames,
        session_nudge=bool(session_nudge),
        should_stop=should_stop,
    )

    # Public summary — no secrets
    s2c_hist = dict(getattr(r, "s2c_type_hist", {}) or {})
    # normalize hist keys to hex-ish strings if int
    s2c_hist_pub = {
        (hex(k) if isinstance(k, int) else str(k)): v for k, v in s2c_hist.items()
    }
    out_obj: Dict[str, Any] = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "package": "path_b_keepalive_package",
        "freeze_cite": FREEZE_CITE,
        "host": host,
        "ticket_mode": ticket_mode,
        "session_nudge": bool(session_nudge),
        "heart_listen_s": float(heart_listen),
        "ok_ztec50": bool(getattr(r, "ok_ztec50", False)),
        "ok_auth220": bool(getattr(r, "ok_auth220", False)),
        "ok_tls": bool(getattr(r, "ok_tls", False)),
        "ok_redq_s2c": bool(getattr(r, "ok_redq_s2c", False)),
        "ok_heart_keepalive": bool(getattr(r, "ok_heart_keepalive", False)),
        "heart_count": int(getattr(r, "heart_count", 0) or 0),
        "hearts": list(getattr(r, "hearts", []) or []),
        "agent_hb_count": int(getattr(r, "agent_hb_count", 0) or 0),
        "s2c_type_hist": s2c_hist_pub,
        "s2c_frame_count": int(getattr(r, "s2c_frame_count", 0) or 0),
        "error": getattr(r, "error", None),
        "stages_focus": [
            s
            for s in (getattr(r, "stages", []) or [])
            if isinstance(s, dict)
            and (
                s.get("name")
                in (
                    "session_nudge",
                    "session_nudge_err",
                    "heart_listen",
                    "heart_listen_aborted",  # #75fixai stop path
                    "redq_s2c",
                    "ticket",
                )
                or "nudge" in str(s.get("name", ""))
                or "abort" in str(s.get("name", ""))
            )
        ],
        # #75fixai: full stages so oracle can detect user abort without remint/reconnect
        "stages": list(getattr(r, "stages", []) or []),
        "policy": PackagePolicy().as_public_dict(),
    }

    if out is not None:
        text = json.dumps(out_obj, indent=2, ensure_ascii=False)
        Path(out).write_text(text, encoding="utf-8")
        out_obj["out_sha16"] = hashlib.sha256(text.encode()).hexdigest()[:16]

    return out_obj


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="#26 path_B keepalive package (claim=false; stock zeros+nudge)"
    )
    ap.add_argument(
        "--selfcheck",
        action="store_true",
        help="offline policy/import selftest (default if no --live)",
    )
    ap.add_argument(
        "--live",
        action="store_true",
        help="LIVE CAG path_B with stock defaults (claim=false)",
    )
    # issue#2: empty default → resolve_gateway/cloud_pc (not stock GZ4 pin)
    ap.add_argument(
        "--host",
        default=os.environ.get("CAG_HOST", "") or "",
        help="CAG host override (empty=resolve from cloud_pc / env / default)",
    )
    ap.add_argument(
        "--plain",
        default=os.environ.get("SHORT_CONNECT_PLAIN_FILE", DEFAULT_PLAIN),
        help="plain connectStr path (never logged)",
    )
    ap.add_argument("--heart-listen", type=float, default=DEFAULT_HEART_LISTEN_S)
    ap.add_argument(
        "--ticket-mode",
        choices=("template", "zeros", "random"),
        default=DEFAULT_TICKET_MODE,
        help="stock-correct default: zeros",
    )
    ap.add_argument(
        "--session-nudge",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="default ON when --heart-listen>0; --no-session-nudge for pure-idle A/B",
    )
    ap.add_argument("--agent-hb-every", type=float, default=0.0)
    ap.add_argument("--pre", default=DEFAULT_PRE)
    ap.add_argument("--post", default=DEFAULT_POST)
    ap.add_argument("--extra-c2s", default="", help="optional raw frame file")
    ap.add_argument("--out", default="")
    ap.add_argument(
        "--mint",
        action="store_true",
        help="optional preflight: refresh plain via l3/connectstr_mint (claim=false)",
    )
    ap.add_argument(
        "--mint-timeout",
        type=float,
        default=25.0,
        help="timeout for optional --mint HTTP (s)",
    )
    args = ap.parse_args(argv)

    if args.selfcheck or not args.live:
        out = policy_selfcheck()
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if out.get("selfcheck") == "PASS" else 2

    # LIVE
    out_path = Path(args.out) if args.out else None
    if out_path is None:
        # default under nest reports if present
        nest = _L3.parent / "reports" / "r26_live"
        nest.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        out_path = nest / f"pkg_pathb_keepalive_{ts}.json"

    mint_info = None
    if args.mint:
        # optional connectStr refresh; never log -k/plain
        try:
            from connectstr_mint import MintRequest, mint_connectstr  # type: ignore
        except Exception as e:  # pragma: no cover
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"mint_import_fail:{type(e).__name__}",
                        "production_claim": False,
                    },
                    ensure_ascii=False,
                )
            )
            return 4
        # resolve vmid like connectstr_mint.main (cloud_pc → plain --vmid)
        try:
            from connectstr_mint import load_vmid_from_cloud_pc  # type: ignore
        except Exception:
            load_vmid_from_cloud_pc = None  # type: ignore
        vmid = ""
        if load_vmid_from_cloud_pc is not None:
            try:
                vmid = load_vmid_from_cloud_pc() or ""
            except Exception:
                vmid = ""
        if not vmid:
            try:
                import re as _re

                _pt = Path(args.plain).read_text(encoding="utf-8", errors="ignore")
                _m = _re.search(r"--vmid\s+(\S+)", _pt)
                if _m:
                    vmid = _m.group(1)
            except Exception:
                pass
        if vmid and str(vmid).upper().startswith("CCA-"):
            # suOper wants machine_id UUID; CCA- instance_id → 501 no_connectStr
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "mint_vmid_is_instance_id_not_machine_id",
                        "production_claim": False,
                    },
                    ensure_ascii=False,
                )
            )
            return 4
        if not vmid:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "mint_vmid_missing",
                        "production_claim": False,
                    },
                    ensure_ascii=False,
                )
            )
            return 4
        # issue#2: full gateway (host/port/csapip); empty/DEFAULT host → cloud_pc wins
        try:
            from gateway_config import (  # type: ignore
                DEFAULT_CAG_HOST as _DEF_CAG,
                resolve_gateway,
            )
        except Exception:
            try:
                from l3.gateway_config import (  # type: ignore
                    DEFAULT_CAG_HOST as _DEF_CAG,
                    resolve_gateway,
                )
            except Exception as e:  # pragma: no cover
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "error": f"gateway_import_fail:{type(e).__name__}",
                            "production_claim": False,
                        },
                        ensure_ascii=False,
                    )
                )
                return 4
        _hin = (args.host or "").strip()
        _cag_arg = _hin if _hin and _hin != _DEF_CAG else None
        try:
            gw = resolve_gateway(
                cag_host=_cag_arg,
                try_client_discovery=True,
                allow_default=True,
            )
        except Exception as e:  # pragma: no cover
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"gateway_resolve_fail:{type(e).__name__}",
                        "production_claim": False,
                    },
                    ensure_ascii=False,
                )
            )
            return 4
        mres = mint_connectstr(
            MintRequest(
                vmid=vmid,
                cag_host=gw.cag_host,
                cag_port=int(gw.cag_port),
                csapip=str(gw.csapip or ""),
                timeout_s=float(args.mint_timeout),
            ),
            plain_path=Path(args.plain),
            write_plain=True,
            dry_run=False,
        )
        mint_info = mres.as_public_dict()
        if not mres.ok:
            print(json.dumps({"ok": False, "mint": mint_info}, ensure_ascii=False, indent=2))
            return 4

    # issue#2: empty host → resolve_gateway (cloud_pc regional CAG)
    _run_host = (args.host or "").strip()
    if not _run_host:
        try:
            try:
                from gateway_config import (  # type: ignore
                    DEFAULT_CAG_HOST as _DEF_H,
                    resolve_gateway as _rg,
                )
            except Exception:
                from l3.gateway_config import (  # type: ignore
                    DEFAULT_CAG_HOST as _DEF_H,
                    resolve_gateway as _rg,
                )
            _run_host = str(
                _rg(try_client_discovery=True, allow_default=True).cag_host or ""
            ) or _DEF_H
        except Exception:
            try:
                from gateway_config import DEFAULT_CAG_HOST as _DEF_H  # type: ignore
            except Exception:
                from l3.gateway_config import DEFAULT_CAG_HOST as _DEF_H  # type: ignore
            _run_host = _DEF_H
    result = run_path_b_keepalive(
        host=_run_host,
        plain=Path(args.plain),
        heart_listen=float(args.heart_listen),
        ticket_mode=str(args.ticket_mode),
        session_nudge=args.session_nudge,
        agent_hb_every=float(args.agent_hb_every),
        pre=Path(args.pre),
        post=Path(args.post),
        extra_c2s=Path(args.extra_c2s) if args.extra_c2s else None,
        out=out_path,
    )
    if mint_info is not None:
        result = dict(result)
        result["mint"] = mint_info
        result["production_claim"] = False
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("ok_heart_keepalive"):
        return 0
    if result.get("ok_redq_s2c"):
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
