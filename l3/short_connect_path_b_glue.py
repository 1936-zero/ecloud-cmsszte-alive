#!/usr/bin/env python3
"""#26/#27 glue: short_connect skeleton ↔ path_B keepalive package.

production_claim=false · dual_evidence_ok=false · agent_dual_ok=false
PIN: public ecloud :9222 ONLY · 禁 jtydn/爱家 · FREEZE a46d55cd523da9fd

Two planes stay separate (do not invent merge):
  A) short_connect (#27) — ICE peer plan (hv6:5100); offline selfcheck PASS;
     LIVE TCP env-gated (SHORT_CONNECT_HOST/PORT); currently env-blocked.
  B) path_B package (#26) — CAG post-TLS HEART dual 0x74/0x79; stock zeros+nudge;
     LIVE already proven T37–T46.

Glue does:
  - import both modules offline
  - route by plane: default keepalive consumer = path_B CAG
  - share plain-file path env (SHORT_CONNECT_PLAIN_FILE) without logging -k
  - never promote agent dual or classic RSA ticket

Does NOT:
  - claim dual_evidence_ok / production keepalive
  - open jtydn / 爱家
  - invent ICE↔CAG protocol merge
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
from typing import Any, Dict, List, Optional

_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

FREEZE_CITE = "a46d55cd523da9fd"
PRODUCTION_CLAIM = False
DUAL_EVIDENCE_OK = False
AGENT_DUAL_OK = False

# Default CAG plane (path_B stock)
DEFAULT_CAG_HOST = "36.212.224.105"
DEFAULT_CAG_PORT = 8899
DEFAULT_PLAIN = os.environ.get("SHORT_CONNECT_PLAIN_FILE", "/tmp/r26_t29_plain")

# Route labels
ROUTE_PATH_B_CAG = "path_b_cag_keepalive"
ROUTE_ICE_SHORT = "ice_short_connect"
ROUTE_UNKNOWN = "unknown"


@dataclass
class GlueRoute:
    """Public, secret-free route decision."""

    plane: str  # ROUTE_*
    reason: str
    consumer: str  # module name
    keepalive_dual: str = "HEART_0x74_ACK_0x79"  # only path_B claims wire dual
    ice_live_env: bool = False
    notes: List[str] = field(default_factory=list)

    def as_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


def choose_route(
    *,
    prefer: str = "path_b",
    ice_env: Optional[bool] = None,
) -> GlueRoute:
    """Select consumer plane.

    prefer:
      - path_b (default): residual#26 keepalive packaging (LIVE proven)
      - ice: residual#27 short_connect ICE skeleton (LIVE env-blocked)
    """
    if ice_env is None:
        ice_env = bool(
            os.environ.get("SHORT_CONNECT_HOST", "").strip()
            and os.environ.get("SHORT_CONNECT_PORT", "").strip()
        )

    prefer = (prefer or "path_b").strip().lower()
    notes: List[str] = [
        "planes separate: ICE peer ≠ CAG post-TLS",
        "agent dual HARD_NEG (C2S-only)",
        "classic RSA-ticket HARD_NEG; stock ticket=zeros",
        f"freeze_cite={FREEZE_CITE}",
    ]

    if prefer in ("ice", "short", "short_connect", ROUTE_ICE_SHORT):
        return GlueRoute(
            plane=ROUTE_ICE_SHORT,
            reason="prefer=ice skeleton; LIVE only if SHORT_CONNECT_* set",
            consumer="short_connect_skeleton",
            keepalive_dual="none_on_ice_plane",
            ice_live_env=bool(ice_env),
            notes=notes
            + [
                "hv6:5100 historically env-blocked",
                "TCP probe only unless handshake wired",
            ],
        )

    # default path_B
    return GlueRoute(
        plane=ROUTE_PATH_B_CAG,
        reason="prefer=path_b stock keepalive (zeros+default-nudge)",
        consumer="path_b_keepalive_package",
        keepalive_dual="HEART_0x74_ACK_0x79",
        ice_live_env=bool(ice_env),
        notes=notes
        + [
            f"default_cag={DEFAULT_CAG_HOST}:{DEFAULT_CAG_PORT}",
            "plain via SHORT_CONNECT_PLAIN_FILE / --plain (never logged)",
        ],
    )


def glue_selfcheck() -> Dict[str, Any]:
    """Offline contract: both modules import + route + policy pins."""
    checks: Dict[str, bool] = {}
    notes: List[str] = []

    # --- import short_connect ---
    try:
        import short_connect_skeleton as sc  # noqa: WPS

        checks["import_short_connect"] = True
        sc_out = sc.offline_selfcheck()
        checks["short_connect_selfcheck"] = sc_out.get("selfcheck") == "PASS"
        checks["short_dual_false"] = sc_out.get("dual_evidence_ok") is False
        notes.append(
            f"short_peer_path={((sc_out.get('peer') or {}).get('path'))}"
        )
    except Exception as e:  # pragma: no cover
        checks["import_short_connect"] = False
        checks["short_connect_selfcheck"] = False
        checks["short_dual_false"] = False
        notes.append(f"short_err={type(e).__name__}:{e}")

    # --- import path_B package ---
    try:
        import path_b_keepalive_package as pkg  # noqa: WPS

        checks["import_path_b_package"] = True
        pkg_out = pkg.policy_selfcheck()
        checks["path_b_package_selfcheck"] = pkg_out.get("selfcheck") == "PASS"
        checks["pkg_claim_false"] = pkg_out.get("production_claim") is False
        checks["pkg_agent_dual_false"] = pkg_out.get("agent_dual_ok") is False
        checks["pkg_dual_evidence_false"] = pkg_out.get("dual_evidence_ok") is False
        pol = (pkg_out.get("policy") or {})
        checks["pkg_ticket_zeros"] = pol.get("ticket_mode") == "zeros"
        checks["pkg_nudge_default"] = pol.get("session_nudge_default_when_heart") is True
    except Exception as e:  # pragma: no cover
        checks["import_path_b_package"] = False
        checks["path_b_package_selfcheck"] = False
        checks["pkg_claim_false"] = False
        checks["pkg_agent_dual_false"] = False
        checks["pkg_dual_evidence_false"] = False
        checks["pkg_ticket_zeros"] = False
        checks["pkg_nudge_default"] = False
        notes.append(f"pkg_err={type(e).__name__}:{e}")

    # --- routes ---
    r_pb = choose_route(prefer="path_b", ice_env=False)
    r_ice = choose_route(prefer="ice", ice_env=False)
    checks["route_path_b"] = r_pb.plane == ROUTE_PATH_B_CAG
    checks["route_ice"] = r_ice.plane == ROUTE_ICE_SHORT
    checks["route_consumers_distinct"] = r_pb.consumer != r_ice.consumer
    checks["freeze_cite"] = FREEZE_CITE == "a46d55cd523da9fd"
    checks["claim_false"] = PRODUCTION_CLAIM is False
    checks["dual_false"] = DUAL_EVIDENCE_OK is False
    checks["agent_dual_false"] = AGENT_DUAL_OK is False

    ok = all(checks.values())
    out: Dict[str, Any] = {
        "selfcheck": "PASS" if ok else "FAIL",
        "module": "short_connect_path_b_glue",
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "freeze_cite": FREEZE_CITE,
        "checks": checks,
        "notes": notes,
        "routes": {
            "default_path_b": r_pb.as_public_dict(),
            "prefer_ice": r_ice.as_public_dict(),
        },
        "shared_plain_env": "SHORT_CONNECT_PLAIN_FILE",
        "default_plain_cite": DEFAULT_PLAIN,  # path cite only; never contents
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    return out


def run_via_glue(
    *,
    prefer: str = "path_b",
    plain: Path = Path(DEFAULT_PLAIN),
    host: str = DEFAULT_CAG_HOST,
    heart_listen: float = 35.0,
    ticket_mode: str = "zeros",
    session_nudge: Optional[bool] = None,
    live: bool = False,
    out: Optional[Path] = None,
) -> Dict[str, Any]:
    """Dispatch to chosen plane. LIVE only for path_B when live=True.

    ICE LIVE remains env-gated inside short_connect (not auto-fired here).
    Never logs plain/-k contents.
    """
    route = choose_route(prefer=prefer)
    summary: Dict[str, Any] = {
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "freeze_cite": FREEZE_CITE,
        "route": route.as_public_dict(),
        "live_requested": bool(live),
        "plain_path_cite": str(plain),  # path only
        "ts": datetime.now().isoformat(timespec="seconds"),
    }

    if route.plane == ROUTE_ICE_SHORT:
        import short_connect_skeleton as sc

        if plain.exists():
            text = plain.read_text(encoding="utf-8", errors="replace")
            plan = sc.plan_from_plain_connectstr(text, env_override=True)
            summary["short_plan"] = plan.as_public_dict()
        else:
            summary["short_plan"] = sc.offline_selfcheck()
            summary["notes"] = ["plain missing → offline selfcheck plan only"]
        if live:
            # only TCP probe if env ready; never claim dual
            plan_obj = None
            if plain.exists():
                plan_obj = sc.plan_from_plain_connectstr(
                    plain.read_text(encoding="utf-8", errors="replace"),
                    env_override=True,
                )
            summary["live_tcp"] = sc.try_live_tcp(
                plan_obj or sc.plan_from_plain_connectstr(
                    sc._PUBLIC_PLAIN_FIXTURE, env_override=True  # type: ignore[attr-defined]
                )
            )
        summary["dispatched"] = "short_connect_skeleton"
        return summary

    # path_B
    import path_b_keepalive_package as pkg

    if not live:
        summary["dispatched"] = "path_b_keepalive_package"
        summary["offline"] = pkg.policy_selfcheck()
        return summary

    result = pkg.run_path_b_keepalive(
        host=host,
        plain=Path(plain),
        heart_listen=float(heart_listen),
        ticket_mode=str(ticket_mode),
        session_nudge=session_nudge,
        out=out,
    )
    summary["dispatched"] = "path_b_keepalive_package"
    summary["path_b_result"] = result
    # never promote
    summary["dual_evidence_ok"] = False
    summary["agent_dual_ok"] = False
    summary["production_claim"] = False
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="#26/#27 short_connect↔path_B glue (claim=false)"
    )
    ap.add_argument("--selfcheck", action="store_true", help="offline glue contract")
    ap.add_argument(
        "--prefer",
        choices=("path_b", "ice"),
        default="path_b",
        help="default path_b keepalive; ice = short_connect plane",
    )
    ap.add_argument(
        "--live",
        action="store_true",
        help="LIVE dispatch (path_B CAG or ICE TCP if env); claim=false",
    )
    ap.add_argument(
        "--plain",
        default=os.environ.get("SHORT_CONNECT_PLAIN_FILE", DEFAULT_PLAIN),
        help="plain connectStr path (never logged)",
    )
    ap.add_argument("--host", default=os.environ.get("CAG_HOST", DEFAULT_CAG_HOST))
    ap.add_argument("--heart-listen", type=float, default=35.0)
    ap.add_argument(
        "--ticket-mode",
        choices=("template", "zeros", "random"),
        default="zeros",
    )
    ap.add_argument(
        "--session-nudge",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    ap.add_argument("--out", default="")
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args(argv)

    if args.selfcheck or (not args.live and args.prefer == "path_b" and not args.out):
        # default offline
        if args.selfcheck or not args.live:
            out = glue_selfcheck()
            # also dry-run dispatch offline for default route
            dry = run_via_glue(prefer=args.prefer, plain=Path(args.plain), live=False)
            out["dry_dispatch"] = {
                "dispatched": dry.get("dispatched"),
                "route": dry.get("route"),
                "offline_selfcheck": (dry.get("offline") or {}).get("selfcheck"),
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))
            if args.json_out:
                args.json_out.write_text(
                    json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
                )
            return 0 if out.get("selfcheck") == "PASS" else 2

    out_path = Path(args.out) if args.out else None
    result = run_via_glue(
        prefer=args.prefer,
        plain=Path(args.plain),
        host=args.host,
        heart_listen=float(args.heart_listen),
        ticket_mode=str(args.ticket_mode),
        session_nudge=args.session_nudge,
        live=bool(args.live),
        out=out_path,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.json_out:
        text = json.dumps(result, indent=2, ensure_ascii=False)
        args.json_out.write_text(text, encoding="utf-8")
        result["json_out_sha16"] = hashlib.sha256(text.encode()).hexdigest()[:16]

    if not args.live:
        return 0
    # LIVE exit codes mirror package when path_B
    pb = result.get("path_b_result") or {}
    if pb.get("ok_heart_keepalive"):
        return 0
    if pb.get("ok_redq_s2c"):
        return 2
    if result.get("dispatched") == "short_connect_skeleton":
        tcp = result.get("live_tcp") or {}
        return 0 if tcp.get("tcp_ok") else 3
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
