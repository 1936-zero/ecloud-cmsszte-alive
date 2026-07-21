#!/usr/bin/env python3
"""#27 pure-Python short-connect skeleton (public ICE path).

production_claim=false · PIN public-B :9222 only · 禁 jtydn / 爱家

Evidence pins (T29/T32/T33):
  - Peer: --hv6 + --pv6/-p (T29 LIVE ICE has_minus_h=false, port 5100)
  - Session: connectStr -k digits → k_to_prop0x14 → prop0x14 8B UTF-8
  - Guest --guest-passwd = EncryptWithKey SEPARATE (NOT link auth)
  - FREEZE cite a46d55cd523da9fd · public head k cite 91723341

This module:
  - OFFLINE: build peer+sk8+KeyProvider from redacted/public fixtures (default)
  - LIVE optional: only if SHORT_CONNECT_HOST + SHORT_CONNECT_PORT set and
    --live flag; still production_claim=false; never embeds secrets

Does NOT claim dual_evidence_ok or production keepalive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

from connectstr_k_session import (  # noqa: E402
    FREEZE_CITE,
    PUBLIC_HEAD_K_DIGITS,
    SOURCE_CLASS,
    assert_tracks_separated,
    k_to_prop0x14,
    parse_connectstr_k,
    residual_ticket_boundary,
)
from key_provider import (  # noqa: E402
    SLOT_PROP0X14,
    SLOT_SESSION_KEY,
    DictKeyProvider,
    make_key_provider,
)

PRODUCTION_CLAIM = False
DEFAULT_ICE_PORT = 5100
# Public-head-only fixture (already in reports; not a secret mint)
_PUBLIC_PLAIN_FIXTURE = (
    f"-p {DEFAULT_ICE_PORT} -k {PUBLIC_HEAD_K_DIGITS} -f --vmid fixture "
    f"--type ice --hv6 ::1 --pv6 {DEFAULT_ICE_PORT}"
)


@dataclass
class PeerMaterial:
    """Redacted-safe peer bind for short-connect."""

    host: str
    port: int
    path: str  # "ice_hv6" | "ipv4_h" | "env_override" | "missing"
    has_hv6: bool = False
    has_minus_h: bool = False


@dataclass
class SessionMaterial:
    k_present: bool
    k_len: int
    k_class: str  # "digits8" | "other" | "missing"
    prop0x14: bytes
    prop0x14_sha16: str
    source: str = SOURCE_CLASS


@dataclass
class ShortConnectPlan:
    """What a #27 run would use — no secrets dumped beyond sha16/public head."""

    production_claim: bool = PRODUCTION_CLAIM
    freeze_cite: str = FREEZE_CITE
    peer: Optional[PeerMaterial] = None
    session: Optional[SessionMaterial] = None
    use_guest_passwd_for_link: bool = False  # always False (T33)
    notes: list = field(default_factory=list)
    ready_offline: bool = False
    ready_live_env: bool = False

    def as_public_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "production_claim": self.production_claim,
            "freeze_cite": self.freeze_cite,
            "use_guest_passwd_for_link": self.use_guest_passwd_for_link,
            "ready_offline": self.ready_offline,
            "ready_live_env": self.ready_live_env,
            "notes": list(self.notes),
        }
        if self.peer:
            d["peer"] = asdict(self.peer)
        if self.session:
            d["session"] = {
                "k_present": self.session.k_present,
                "k_len": self.session.k_len,
                "k_class": self.session.k_class,
                "prop0x14_len": len(self.session.prop0x14),
                "prop0x14_sha16": self.session.prop0x14_sha16,
                "source": self.session.source,
                # never dump raw prop0x14 unless public-head fixture and --dump-public-head
            }
        return d


def _sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def _k_class(k: Optional[str]) -> str:
    if not k:
        return "missing"
    if k.isdigit() and len(k) == 8:
        return "digits8"
    return "other"


def extract_peer(fields: Dict[str, str], *, env_override: bool = True) -> PeerMaterial:
    """T29 ICE preference: hv6 first; fallback -h; optional env override."""
    if env_override:
        eh = os.environ.get("SHORT_CONNECT_HOST", "").strip()
        ep = os.environ.get("SHORT_CONNECT_PORT", "").strip()
        if eh and ep:
            return PeerMaterial(
                host=eh, port=int(ep), path="env_override",
                has_hv6="hv6" in eh or ":" in eh,
                has_minus_h=False,
            )
    hv6 = fields.get("host_v6") or fields.get("hv6")
    h = fields.get("host")
    pv6 = fields.get("port") or fields.get("host")  # port key from -p
    # parse_connectstr_k maps --pv6? check: only -p is "port". T29 also --pv6.
    # Our flag table has -p → port; --pv6 not in _FLAG_SPECS — add soft find.
    port_s = fields.get("port") or str(DEFAULT_ICE_PORT)
    try:
        port = int(port_s)
    except ValueError:
        port = DEFAULT_ICE_PORT

    if hv6:
        return PeerMaterial(
            host=hv6, port=port, path="ice_hv6", has_hv6=True, has_minus_h=False
        )
    if h:
        return PeerMaterial(
            host=h, port=port, path="ipv4_h", has_hv6=False, has_minus_h=True
        )
    return PeerMaterial(host="", port=port, path="missing", has_hv6=False, has_minus_h=False)


def build_session(k_value: Optional[str]) -> SessionMaterial:
    if not k_value:
        empty = b"\x00" * 8
        return SessionMaterial(
            k_present=False, k_len=0, k_class="missing",
            prop0x14=empty, prop0x14_sha16=_sha16(empty),
        )
    sk = k_to_prop0x14(k_value)
    return SessionMaterial(
        k_present=True,
        k_len=len(k_value),
        k_class=_k_class(k_value),
        prop0x14=sk,
        prop0x14_sha16=_sha16(sk),
    )


def plan_from_plain_connectstr(
    plain: str,
    *,
    env_override: bool = True,
    ewk_product_hex: str = "",
) -> ShortConnectPlan:
    """Build short-connect plan from post-AesDecode connectStr plain."""
    parsed = parse_connectstr_k(plain)
    peer = extract_peer(parsed.fields, env_override=env_override)
    sess = build_session(parsed.k_value)
    plan = ShortConnectPlan(peer=peer, session=sess)
    plan.notes.append("link_auth=prop0x14_from_-k (NOT guest EncryptWithKey)")
    plan.notes.append("T33: --guest-passwd is client-derived EWK product; skip for short link")
    if ewk_product_hex and parsed.k_value:
        assert_tracks_separated(parsed.k_value, ewk_product_hex)
        plan.notes.append("assert_tracks_separated OK")
    # residual ticket boundary (offline)
    rb = residual_ticket_boundary(
        ticket_raw=None, k_value=parsed.k_value, session_8b=sess.prop0x14
    )
    plan.notes.append(f"residual_ticket_boundary_ok={rb.get('ok', rb)}")

    plan.ready_offline = bool(
        sess.k_present and sess.k_class == "digits8" and peer.path != "missing"
    )
    # LIVE env readiness: host/port from env OR non-fixture peer
    live_h = os.environ.get("SHORT_CONNECT_HOST", "").strip()
    live_p = os.environ.get("SHORT_CONNECT_PORT", "").strip()
    plan.ready_live_env = bool(live_h and live_p and sess.k_present)
    if peer.host in ("::1", "127.0.0.1", "localhost", ""):
        plan.notes.append("peer is fixture/loopback — offline only unless SHORT_CONNECT_* set")
    return plan


def make_provider_from_plan(plan: ShortConnectPlan):
    """Inject prop0x14 (+ alias session_key) — never EWK guest product."""
    if not plan.session or not plan.session.k_present:
        raise RuntimeError("no session material; refuse Null live auth")
    sk = plan.session.prop0x14
    return DictKeyProvider(
        {
            SLOT_PROP0X14: sk,
            SLOT_SESSION_KEY: sk,  # same 8B for residual handshake slot
        }
    )


def offline_selfcheck() -> Dict[str, Any]:
    """Deterministic selftest with public-head fixture. Exit-ready."""
    plan = plan_from_plain_connectstr(_PUBLIC_PLAIN_FIXTURE, env_override=False)
    assert plan.session is not None
    assert plan.peer is not None
    assert plan.session.k_class == "digits8"
    assert plan.session.prop0x14 == PUBLIC_HEAD_K_DIGITS.encode("utf-8")
    assert plan.peer.path == "ice_hv6"
    assert plan.peer.port == DEFAULT_ICE_PORT
    assert plan.use_guest_passwd_for_link is False
    # refuse EWK substitution
    assert_tracks_separated(PUBLIC_HEAD_K_DIGITS, "deadbeefcafebabe00")
    provider = make_provider_from_plan(plan)
    assert provider.get(SLOT_PROP0X14) == plan.session.prop0x14
    # optional handshake dry import (class name may vary)
    handshake_ok = False
    try:
        import spice_handshake as _sh  # type: ignore

        cls = (
            getattr(_sh, "SpiceHandshakeSkeleton", None)
            or getattr(_sh, "SpiceHandshake", None)
            or getattr(_sh, "HandshakeStateMachine", None)
        )
        if cls is not None:
            hs = cls(key_provider=provider)
            handshake_ok = hasattr(hs, "phase") or hasattr(hs, "state")
        else:
            handshake_ok = hasattr(_sh, "HandshakePhase")
            plan.notes.append(
                "handshake_module_ok_no_ctor="
                + ",".join(n for n in dir(_sh) if "Hand" in n or "State" in n)[:120]
            )
    except Exception as e:  # offline tolerate missing glue
        handshake_ok = False
        plan.notes.append(f"handshake_import_note={type(e).__name__}:{e}")

    out = plan.as_public_dict()
    out["selfcheck"] = "PASS"
    out["public_head_k_cite"] = PUBLIC_HEAD_K_DIGITS
    out["prop0x14_matches_public_head"] = True
    out["handshake_dry_import"] = handshake_ok
    out["dual_evidence_ok"] = False  # never flip here
    return out


def try_live_tcp(plan: ShortConnectPlan, *, timeout_s: float = 5.0) -> Dict[str, Any]:
    """Best-effort TCP(+optional TLS) probe — production_claim=false.

    Requires SHORT_CONNECT_HOST/PORT. Does not send secrets beyond link material
    when handshake wired; default only checks TCP reachability.
    """
    import socket

    if not plan.ready_live_env and not (
        plan.peer and plan.peer.path == "env_override"
    ):
        # re-extract with env
        live_h = os.environ.get("SHORT_CONNECT_HOST", "").strip()
        live_p = os.environ.get("SHORT_CONNECT_PORT", "").strip()
        if not (live_h and live_p):
            return {
                "live": False,
                "reason": "SHORT_CONNECT_HOST/PORT not set",
                "production_claim": False,
            }
        host, port = live_h, int(live_p)
    else:
        assert plan.peer
        host, port = plan.peer.host, plan.peer.port

    result: Dict[str, Any] = {
        "live": True,
        "host_redacted": host[:3] + "…" if len(host) > 6 else "(short)",
        "port": port,
        "tcp_ok": False,
        "production_claim": False,
        "dual_evidence_ok": False,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            result["tcp_ok"] = True
            result["peername_family"] = s.family
    except OSError as e:
        result["error"] = f"{type(e).__name__}:{e}"
    return result


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="#27 short-connect skeleton (claim=false)")
    ap.add_argument("--selfcheck", action="store_true", help="offline public-head selftest")
    ap.add_argument("--plain-file", type=Path, help="post-AesDecode plain connectStr file")
    ap.add_argument("--live-tcp", action="store_true", help="TCP probe if SHORT_CONNECT_* set")
    ap.add_argument("--json-out", type=Path, help="write public plan json")
    args = ap.parse_args(argv)

    if args.selfcheck or (not args.plain_file and not args.live_tcp):
        out = offline_selfcheck()
        print(json.dumps(out, indent=2, ensure_ascii=False))
        if args.json_out:
            args.json_out.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return 0 if out.get("selfcheck") == "PASS" else 2

    plain = args.plain_file.read_text(encoding="utf-8", errors="replace")
    plan = plan_from_plain_connectstr(plain, env_override=True)
    out = plan.as_public_dict()
    if args.live_tcp:
        out["live_tcp"] = try_live_tcp(plan)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.json_out:
        args.json_out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
