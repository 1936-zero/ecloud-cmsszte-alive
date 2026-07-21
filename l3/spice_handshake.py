#!/usr/bin/env python3
"""Pure-Python SPICE handshake + heartbeat + reconnect state machine (N5 / L-proto).

production_claim=false

Phases (offline-safe; no network, no vendor SDK):
  INIT → LINK_MESS → AUTH → CAPS_NEGOTIATE → HEARTBEAT → CLOSED
                     ↘ MissingKeyError (explainable) if key_provider lacks slot
  HEARTBEAT|AUTH|CAPS → DISCONNECTED → RECONNECT → LINK_MESS → ... (re-auth)

Integrates existing builders:
  - spice_pure_proto.pack_spice_link_mess / parse_spice_link_header
  - spice_frame_builder HEART / AGENT HB frames

N6 inject alignment (key_provider slots, no secret dump):
  - SLOT_TICKET (AUTH required by default)
  - SLOT_SESSION_KEY (optional session material after AUTH)
  - SLOT_PROP0X14 (optional vendor prop0x14; ≠ guest EncryptWithKey track)
  - SLOT_ZTEC_C2S (optional preamble length log only)

Does NOT claim production login or LIVE REDQ proof on CAG :8899.
"""
from __future__ import annotations

import enum
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

try:
    from .key_provider import (  # type: ignore
        SLOT_PROP0X14,
        SLOT_SESSION_KEY,
        SLOT_TICKET,
        SLOT_ZTEC_C2S,
        KeyProvider,
        MissingKeyError,
        NullKeyProvider,
        make_key_provider,
    )
    from .spice_frame_builder import (  # type: ignore
        TYPE_C49_HEART_ACK,
        TYPE_S53_HEART_REQ,
        build_agent_heartbeat,
        build_heart_ack,
        build_heart_req,
        parse_spice_frame,
    )
    from .spice_pure_proto import (  # type: ignore
        SPICE_CHANNEL_MAIN,
        SPICE_MAGIC,
        pack_spice_link_mess,
        parse_spice_link_header,
    )
except ImportError:  # script / sys.path=l3 mode
    from key_provider import (  # type: ignore
        SLOT_PROP0X14,
        SLOT_SESSION_KEY,
        SLOT_TICKET,
        SLOT_ZTEC_C2S,
        KeyProvider,
        MissingKeyError,
        NullKeyProvider,
        make_key_provider,
    )
    from spice_frame_builder import (  # type: ignore
        TYPE_C49_HEART_ACK,
        TYPE_S53_HEART_REQ,
        build_agent_heartbeat,
        build_heart_ack,
        build_heart_req,
        parse_spice_frame,
    )
    from spice_pure_proto import (  # type: ignore
        SPICE_CHANNEL_MAIN,
        SPICE_MAGIC,
        pack_spice_link_mess,
        parse_spice_link_header,
    )


class HandshakePhase(str, enum.Enum):
    INIT = "INIT"
    LINK_MESS = "LINK_MESS"
    AUTH = "AUTH"
    CAPS_NEGOTIATE = "CAPS_NEGOTIATE"
    HEARTBEAT = "HEARTBEAT"
    DISCONNECTED = "DISCONNECTED"
    RECONNECT = "RECONNECT"
    CLOSED = "CLOSED"
    FAILED = "FAILED"


@dataclass
class HandshakeConfig:
    """Offline / dry config. No host required for skeleton drive."""

    connection_id: int = 0
    channel_type: int = SPICE_CHANNEL_MAIN
    channel_id: int = 0
    # AUTH: which slot is required before leaving AUTH (ticket preferred).
    auth_required_slot: str = SLOT_TICKET
    # If True, AUTH may proceed without ticket (dry structural walk only).
    allow_auth_skip: bool = False
    # Heartbeat loop (offline inject). N5 deepen: default ≥3 cycles.
    max_heart_rounds: int = 3
    send_agent_hb: bool = True
    # Reconnect SM
    max_reconnects: int = 3
    # When True, after AUTH also record prop0x14 / session_key inject surface.
    bind_n6_slots: bool = True
    production_claim: bool = False  # MUST remain False for N5


@dataclass
class HandshakeEvent:
    ts: float
    phase: str
    action: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ts": self.ts,
            "phase": self.phase,
            "action": self.action,
            "detail": self.detail,
        }


@dataclass
class HandshakeResult:
    ok: bool
    phase: str
    events: List[HandshakeEvent] = field(default_factory=list)
    tx_frames: List[bytes] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    production_claim: bool = False

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "phase": self.phase,
            "events": [e.as_dict() for e in self.events],
            "tx_frame_count": len(self.tx_frames),
            "tx_frame_sha_prefix": [
                __import__("hashlib").sha256(f).hexdigest()[:16] for f in self.tx_frames[:8]
            ],
            "stats": self.stats,
            "error": self.error,
            "production_claim": False,  # hard pin
        }


class SpiceHandshakeSkeleton:
    """Connect / capability negotiate / heart / reconnect SM with key inject.

    Offline drive:
      sm = SpiceHandshakeSkeleton(key_provider=DictKeyProvider({...}))
      result = sm.run_offline()
      # or with mid-session disconnect simulation:
      result = sm.run_offline_with_reconnect(disconnect_after_hearts=1)
    """

    def __init__(
        self,
        key_provider: Optional[KeyProvider] = None,
        config: Optional[HandshakeConfig] = None,
    ) -> None:
        self.keys: KeyProvider = key_provider or NullKeyProvider()
        self.cfg = config or HandshakeConfig()
        if self.cfg.production_claim:
            raise ValueError("N5 forbids production_claim=True on skeleton")
        self.phase = HandshakePhase.INIT
        self.events: List[HandshakeEvent] = []
        self.tx: List[bytes] = []
        self._serial = 1
        self.stats: Dict[str, int] = {
            "link_mess_built": 0,
            "auth_ok": 0,
            "auth_missing_key": 0,
            "caps_ok": 0,
            "s53_seen": 0,
            "c49_sent": 0,
            "agent_hb_sent": 0,
            "disconnects": 0,
            "reconnects": 0,
            "session_key_bound": 0,
            "prop0x14_bound": 0,
            "heart_rounds_completed": 0,
        }
        self._n6_bind: Dict[str, Any] = {
            "session_key_len": 0,
            "prop0x14_len": 0,
            "session_key_present": False,
            "prop0x14_present": False,
        }

    # --- internal helpers -------------------------------------------------

    def _log(self, action: str, **detail: Any) -> None:
        self.events.append(
            HandshakeEvent(
                ts=time.time(),
                phase=self.phase.value,
                action=action,
                detail=detail,
            )
        )

    def _next_serial(self) -> int:
        s = self._serial
        self._serial += 1
        return s

    def _emit(self, frame: bytes, label: str) -> bytes:
        self.tx.append(frame)
        self._log("tx", label=label, nbytes=len(frame), serial_hint=self._serial - 1)
        return frame

    def _bind_n6_slots(self) -> Dict[str, Any]:
        """Align with N6 key_provider surface (length-only; no secret dump)."""
        info: Dict[str, Any] = {
            "session_key_present": False,
            "session_key_len": 0,
            "prop0x14_present": False,
            "prop0x14_len": 0,
            "n6_align": True,
        }
        if not self.cfg.bind_n6_slots:
            info["n6_align"] = False
            return info
        sk = self.keys.get(SLOT_SESSION_KEY)
        if sk is not None:
            info["session_key_present"] = True
            info["session_key_len"] = len(sk)
            self.stats["session_key_bound"] += 1
        p14 = self.keys.get(SLOT_PROP0X14)
        if p14 is not None:
            info["prop0x14_present"] = True
            info["prop0x14_len"] = len(p14)
            self.stats["prop0x14_bound"] += 1
        self._n6_bind = {
            "session_key_len": info["session_key_len"],
            "prop0x14_len": info["prop0x14_len"],
            "session_key_present": info["session_key_present"],
            "prop0x14_present": info["prop0x14_present"],
        }
        self._log("n6_slot_bind", **info)
        return info

    # --- phases -----------------------------------------------------------

    def step_init(self) -> None:
        if self.phase not in (HandshakePhase.INIT, HandshakePhase.RECONNECT):
            raise RuntimeError(f"step_init from {self.phase}")
        inv = self.keys.describe()
        self._log("init", key_inventory=inv, from_reconnect=(self.phase == HandshakePhase.RECONNECT))
        self.phase = HandshakePhase.LINK_MESS

    def step_link_mess(self) -> bytes:
        if self.phase != HandshakePhase.LINK_MESS:
            raise RuntimeError(f"step_link_mess from {self.phase}")
        # Optional ZTEC preamble is *not* required for classic REDQ skeleton;
        # if present we record length only (no secret dump).
        ztec = self.keys.get(SLOT_ZTEC_C2S)
        if ztec is not None:
            self._log("ztec_preamble_present", len=len(ztec))
        mess = pack_spice_link_mess(
            connection_id=self.cfg.connection_id,
            channel_type=self.cfg.channel_type,
            channel_id=self.cfg.channel_id,
        )
        assert mess.startswith(SPICE_MAGIC)
        parsed = parse_spice_link_header(mess)
        assert parsed and not parsed.get("truncated")
        self.stats["link_mess_built"] += 1
        self._emit(mess, "SpiceLinkMess")
        self._log("link_mess_ok", major=parsed["major"], minor=parsed["minor"])
        self.phase = HandshakePhase.AUTH
        return mess

    def step_auth(self) -> bytes:
        """Consume ticket (or configured slot) via key_provider.

        Missing key → MissingKeyError with stage=AUTH (explainable).
        After success, optionally bind N6 slots (session_key / prop0x14).
        """
        if self.phase != HandshakePhase.AUTH:
            raise RuntimeError(f"step_auth from {self.phase}")
        slot = self.cfg.auth_required_slot
        if self.cfg.allow_auth_skip and not self.keys.has(slot):
            self._log(
                "auth_skipped",
                slot=slot,
                note="allow_auth_skip=True; structural dry only",
            )
            self.stats["auth_ok"] += 1
            self._bind_n6_slots()
            self.phase = HandshakePhase.CAPS_NEGOTIATE
            return b""
        try:
            material = self.keys.require(slot, stage="AUTH")
        except MissingKeyError:
            self.stats["auth_missing_key"] += 1
            self.phase = HandshakePhase.FAILED
            self._log("auth_missing_key", slot=slot)
            raise
        # Skeleton: do not invent RSA/link-encrypt; bind opaque token frame id.
        # Future residual26 may wrap material; here we only prove inject path.
        token_frame = (
            b"AUTH_TOKEN_SKELETON\x00"
            + len(material).to_bytes(4, "little")
            + material[:64]  # cap in tx log path; full len tracked in stats
        )
        self.stats["auth_ok"] += 1
        self._emit(token_frame, f"auth_token[{slot}]")
        # N6 align: session_key + prop0x14 inject surface (length only)
        self._bind_n6_slots()
        self.phase = HandshakePhase.CAPS_NEGOTIATE
        return token_frame

    def step_caps(self) -> Dict[str, Any]:
        """Capability negotiate placeholder (client→server caps list empty)."""
        if self.phase != HandshakePhase.CAPS_NEGOTIATE:
            raise RuntimeError(f"step_caps from {self.phase}")
        caps = {
            "common_caps": [],
            "channel_caps": [],
            "channel_type": self.cfg.channel_type,
            "note": "skeleton empty caps; LIVE caps TBD from capture",
            "n6_bind": dict(self._n6_bind),
        }
        self.stats["caps_ok"] += 1
        self._log("caps_negotiate", **{k: v for k, v in caps.items() if k != "note"})
        self.phase = HandshakePhase.HEARTBEAT
        return caps

    def step_heartbeat_round(self, s53_frame: Optional[bytes] = None) -> List[bytes]:
        """One heart round: optional S53 inject → C49 ack + optional agent HB."""
        if self.phase != HandshakePhase.HEARTBEAT:
            raise RuntimeError(f"step_heartbeat from {self.phase}")
        out: List[bytes] = []
        if s53_frame is None:
            s53_frame = build_heart_req(self._next_serial(), pad_to=0)
        parsed = parse_spice_frame(s53_frame)
        if not parsed or parsed["type"] != TYPE_S53_HEART_REQ:
            raise ValueError(f"expected S53 type 0x74, got {parsed}")
        self.stats["s53_seen"] += 1
        self._log("rx_s53", serial=parsed["serial"])
        c49 = build_heart_ack(self._next_serial(), 0x00)
        assert parse_spice_frame(c49)["type"] == TYPE_C49_HEART_ACK
        self._emit(c49, "C49_HEART_ACK")
        self.stats["c49_sent"] += 1
        out.append(c49)
        if self.cfg.send_agent_hb:
            hb = build_agent_heartbeat(self._next_serial())
            self._emit(hb, "AGENT_HB_0x7d")
            self.stats["agent_hb_sent"] += 1
            out.append(hb)
        self.stats["heart_rounds_completed"] += 1
        return out

    def step_close(self) -> None:
        if self.phase in (HandshakePhase.CLOSED, HandshakePhase.FAILED):
            return
        self._log("close")
        self.phase = HandshakePhase.CLOSED

    # --- reconnect state machine ------------------------------------------

    def simulate_disconnect(self, reason: str = "offline_sim") -> None:
        """Mid-session disconnect (offline). Moves to DISCONNECTED."""
        if self.phase in (HandshakePhase.CLOSED, HandshakePhase.FAILED, HandshakePhase.INIT):
            raise RuntimeError(f"simulate_disconnect from {self.phase}")
        prev = self.phase.value
        self.phase = HandshakePhase.DISCONNECTED
        self.stats["disconnects"] += 1
        self._log("disconnect", reason=reason, from_phase=prev)

    def step_reconnect(self) -> None:
        """DISCONNECTED → RECONNECT; clears serial soft-state for re-link.

        Does NOT clear events/tx/stats (accumulate for audit).
        """
        if self.phase != HandshakePhase.DISCONNECTED:
            raise RuntimeError(f"step_reconnect from {self.phase}")
        if self.stats["reconnects"] >= self.cfg.max_reconnects:
            self.phase = HandshakePhase.FAILED
            self._log("reconnect_exhausted", max=self.cfg.max_reconnects)
            raise RuntimeError(f"max_reconnects={self.cfg.max_reconnects} exhausted")
        self.stats["reconnects"] += 1
        self.phase = HandshakePhase.RECONNECT
        self._log(
            "reconnect_begin",
            attempt=self.stats["reconnects"],
            max=self.cfg.max_reconnects,
        )
        # soft reset of serial for new link sequence (keep cumulative stats)
        self._serial = 1

    def run_handshake_once(
        self,
        *,
        heart_rounds: Optional[int] = None,
        inject_s53: bool = True,
    ) -> None:
        """Drive INIT/RECONNECT → HEARTBEAT (without close). Raises on error."""
        rounds = self.cfg.max_heart_rounds if heart_rounds is None else heart_rounds
        self.step_init()
        self.step_link_mess()
        self.step_auth()
        self.step_caps()
        for _ in range(max(0, rounds)):
            self.step_heartbeat_round(
                build_heart_req(self._next_serial(), pad_to=0) if inject_s53 else None
            )

    # --- full offline run -------------------------------------------------

    def run_offline(
        self,
        *,
        heart_rounds: Optional[int] = None,
        inject_s53: bool = True,
    ) -> HandshakeResult:
        """Drive full skeleton without sockets. Failures are structured."""
        try:
            self.run_handshake_once(heart_rounds=heart_rounds, inject_s53=inject_s53)
            self.step_close()
            return HandshakeResult(
                ok=True,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                production_claim=False,
            )
        except MissingKeyError as e:
            return HandshakeResult(
                ok=False,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                error=e.as_dict(),
                production_claim=False,
            )
        except Exception as e:  # noqa: BLE001 — skeleton surfaces any error
            self.phase = HandshakePhase.FAILED
            self._log("exception", type=type(e).__name__, msg=str(e))
            return HandshakeResult(
                ok=False,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                error={
                    "error": type(e).__name__,
                    "msg": str(e),
                    "production_claim": False,
                },
                production_claim=False,
            )

    def run_offline_with_reconnect(
        self,
        *,
        disconnect_after_hearts: int = 1,
        hearts_before: Optional[int] = None,
        hearts_after: Optional[int] = None,
        inject_s53: bool = True,
        reason: str = "offline_sim_drop",
    ) -> HandshakeResult:
        """Offline multi-cycle path with mid-HB disconnect → reconnect → ≥3 HB total.

        Flow:
          handshakes once with `hearts_before` rounds
          → simulate_disconnect
          → step_reconnect
          → re-handshake with `hearts_after` rounds
          → close

        Default ensures total heart rounds ≥ 3 when cfg.max_heart_rounds≥3.
        """
        before = (
            disconnect_after_hearts
            if hearts_before is None
            else hearts_before
        )
        after = (
            max(1, self.cfg.max_heart_rounds - before)
            if hearts_after is None
            else hearts_after
        )
        # Guarantee ≥3 total cycles for N5 deepen accept when defaults used.
        total = before + after
        if total < 3:
            after = 3 - before
        try:
            self.run_handshake_once(heart_rounds=before, inject_s53=inject_s53)
            self.simulate_disconnect(reason=reason)
            self.step_reconnect()
            self.run_handshake_once(heart_rounds=after, inject_s53=inject_s53)
            self.step_close()
            return HandshakeResult(
                ok=True,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                production_claim=False,
            )
        except MissingKeyError as e:
            return HandshakeResult(
                ok=False,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                error=e.as_dict(),
                production_claim=False,
            )
        except Exception as e:  # noqa: BLE001
            if self.phase != HandshakePhase.FAILED:
                self.phase = HandshakePhase.FAILED
            self._log("exception", type=type(e).__name__, msg=str(e))
            return HandshakeResult(
                ok=False,
                phase=self.phase.value,
                events=list(self.events),
                tx_frames=list(self.tx),
                stats=dict(self.stats),
                error={
                    "error": type(e).__name__,
                    "msg": str(e),
                    "production_claim": False,
                },
                production_claim=False,
            )


def selftest() -> None:
    # 1) missing key → explainable failure
    r = SpiceHandshakeSkeleton(NullKeyProvider()).run_offline()
    assert r.ok is False and r.error and r.error["error"] == "MissingKeyError"
    assert r.error["slot"] == SLOT_TICKET
    assert r.production_claim is False
    assert r.stats["auth_missing_key"] == 1

    # 2) with fixture ticket → green path ≥3 hearts
    try:
        from .key_provider import DictKeyProvider  # type: ignore
    except ImportError:
        from key_provider import DictKeyProvider  # type: ignore

    kp = DictKeyProvider(
        {
            SLOT_TICKET: b"\xab\xcd" * 8,
            SLOT_SESSION_KEY: b"\x00" * 16,
            SLOT_PROP0X14: b"\x14" * 8,
        }
    )
    sm = SpiceHandshakeSkeleton(kp, HandshakeConfig(max_heart_rounds=3))
    r2 = sm.run_offline()
    assert r2.ok, r2.as_dict()
    assert r2.phase == HandshakePhase.CLOSED.value
    assert r2.stats["link_mess_built"] == 1
    assert r2.stats["c49_sent"] == 3
    assert r2.stats["agent_hb_sent"] == 3
    assert r2.stats["heart_rounds_completed"] == 3
    assert r2.stats["session_key_bound"] == 1
    assert r2.stats["prop0x14_bound"] == 1
    assert r2.production_claim is False
    d = r2.as_dict()
    assert d["production_claim"] is False

    # 3) auth skip dry
    sm3 = SpiceHandshakeSkeleton(
        NullKeyProvider(),
        HandshakeConfig(allow_auth_skip=True, max_heart_rounds=1, send_agent_hb=False),
    )
    r3 = sm3.run_offline()
    assert r3.ok and r3.stats["c49_sent"] == 1 and r3.stats["agent_hb_sent"] == 0

    # 4) reconnect offline: disconnect mid-HB → re-auth → total ≥3 hearts
    sm4 = SpiceHandshakeSkeleton(
        DictKeyProvider(
            {
                SLOT_TICKET: b"\x11" * 16,
                SLOT_SESSION_KEY: b"\x22" * 16,
                SLOT_PROP0X14: b"\x33" * 4,
            }
        ),
        HandshakeConfig(max_heart_rounds=3),
    )
    r4 = sm4.run_offline_with_reconnect(disconnect_after_hearts=1)
    assert r4.ok, r4.as_dict()
    assert r4.stats["disconnects"] == 1
    assert r4.stats["reconnects"] == 1
    assert r4.stats["link_mess_built"] == 2  # initial + reconnect
    assert r4.stats["auth_ok"] == 2
    assert r4.stats["heart_rounds_completed"] >= 3
    assert r4.stats["c49_sent"] >= 3
    assert r4.stats["session_key_bound"] == 2
    assert r4.stats["prop0x14_bound"] == 2
    actions = [e.action for e in r4.events]
    assert "disconnect" in actions
    assert "reconnect_begin" in actions
    assert "n6_slot_bind" in actions

    print("spice_handshake selftest OK")
    print(
        json.dumps(
            {
                "missing": r.as_dict()["error"],
                "ok_stats": r2.stats,
                "reconnect_stats": r4.stats,
            },
            ensure_ascii=False,
        )
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="N5 SPICE handshake skeleton (offline)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--allow-auth-skip", action="store_true")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--reconnect", action="store_true", help="run offline with reconnect sim")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.selftest:
        selftest()
        return 0
    cfg = HandshakeConfig(max_heart_rounds=args.rounds, allow_auth_skip=args.allow_auth_skip)
    sm = SpiceHandshakeSkeleton(make_key_provider(None), cfg)
    if args.reconnect:
        r = sm.run_offline_with_reconnect()
    else:
        r = sm.run_offline()
    print(json.dumps(r.as_dict(), ensure_ascii=False, indent=2))
    return 0 if r.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
