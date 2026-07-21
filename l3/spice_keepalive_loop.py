#!/usr/bin/env python3
"""Pure-Python SPICE keepalive loop (N7) on N5 handshake skeleton.

production_claim=false

Offline-safe:
  - reconnect with exponential backoff
  - heartbeat rounds via SpiceHandshakeSkeleton (default ≥3; N5#292 align)
  - key inject via KeyProvider (no vendor SDK path)
  - N6 slot surface: SLOT_SESSION_KEY / SLOT_PROP0X14 (bind_n6_slots=True)
  - residual26 hooks (ticket/session_key refresh) as optional callables

Does NOT claim production login or LIVE CAG keepalive.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

try:
    from .key_provider import (  # type: ignore
        SLOT_PROP0X14,
        SLOT_SESSION_KEY,
        SLOT_TICKET,
        DictKeyProvider,
        KeyProvider,
        MissingKeyError,
        NullKeyProvider,
        make_key_provider,
    )
    from .spice_handshake import (  # type: ignore
        HandshakeConfig,
        HandshakeResult,
        SpiceHandshakeSkeleton,
    )
except ImportError:  # script / sys.path=l3 mode
    from key_provider import (  # type: ignore
        SLOT_PROP0X14,
        SLOT_SESSION_KEY,
        SLOT_TICKET,
        DictKeyProvider,
        KeyProvider,
        MissingKeyError,
        NullKeyProvider,
        make_key_provider,
    )
    from spice_handshake import (  # type: ignore
        HandshakeConfig,
        HandshakeResult,
        SpiceHandshakeSkeleton,
    )


# residual26 extension points (callers may inject; never auto-load native libs)
Residual26Hook = Callable[[KeyProvider, Dict[str, Any]], None]


@dataclass
class KeepaliveConfig:
    """Offline / dry keepalive loop config. No host required for N7 green path."""

    # session / heart — N5#292 deepen: default ≥3 cycles
    max_heart_rounds: int = 3
    send_agent_hb: bool = True
    allow_auth_skip: bool = False
    # N6 inject alignment surface (length-only; no secret dump)
    bind_n6_slots: bool = True
    # reconnect / backoff
    max_attempts: int = 3
    max_success_sessions: int = 1  # stop after N green sessions (offline)
    backoff_base_s: float = 0.01  # tiny for offline tests; LIVE would be larger
    backoff_max_s: float = 0.08
    backoff_factor: float = 2.0
    # simulation: which attempt indices fail before heart (1-based); empty = none
    simulate_fail_attempts: Sequence[int] = field(default_factory=tuple)
    # if True, sleep real time during backoff (tests usually False)
    real_sleep: bool = False
    production_claim: bool = False  # MUST remain False for N7


@dataclass
class AttemptRecord:
    attempt: int
    ok: bool
    phase: str
    backoff_s: float
    stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None

    def as_dict(self) -> dict:
        return {
            "attempt": self.attempt,
            "ok": self.ok,
            "phase": self.phase,
            "backoff_s": self.backoff_s,
            "stats": self.stats,
            "error": self.error,
        }


@dataclass
class KeepaliveResult:
    ok: bool
    attempts: List[AttemptRecord] = field(default_factory=list)
    sessions_ok: int = 0
    total_c49: int = 0
    total_agent_hb: int = 0
    total_s53: int = 0
    total_session_key_bound: int = 0
    total_prop0x14_bound: int = 0
    total_backoff_s: float = 0.0
    residual26_hooks_fired: int = 0
    last_n6_bind: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    production_claim: bool = False

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "sessions_ok": self.sessions_ok,
            "attempts": [a.as_dict() for a in self.attempts],
            "stats": {
                "total_c49": self.total_c49,
                "total_agent_hb": self.total_agent_hb,
                "total_s53": self.total_s53,
                "total_session_key_bound": self.total_session_key_bound,
                "total_prop0x14_bound": self.total_prop0x14_bound,
                "total_backoff_s": round(self.total_backoff_s, 6),
                "attempts": len(self.attempts),
                "residual26_hooks_fired": self.residual26_hooks_fired,
                "last_n6_bind": self.last_n6_bind,
            },
            "error": self.error,
            "production_claim": False,  # hard pin
        }


class SpiceKeepaliveLoop:
    """Reconnect / backoff / heartbeat loop on N5 SpiceHandshakeSkeleton.

    Offline drive:
      loop = SpiceKeepaliveLoop(DictKeyProvider({SLOT_TICKET: b"..."}))
      result = loop.run_offline()
    """

    def __init__(
        self,
        key_provider: Optional[KeyProvider] = None,
        config: Optional[KeepaliveConfig] = None,
        residual26_hooks: Optional[Sequence[Residual26Hook]] = None,
    ) -> None:
        self.keys: KeyProvider = key_provider or NullKeyProvider()
        self.cfg = config or KeepaliveConfig()
        if self.cfg.production_claim:
            raise ValueError("N7 forbids production_claim=True")
        self.residual26_hooks: List[Residual26Hook] = list(residual26_hooks or [])
        self._hooks_fired = 0

    def _backoff_for(self, fail_index: int) -> float:
        """Exponential backoff after fail_index consecutive failures (0-based)."""
        b = self.cfg.backoff_base_s * (self.cfg.backoff_factor ** fail_index)
        return min(b, self.cfg.backoff_max_s)

    def _run_residual26_hooks(self, ctx: Dict[str, Any]) -> None:
        for hook in self.residual26_hooks:
            hook(self.keys, dict(ctx))
            self._hooks_fired += 1

    def _one_session(self, attempt: int, force_fail: bool = False) -> HandshakeResult:
        """One offline handshake+heart session via N5 skeleton.

        force_fail: inject SimulatedDisconnect before/at handshake (reconnect test).
        """
        if force_fail:
            return HandshakeResult(
                ok=False,
                phase="FAILED",
                error={"error": "SimulatedDisconnect", "attempt": attempt},
                production_claim=False,
            )
        # Missing key is explainable and stops early (no thrash)
        if self.keys.get(SLOT_TICKET) is None:
            return HandshakeResult(
                ok=False,
                phase="FAILED",
                error={
                    "error": "MissingKeyError",
                    "slot": SLOT_TICKET,
                    "attempt": attempt,
                },
                production_claim=False,
            )

        hs_cfg = HandshakeConfig(
            max_heart_rounds=self.cfg.max_heart_rounds,
            send_agent_hb=self.cfg.send_agent_hb,
            allow_auth_skip=self.cfg.allow_auth_skip,
            bind_n6_slots=self.cfg.bind_n6_slots,
            production_claim=False,
        )
        # residual26 hook: refresh/derive inject surface before handshake
        self._run_residual26_hooks(
            {"stage": "pre_handshake", "attempt": attempt, "production_claim": False}
        )
        sm = SpiceHandshakeSkeleton(self.keys, hs_cfg)
        return sm.run_offline()

    def run_offline(self) -> KeepaliveResult:
        """Drive reconnect/backoff/heartbeat offline. No network, no SDK."""
        attempts: List[AttemptRecord] = []
        sessions_ok = 0
        total_c49 = 0
        total_agent_hb = 0
        total_s53 = 0
        total_sk = 0
        total_p14 = 0
        total_backoff = 0.0
        consecutive_fails = 0
        last_error: Optional[Dict[str, Any]] = None
        last_n6: Optional[Dict[str, Any]] = None
        fail_set = set(int(x) for x in self.cfg.simulate_fail_attempts)

        for n in range(1, self.cfg.max_attempts + 1):
            force_fail = n in fail_set
            hr = self._one_session(attempt=n, force_fail=force_fail)
            backoff_s = 0.0
            if hr.ok:
                sessions_ok += 1
                consecutive_fails = 0
                total_c49 += int(hr.stats.get("c49_sent", 0))
                total_agent_hb += int(hr.stats.get("agent_hb_sent", 0))
                total_s53 += int(hr.stats.get("s53_seen", 0))
                total_sk += int(hr.stats.get("session_key_bound", 0))
                total_p14 += int(hr.stats.get("prop0x14_bound", 0))
                # N5 puts n6_bind only inside caps event; stats has bound counters.
                # Synthesize length-only surface (no secret dump) for loop audit.
                n6 = hr.stats.get("n6_bind")
                if isinstance(n6, dict):
                    last_n6 = dict(n6)
                elif self.cfg.bind_n6_slots:
                    sk = self.keys.get(SLOT_SESSION_KEY)
                    p14 = self.keys.get(SLOT_PROP0X14)
                    last_n6 = {
                        "session_key_present": sk is not None,
                        "session_key_len": len(sk) if sk is not None else 0,
                        "prop0x14_present": p14 is not None,
                        "prop0x14_len": len(p14) if p14 is not None else 0,
                        "session_key_bound": int(hr.stats.get("session_key_bound", 0)),
                        "prop0x14_bound": int(hr.stats.get("prop0x14_bound", 0)),
                    }
            else:
                consecutive_fails += 1
                last_error = hr.error
                # backoff before next attempt (if any remaining)
                if n < self.cfg.max_attempts and sessions_ok < self.cfg.max_success_sessions:
                    backoff_s = self._backoff_for(consecutive_fails - 1)
                    total_backoff += backoff_s
                    if self.cfg.real_sleep and backoff_s > 0:
                        time.sleep(backoff_s)

            attempts.append(
                AttemptRecord(
                    attempt=n,
                    ok=hr.ok,
                    phase=hr.phase,
                    backoff_s=backoff_s,
                    stats=dict(hr.stats or {}),
                    error=hr.error,
                )
            )
            if sessions_ok >= self.cfg.max_success_sessions:
                break
            # hard stop on missing key (not a transient disconnect)
            if hr.error and hr.error.get("error") == "MissingKeyError":
                break

        ok = sessions_ok >= self.cfg.max_success_sessions
        return KeepaliveResult(
            ok=ok,
            attempts=attempts,
            sessions_ok=sessions_ok,
            total_c49=total_c49,
            total_agent_hb=total_agent_hb,
            total_s53=total_s53,
            total_session_key_bound=total_sk,
            total_prop0x14_bound=total_p14,
            total_backoff_s=total_backoff,
            residual26_hooks_fired=self._hooks_fired,
            last_n6_bind=last_n6,
            error=None if ok else last_error,
            production_claim=False,
        )


def selftest() -> None:
    # 1) missing key → explainable, no infinite retry waste
    r = SpiceKeepaliveLoop(NullKeyProvider(), KeepaliveConfig(max_attempts=3)).run_offline()
    assert r.ok is False
    assert r.sessions_ok == 0
    assert len(r.attempts) == 1  # MissingKeyError stops early
    assert r.attempts[0].error and r.attempts[0].error["error"] == "MissingKeyError"
    assert r.production_claim is False
    assert r.as_dict()["production_claim"] is False

    # 2) green single session — default ≥3 hearts + N6 slots
    kp = DictKeyProvider(
        {
            SLOT_TICKET: b"\xab\xcd" * 8,
            SLOT_SESSION_KEY: b"\x00" * 16,
            SLOT_PROP0X14: b"\x14" * 8,
        }
    )
    r2 = SpiceKeepaliveLoop(
        kp,
        KeepaliveConfig(max_attempts=2, max_success_sessions=1),  # default max_heart_rounds=3
    ).run_offline()
    assert r2.ok, r2.as_dict()
    assert r2.sessions_ok == 1
    assert r2.total_c49 == 3, r2.total_c49
    assert r2.total_agent_hb == 3, r2.total_agent_hb
    assert r2.total_s53 == 3, r2.total_s53
    assert r2.total_session_key_bound == 1
    assert r2.total_prop0x14_bound == 1
    assert r2.last_n6_bind and r2.last_n6_bind.get("session_key_present") is True
    assert r2.last_n6_bind.get("prop0x14_present") is True
    assert r2.production_claim is False

    # 3) reconnect + backoff after simulated disconnect then green
    r3 = SpiceKeepaliveLoop(
        kp,
        KeepaliveConfig(
            max_attempts=4,
            max_success_sessions=1,
            max_heart_rounds=1,
            send_agent_hb=False,
            simulate_fail_attempts=(1, 2),
            backoff_base_s=0.01,
            backoff_factor=2.0,
            backoff_max_s=0.1,
            real_sleep=False,
        ),
    ).run_offline()
    assert r3.ok, r3.as_dict()
    assert r3.sessions_ok == 1
    assert len(r3.attempts) == 3  # fail, fail, ok
    assert r3.attempts[0].ok is False and r3.attempts[1].ok is False
    assert r3.attempts[2].ok is True
    # backoff after fail1=0.01, fail2=0.02
    assert abs(r3.total_backoff_s - 0.03) < 1e-9, r3.total_backoff_s
    assert r3.attempts[0].backoff_s == 0.01
    assert r3.attempts[1].backoff_s == 0.02
    assert r3.attempts[2].backoff_s == 0.0

    # 4) residual26 hook fires pre_handshake
    fired: List[str] = []

    def _hook(keys: KeyProvider, ctx: Dict[str, Any]) -> None:
        fired.append(ctx.get("stage", ""))
        # inject is already present; hook only proves surface
        assert keys.get(SLOT_TICKET) is not None

    r4 = SpiceKeepaliveLoop(
        kp,
        KeepaliveConfig(max_attempts=1, max_heart_rounds=1, send_agent_hb=False),
        residual26_hooks=[_hook],
    ).run_offline()
    assert r4.ok and r4.residual26_hooks_fired == 1
    assert fired == ["pre_handshake"]

    # 5) no native-lib / vendor-client import path in source
    import pathlib
    import re

    src_txt = pathlib.Path(__file__).read_text(encoding="utf-8")
    # build ban tokens without embedding full vendor/native load strings in module body
    bans = [
        "ctypes" + "." + "CDLL",
        "cdll" + "." + "LoadLibrary",
        "spice-client" + "-glib",
    ]
    for ban in bans:
        assert ban not in src_txt, ban
    assert re.search(r"^\s*(import|from)\s+\S*" + "uSmart", src_txt, re.M) is None

    # 6) default config heart rounds ≥ 3 (N5 align)
    assert KeepaliveConfig().max_heart_rounds >= 3
    assert KeepaliveConfig().bind_n6_slots is True

    print("spice_keepalive_loop selftest OK")
    print(
        json.dumps(
            {
                "missing_stop": r.as_dict()["stats"],
                "green": r2.as_dict()["stats"],
                "reconnect": r3.as_dict()["stats"],
                "hooks": r4.residual26_hooks_fired,
            },
            ensure_ascii=False,
        )
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="N7 pure-Python keepalive loop (offline)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--allow-auth-skip", action="store_true")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--heart-rounds", type=int, default=3)
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.selftest:
        selftest()
        return 0
    cfg = KeepaliveConfig(
        max_attempts=args.attempts,
        max_heart_rounds=args.heart_rounds,
        allow_auth_skip=args.allow_auth_skip,
    )
    r = SpiceKeepaliveLoop(make_key_provider(None), cfg).run_offline()
    print(json.dumps(r.as_dict(), ensure_ascii=False, indent=2))
    return 0 if r.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
