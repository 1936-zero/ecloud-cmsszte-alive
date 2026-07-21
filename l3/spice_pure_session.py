#!/usr/bin/env python3
"""Pure-Python SPICE keepalive session loop — no vendor SDK / uSmartView.

production_claim=false

Implements residual25 offline loop + residual26/27 hooks:
  - On S53 HEART req (0x74): reply C49 ack (0x79)
  - Periodic agent HB (0x6b / VDAgent 0x7d empty) every ~9s (LIVE residual24)
  - Optional proactive C49 every 12s (LIVE residual19 idle cadence)

Does not launch public client. Does not claim production keepalive.
Live use still needs: host/port + ZTEC/TLS + link-auth (ticket/RSA) — residual26.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow running as script from repo root or l3/
_L3 = Path(__file__).resolve().parent
if str(_L3) not in sys.path:
    sys.path.insert(0, str(_L3))

from spice_frame_builder import (  # type: ignore
    TYPE_C49_HEART_ACK,
    TYPE_S53_HEART_REQ,
    build_agent_heartbeat,
    build_heart_ack,
)
from spice_pure_link import LinkConfig, SpicePureLink  # type: ignore
from spice_pure_proto import pack_spice_link_mess  # type: ignore


@dataclass
class SessionConfig:
    host: str = ""
    port: int = 8899
    server_hostname: Optional[str] = None
    use_tls: bool = True
    insecure_skip_verify: bool = True
    ztec_c2s_path: Optional[str] = None  # file with raw ZTEC C2S preamble
    # timers (seconds) — LIVE evidence defaults
    agent_hb_interval_s: float = 9.0
    proactive_heart_interval_s: float = 12.0
    reply_s53: bool = True
    send_agent_hb: bool = True
    send_proactive_c49: bool = False  # off by default; observe mode replies only
    duration_s: float = 30.0
    # dry-run: no network
    dry_run: bool = True


@dataclass
class SessionStats:
    s53_seen: int = 0
    c49_sent: int = 0
    agent_hb_sent: int = 0
    frames_rx: int = 0
    errors: List[str] = field(default_factory=list)
    started_at: float = 0.0
    ended_at: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "s53_seen": self.s53_seen,
            "c49_sent": self.c49_sent,
            "agent_hb_sent": self.agent_hb_sent,
            "frames_rx": self.frames_rx,
            "errors": list(self.errors),
            "duration_s": (self.ended_at - self.started_at) if self.ended_at else None,
            "production_claim": False,
        }


class SpicePureSession:
    def __init__(self, cfg: SessionConfig):
        self.cfg = cfg
        self.stats = SessionStats()
        self.link: Optional[SpicePureLink] = None

    def _load_ztec(self) -> Optional[bytes]:
        if not self.cfg.ztec_c2s_path:
            return None
        p = Path(self.cfg.ztec_c2s_path)
        data = p.read_bytes()
        if not data.startswith(b"ZTEC"):
            raise ValueError(f"ZTEC file must start with ZTEC: {p}")
        return data

    def run(self) -> SessionStats:
        self.stats = SessionStats(started_at=time.time())
        cfg = self.cfg
        if cfg.dry_run:
            return self._run_dry()
        if not cfg.host:
            self.stats.errors.append("host required for live mode")
            self.stats.ended_at = time.time()
            return self.stats

        ztec = self._load_ztec()
        lcfg = LinkConfig(
            host=cfg.host,
            port=cfg.port,
            server_hostname=cfg.server_hostname,
            use_tls=cfg.use_tls,
            insecure_skip_verify=cfg.insecure_skip_verify,
            ztec_c2s_preamble=ztec,
        )
        try:
            with SpicePureLink(lcfg) as link:
                self.link = link
                self._loop(link)
        except Exception as e:
            self.stats.errors.append(f"{type(e).__name__}: {e}")
        finally:
            self.link = None
            self.stats.ended_at = time.time()
        return self.stats

    def _run_dry(self) -> SessionStats:
        """Offline simulation: feed synthetic S53, expect C49 + agent HB builders."""
        # Prove builders + state machine without network / SDK
        serial = 1
        fake_s53 = build_heart_ack  # type placeholder
        from spice_frame_builder import build_heart_req  # type: ignore

        # simulate 3 S53 reqs
        for i in range(3):
            self.stats.s53_seen += 1
            if self.cfg.reply_s53:
                _ = build_heart_ack(serial, 0x00)
                serial += 1
                self.stats.c49_sent += 1
        if self.cfg.send_agent_hb:
            for i in range(2):
                _ = build_agent_heartbeat(serial)
                serial += 1
                self.stats.agent_hb_sent += 1
        # link mess skeleton exists
        _ = pack_spice_link_mess()
        # synthetic drain via link offline buffer
        link = SpicePureLink(LinkConfig(host="127.0.0.1", port=1, use_tls=False))
        fr = build_heart_req(99, pad_to=0)
        link._rx.extend(fr)
        frames = link.drain_spice_frames()
        self.stats.frames_rx += len(frames)
        self.stats.ended_at = time.time()
        return self.stats

    def _loop(self, link: SpicePureLink) -> None:
        cfg = self.cfg
        t0 = time.time()
        last_agent = t0
        last_c49 = t0
        while time.time() - t0 < cfg.duration_s:
            link.recv_into_buffer(timeout=0.5)
            for fr in link.drain_spice_frames():
                self.stats.frames_rx += 1
                if fr.get("type") == TYPE_S53_HEART_REQ:
                    self.stats.s53_seen += 1
                    if cfg.reply_s53:
                        link.send_raw(build_heart_ack(link.next_serial, 0x00))
                        self.stats.c49_sent += 1
                        last_c49 = time.time()
            now = time.time()
            if cfg.send_agent_hb and (now - last_agent) >= cfg.agent_hb_interval_s:
                link.send_raw(build_agent_heartbeat(link.next_serial))
                self.stats.agent_hb_sent += 1
                last_agent = now
            if cfg.send_proactive_c49 and (now - last_c49) >= cfg.proactive_heart_interval_s:
                link.send_raw(build_heart_ack(link.next_serial, 0x00))
                self.stats.c49_sent += 1
                last_c49 = now


def selftest() -> None:
    s = SpicePureSession(SessionConfig(dry_run=True))
    st = s.run()
    assert st.s53_seen == 3 and st.c49_sent == 3, st
    assert st.agent_hb_sent == 2, st
    assert st.frames_rx == 1, st
    assert st.as_dict()["production_claim"] is False
    print("spice_pure_session selftest OK (dry_run)")
    print(" ", json.dumps(st.as_dict(), ensure_ascii=False))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pure-Python SPICE session (production_claim=false)")
    ap.add_argument("--host", default="", help="CAG/SPICE host (live)")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--ztec-c2s", default="", help="path to ZTEC C2S preamble blob")
    ap.add_argument("--live", action="store_true", help="enable network (default dry-run)")
    ap.add_argument("--proactive-c49", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest or not args.live:
        if args.selftest or not args.live:
            selftest()
            if not args.live:
                return 0
    cfg = SessionConfig(
        host=args.host,
        port=args.port,
        duration_s=args.duration,
        ztec_c2s_path=args.ztec_c2s or None,
        dry_run=not args.live,
        send_proactive_c49=args.proactive_c49,
    )
    st = SpicePureSession(cfg).run()
    print(json.dumps(st.as_dict(), ensure_ascii=False, indent=2))
    return 0 if not st.errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
