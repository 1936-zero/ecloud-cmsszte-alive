#!/usr/bin/env python3
"""Sticky ZTEC pre-TLS gateway heart (0a000000) using LIVE auth220 as-is.

Does NOT rebuild auth220 from plain (path_b build_packets overwrites port/hv6/vmid).
Does NOT claim production / dual-oracle desktopStatus.

Usage:
  python3 l3/gw_ztec_heart_keepalive.py --pre /tmp/live_pretls_20260719_0332 \
      --host 36.138.129.86 --interval 3 --rounds 0 --report /tmp/gw_heart.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import time
from pathlib import Path


def recvn(s: socket.socket, n: int, t: float = 5.0) -> bytes:
    s.settimeout(t)
    out = b""
    try:
        while len(out) < n:
            c = s.recv(n - len(out))
            if not c:
                break
            out += c
    except socket.timeout:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Sticky ZTEC gateway 0a000000 heart (claim=false)")
    ap.add_argument("--pre", required=True, help="dir with f20_C2S_50.bin + f23_C2S_220.bin (sticky)")
    ap.add_argument("--host", default="36.138.129.86")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--interval", type=float, default=3.0, help="heart interval seconds (GUI~1.08; <=5 stable)")
    ap.add_argument("--rounds", type=int, default=0, help="0=unlimited")
    ap.add_argument("--report", default="")
    ap.add_argument("--c116", action="store_true", help="also send f26_C2S_116.bin if present (optional)")
    args = ap.parse_args()

    pre = Path(args.pre)
    c50 = (pre / "f20_C2S_50.bin").read_bytes()
    a220 = (pre / "f23_C2S_220.bin").read_bytes()
    if len(c50) != 50 or len(a220) != 220:
        raise SystemExit(f"bad sticky pre sizes: 50={len(c50)} 220={len(a220)}")

    meta = {
        "host": args.host,
        "port": args.port,
        "interval": args.interval,
        "auth220_sha16": hashlib.sha256(a220).hexdigest()[:16],
        "ztec50_sha16": hashlib.sha256(c50).hexdigest()[:16],
        "production_claim": False,
        "dual_evidence_ok": False,
        "layer": "preTLS_ZTEC_gateway_0a000000_NOT_spice_0x74",
        "ok": 0,
        "fail": 0,
        "events": [],
    }

    s = socket.create_connection((args.host, args.port), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(c50)
    ack50 = recvn(s, 50, 3)
    if not (len(ack50) == 50 and ack50.startswith(b"ZTEC")):
        meta["error"] = "ztec50_ack"
        meta["ack50_n"] = len(ack50)
        print(json.dumps(meta, ensure_ascii=False))
        return 2
    s.sendall(a220)
    ack36 = recvn(s, 36, 3)
    if len(ack36) != 36:
        meta["error"] = "auth220_ack36_timeout"
        meta["ack36_n"] = len(ack36)
        print(json.dumps(meta, ensure_ascii=False))
        return 3
    meta["ack36_hex16"] = ack36[:16].hex()
    if args.c116:
        p116 = pre / "f26_C2S_116.bin"
        if p116.exists():
            s.sendall(p116.read_bytes())
            _ = recvn(s, 64, 0.4)

    print(
        f"[gw-heart] auth ok host={args.host} sha16={meta['auth220_sha16']} "
        f"interval={args.interval} claim=false",
        flush=True,
    )
    i = 0
    t0 = time.time()
    try:
        while True:
            if args.rounds and i >= args.rounds:
                break
            ti = time.time()
            try:
                s.sendall(b"\x0a\x00\x00\x00")
                rh = recvn(s, 4, max(3.0, args.interval + 2))
                if rh != b"\x0a\x00\x00\x00":
                    meta["fail"] += 1
                    meta["events"].append(
                        {"i": i, "ok": False, "hex": rh.hex() if rh else "", "t": round(time.time() - t0, 2)}
                    )
                    meta["error"] = "heart_mismatch_or_eof"
                    break
                meta["ok"] += 1
                if i % 20 == 0:
                    meta["events"].append(
                        {"i": i, "ok": True, "rtt_ms": int((time.time() - ti) * 1000), "t": round(time.time() - t0, 2)}
                    )
                    print(f"[gw-heart] i={i} ok={meta['ok']} rtt={int((time.time()-ti)*1000)}ms", flush=True)
            except Exception as e:
                meta["fail"] += 1
                meta["error"] = f"{type(e).__name__}:{e}"
                meta["events"].append({"i": i, "err": meta["error"], "t": round(time.time() - t0, 2)})
                break
            rem = args.interval - (time.time() - ti)
            if rem > 0:
                time.sleep(rem)
            i += 1
    finally:
        try:
            s.close()
        except Exception:
            pass
        meta["duration_s"] = round(time.time() - t0, 2)
        meta["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        if args.report:
            Path(args.report).write_text(json.dumps(meta, indent=2, ensure_ascii=False))
            print(f"[gw-heart] wrote {args.report}", flush=True)
        print(json.dumps({k: meta[k] for k in meta if k != "events"}, ensure_ascii=False), flush=True)
    return 0 if meta["fail"] == 0 and meta["ok"] > 0 else 4


if __name__ == "__main__":
    raise SystemExit(main())
