#!/usr/bin/env python3
"""path_B: public-cloud CAG ZTEC → TLS → post-TLS REDQ (production_claim=false).

Evidence (T37 LIVE 2026-07-17):
  peer 36.212.224.105:8899 / .100:8899
  pre-TLS: ZTEC50 → ack50 → 220(auth) → ack36 → 116 → TLS1.3
  post-TLS: 108 (1a01+sport+hv6) → 0a01|0x00a3 → REDQ163(k||vmid)
            ← 0a01|0x0152 + REDQ342 (RSA**2048** SPKI; PKCS1 ct=256B)
               bit-identical to T14 — NOT classic SPICE RSA1024
  further: 0a01|0x80 + 128B ticket-slot (T14/T41 zeros OK) → multi S2C
           HARD_NEG: RSA2048 ct 256 ≠ wire slot 128 → classic RSA-ticket closed

PIN: public ecloud :9222 ONLY. Never jtydn/爱家.
Secrets: read from SHORT_CONNECT_PLAIN_FILE /env; never log -k.
"""
from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


def _sha16(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def parse_connect_plain(text: str) -> Dict[str, str]:
    parts = text.split()
    flags: Dict[str, str] = {}
    i = 0
    while i < len(parts):
        t = parts[i]
        if t.startswith("--"):
            key = t[2:]
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                flags[key] = parts[i + 1]
                i += 2
            else:
                flags[key] = "true"
                i += 1
        elif t.startswith("-") and len(t) == 2:
            key = t[1:]
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                flags[key] = parts[i + 1]
                i += 2
            else:
                flags[key] = "true"
                i += 1
        else:
            i += 1
    if "vmid" not in flags and "vm-id" not in flags:
        m = re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            text,
        )
        if m:
            flags["vmid"] = m.group(0)
    return flags


def recvn(sock: socket.socket, n: int, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def recvall(sock: socket.socket, timeout: float = 1.5, maxn: int = 1 << 16) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < maxn:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            sock.settimeout(0.4)
    except socket.timeout:
        pass
    return buf


def pack_0a01(payload: bytes) -> bytes:
    """Vendor post-TLS length prefix observed in T14/T37: 0a01 | u16le len | (payload separate or inline)."""
    return b"\x0a\x01" + struct.pack("<H", len(payload))


@dataclass
class PathBResult:
    host: str
    ok_ztec50: bool = False
    ok_auth220: bool = False
    ok_tls: bool = False
    ok_redq_s2c: bool = False
    ok_heart_keepalive: bool = False
    heart_count: int = 0
    hearts: List[dict] = field(default_factory=list)
    agent_hb_count: int = 0
    agent_hbs: List[dict] = field(default_factory=list)
    s2c_type_hist: Dict[str, int] = field(default_factory=dict)
    s2c_frame_count: int = 0
    s2c_non_heart_samples: List[dict] = field(default_factory=list)
    tls_version: str = ""
    s2c_redq_len: int = 0
    s2c_eq_t14: Optional[bool] = None
    stages: List[dict] = field(default_factory=list)
    error: str = ""
    production_claim: bool = False


def build_packets_from_templates(
    *,
    tmpl_pre: Path,
    tmpl_post: Path,
    hv6: str,
    vmid: str,
    k: str,
    port: int = 5100,
    sport: int = 60063,
) -> Dict[str, bytes]:
    ip6 = socket.inet_pton(socket.AF_INET6, hv6.split("%")[0])
    t50 = (tmpl_pre / "f20_C2S_50.bin").read_bytes()
    t220 = bytearray((tmpl_pre / "f23_C2S_220.bin").read_bytes())
    t116 = bytearray((tmpl_pre / "f26_C2S_116.bin").read_bytes())
    struct.pack_into("<I", t220, 0, port)
    t220[4:20] = ip6
    t220[20:56] = vmid.encode("ascii")
    t220[56:60] = b"\x00" * 4
    struct.pack_into("<I", t116, 8, sport)

    b108 = bytearray((tmpl_post / "block_00_C2S_108.bin").read_bytes())
    struct.pack_into("<H", b108, 4, sport & 0xFFFF)
    if len(b108) >= 28:
        b108[12:28] = ip6
    for off in range(0, len(b108) - 3):
        if struct.unpack_from("<I", b108, off)[0] == 60063:
            struct.pack_into("<I", b108, off, sport)

    b163 = bytearray((tmpl_post / "block_02_C2S_163.bin").read_bytes())
    m = re.search(
        rb"\d{8}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        bytes(b163),
    )
    if not m:
        raise ValueError("REDQ163 template missing k||vmid slot")
    new = (k + vmid).encode("ascii")
    if len(new) != 44:
        raise ValueError("k must be 8 digits and vmid 36 chars")
    b163[m.start() : m.start() + 44] = new

    return {
        "ztec50": t50,
        "auth220": bytes(t220),
        "c116": bytes(t116),
        "c108": bytes(b108),
        "hdr163": (tmpl_post / "block_01_C2S_4.bin").read_bytes(),
        "redq163": bytes(b163),
        "hdr128": (tmpl_post / "block_04_C2S_4.bin").read_bytes(),
        "ticket128": (tmpl_post / "block_05_C2S_128.bin").read_bytes(),
        "t14_s2c342": (tmpl_post / "block_03_S2C_342.bin").read_bytes(),
    }


def _peel_spice_types(buf: bytes) -> List[dict]:
    """Parse vendor 0a01 frames then SpiceDataHeader; return spice frame dicts."""
    try:
        from spice_frame_builder import parse_spice_frame  # type: ignore
    except Exception:
        from pathlib import Path as _P
        import sys as _sys

        _sys.path.insert(0, str(_P(__file__).resolve().parent))
        from spice_frame_builder import parse_spice_frame  # type: ignore

    found: List[dict] = []
    i = 0
    while i + 4 <= len(buf):
        if buf[i : i + 2] != b"\x0a\x01":
            j = buf.find(b"\x0a\x01", i + 1)
            if j < 0:
                break
            i = j
            continue
        plen = struct.unpack_from("<H", buf, i + 2)[0]
        pay = buf[i + 4 : i + 4 + plen]
        off = 0
        while off + 16 <= len(pay):
            fr = parse_spice_frame(pay, off)
            if not fr or fr.get("truncated"):
                break
            found.append(fr)
            off += 16 + int(fr["size"])
            if off >= len(pay):
                break
        i += 4 + plen
    return found


def path_b_connect(
    host: str,
    *,
    plain_file: Path,
    tmpl_pre: Path = Path("/tmp/t14_100"),
    tmpl_post: Path = Path("/tmp/t14_tls_plain"),
    cag_port: int = 8899,
    continue_channels: bool = True,
    heart_listen_s: float = 0.0,
    agent_hb_every: float = 0.0,
    agent_hb_serial: int = 100,
    ticket_mode: str = "zeros",  # T41 stock Write_if g_malloc0(128); classic RSA HARD_NEG
    extra_c2s_frames: Optional[List[bytes]] = None,
    session_nudge: bool = False,
    should_stop: Optional[Callable[[], bool]] = None,
) -> PathBResult:
    text = Path(plain_file).read_text()
    flags = parse_connect_plain(text)
    hv6 = flags.get("hv6") or flags.get("h")
    k = flags.get("k")
    vmid = flags.get("vmid") or flags.get("vm-id")
    port = int(flags.get("p") or flags.get("pv6") or 5100)
    sport = int(flags.get("proxy-sport") or flags.get("sport") or 60063)
    if not (hv6 and k and vmid):
        return PathBResult(host=host, error="missing hv6/k/vmid in plain")

    # ticket_mode: template|zeros|random — residual#26 A/B (claim=false)
    # T41: stock Write_if = g_malloc0(128) zeros ("ice ticket key"); not RSA ticket.
    # T40: RSA2048 SPKI ct=256 ≠ 128B slot; zeros+random both LIVE-channel.
    if ticket_mode not in ("template", "zeros", "random"):
        return PathBResult(host=host, error=f"bad ticket_mode={ticket_mode}")

    pkts = build_packets_from_templates(
        tmpl_pre=tmpl_pre, tmpl_post=tmpl_post, hv6=hv6, vmid=vmid, k=k, port=port, sport=sport
    )
    res = PathBResult(host=host)
    res.stages.append(
        {
            "meta": True,
            "k_sha16": _sha16(k),
            "vmid": vmid,
            "port": port,
            "sport": sport,
            "hv6_len": len(hv6),
        }
    )
    try:
        s = socket.create_connection((host, cag_port), timeout=5)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(pkts["ztec50"])
        ack50 = recvn(s, 50, 5)
        res.ok_ztec50 = len(ack50) == 50 and ack50.startswith(b"ZTEC")
        res.stages.append({"name": "ztec50", "recv": len(ack50), "ok": res.ok_ztec50})
        if not res.ok_ztec50:
            res.error = "ztec50_ack"
            s.close()
            return res

        s.sendall(pkts["auth220"])
        ack36 = recvn(s, 36, 5)
        res.ok_auth220 = len(ack36) == 36
        res.stages.append({"name": "auth220", "recv": len(ack36), "hex": ack36[:8].hex()})
        s.sendall(pkts["c116"])
        _ = recvall(s, 0.4)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(s, server_hostname=host)
        res.ok_tls = True
        res.tls_version = tls.version() or ""
        res.stages.append({"name": "tls", "ver": res.tls_version})

        tls.sendall(pkts["c108"])
        _ = recvall(tls, 0.5)
        tls.sendall(pkts["hdr163"])
        _ = recvall(tls, 0.3)
        tls.sendall(pkts["redq163"])
        s2c = recvall(tls, 2.0)
        res.ok_redq_s2c = b"REDQ" in s2c and len(s2c) >= 100
        res.s2c_redq_len = len(s2c)
        res.s2c_eq_t14 = s2c == pkts["t14_s2c342"] if s2c else None
        res.stages.append(
            {
                "name": "redq_s2c",
                "recv": len(s2c),
                "ok": res.ok_redq_s2c,
                "eq_t14": res.s2c_eq_t14,
                "head": s2c[:16].hex() if s2c else "",
            }
        )
        if continue_channels and res.ok_redq_s2c:
            if ticket_mode == "zeros":
                ticket_blob = b"\x00" * 128
            elif ticket_mode == "random":
                ticket_blob = os.urandom(128)
            else:
                ticket_blob = pkts["ticket128"]
            tls.sendall(pkts["hdr128"])
            tls.sendall(ticket_blob)
            rx = recvall(tls, 1.5)
            res.stages.append(
                {
                    "name": "after_ticket128",
                    "ticket_mode": ticket_mode,
                    "ticket_len": len(ticket_blob),
                    "ticket_all_zero": ticket_blob == b"\x00" * len(ticket_blob),
                    "ticket_sha16": hashlib.sha256(ticket_blob).hexdigest()[:16],
                    "recv": len(rx),
                    "head": rx[:24].hex() if rx else "",
                }
            )
            # T14 post-ticket: pairs of 0a01|u16le + Spice body (blocks >=9)
            blocks = sorted(
                [
                    p
                    for p in tmpl_post.glob("block_*_C2S_*.bin")
                    if int(p.name.split("_")[1]) >= 9
                ],
                key=lambda p: int(p.name.split("_")[1]),
            )
            bi = 0
            while bi < len(blocks):
                b = blocks[bi].read_bytes()
                if len(b) == 4 and b[:2] == b"\x0a\x01" and bi + 1 < len(blocks):
                    body = blocks[bi + 1].read_bytes()
                    name = blocks[bi].name + "+" + blocks[bi + 1].name
                    tls.sendall(b + body)
                    rx = recvall(tls, 0.9)
                    res.stages.append({"name": name, "sent": 4 + len(body), "recv": len(rx)})
                    bi += 2
                else:
                    tls.sendall(b)
                    rx = recvall(tls, 0.6)
                    res.stages.append({"name": blocks[bi].name, "sent": len(b), "recv": len(rx)})
                    bi += 1

            # T38-C LIVE: S2C HEART type=0x74 every ~12s; C2S ACK type=0x79
            # wrapped as vendor 0a01|u16le|frame (claim=false)
            # T39: optional C2S agent 0x6b/0x7d idle HB (residual23) interleaved
            if heart_listen_s and heart_listen_s > 0:
                try:
                    from spice_frame_builder import (  # type: ignore
                        TYPE_S53_HEART_REQ,
                        build_agent_heartbeat,
                        build_heart_ack,
                    )
                except Exception:
                    from pathlib import Path as _P
                    import sys as _sys

                    _sys.path.insert(0, str(_P(__file__).resolve().parent))
                    from spice_frame_builder import (  # type: ignore
                        TYPE_S53_HEART_REQ,
                        build_agent_heartbeat,
                        build_heart_ack,
                    )
                t0 = time.time()
                next_agent = t0
                agent_ser = int(agent_hb_serial)
                # T43: any C2S post-channel-up acts as nudge for S2C HEART (not agent dual).
                # T44: optional stock non-empty 0x6b frames (vd 0x6/0x8f/0x8c) for S2C dual probe.
                if session_nudge and not (agent_hb_every and agent_hb_every > 0):
                    try:
                        hb0 = build_agent_heartbeat(agent_ser)
                        wrapped0 = pack_0a01(hb0) + hb0
                        tls.sendall(wrapped0)
                        res.agent_hbs.append(
                            {
                                "t": 0.0,
                                "serial": agent_ser,
                                "len": len(wrapped0),
                                "type": "0x6b/0x7d",
                                "role": "session_nudge",
                            }
                        )
                        res.agent_hb_count = len(res.agent_hbs)
                        agent_ser += 1
                        next_agent = t0 + max(float(agent_hb_every or 0), 1e9)
                        res.stages.append(
                            {"name": "session_nudge", "ok": True, "len": len(wrapped0)}
                        )
                    except Exception as e:
                        res.stages.append(
                            {
                                "name": "session_nudge_err",
                                "err": f"{type(e).__name__}:{e}",
                            }
                        )
                if extra_c2s_frames:
                    sent_extra = 0
                    for i, frb in enumerate(extra_c2s_frames):
                        if not frb:
                            continue
                        try:
                            raw = bytes(frb)
                            wrapped = pack_0a01(raw) + raw
                            tls.sendall(wrapped)
                            sent_extra += 1
                            res.agent_hbs.append(
                                {
                                    "t": round(time.time() - t0, 2),
                                    "serial": None,
                                    "len": len(wrapped),
                                    "type": "extra_c2s",
                                    "idx": i,
                                    "head": raw[:16].hex(),
                                }
                            )
                            res.agent_hb_count = len(res.agent_hbs)
                        except Exception as e:
                            res.stages.append(
                                {
                                    "name": "extra_c2s_err",
                                    "idx": i,
                                    "err": f"{type(e).__name__}:{e}",
                                }
                            )
                            break
                    res.stages.append(
                        {
                            "name": "extra_c2s",
                            "count": sent_extra,
                            "ok": sent_extra > 0,
                        }
                    )
                # #75fixah/#75fixai: poll should_stop; abort must not look like mid-session drop
                while time.time() - t0 < float(heart_listen_s):
                    if should_stop is not None:
                        try:
                            if bool(should_stop()):
                                res.error = "aborted:should_stop"
                                res.stages.append(
                                    {
                                        "name": "heart_listen_aborted",
                                        "reason": "should_stop",
                                        "t": round(time.time() - t0, 2),
                                        "heart_count": res.heart_count,
                                        "production_claim": False,
                                    }
                                )
                                # force-close so recvall/handshake cannot hang the worker
                                try:
                                    tls.close()
                                except Exception:
                                    pass
                                break
                        except Exception:
                            pass
                    now = time.time()
                    if agent_hb_every and agent_hb_every > 0 and now >= next_agent:
                        hb = build_agent_heartbeat(agent_ser)
                        wrapped_hb = pack_0a01(hb) + hb
                        try:
                            tls.sendall(wrapped_hb)
                            res.agent_hbs.append(
                                {
                                    "t": round(now - t0, 2),
                                    "serial": agent_ser,
                                    "len": len(wrapped_hb),
                                    "type": "0x6b/0x7d",
                                }
                            )
                            res.agent_hb_count = len(res.agent_hbs)
                            agent_ser += 1
                        except Exception as e:
                            res.stages.append(
                                {
                                    "name": "agent_hb_send_err",
                                    "err": f"{type(e).__name__}:{e}",
                                }
                            )
                            break
                        next_agent = now + float(agent_hb_every)
                    chunk = recvall(tls, 1.5)
                    if not chunk:
                        continue
                    for fr in _peel_spice_types(chunk):
                        ty = fr.get("type")
                        if ty is None:
                            continue
                        try:
                            ty_i = int(ty)
                        except Exception:
                            continue
                        key = f"0x{ty_i:02x}"
                        res.s2c_type_hist[key] = res.s2c_type_hist.get(key, 0) + 1
                        res.s2c_frame_count += 1
                        if ty_i != TYPE_S53_HEART_REQ and len(res.s2c_non_heart_samples) < 16:
                            res.s2c_non_heart_samples.append(
                                {
                                    "t": round(time.time() - t0, 2),
                                    "type": key,
                                    "serial": fr.get("serial"),
                                    "size": fr.get("size"),
                                    "head": (fr.get("body") or b"")[:16].hex()
                                    if isinstance(fr.get("body"), (bytes, bytearray))
                                    else "",
                                }
                            )
                        if ty_i != TYPE_S53_HEART_REQ:
                            continue
                        serial = int(fr.get("serial") or 0)
                        ack = build_heart_ack(serial)
                        wrapped = pack_0a01(ack) + ack
                        tls.sendall(wrapped)
                        entry = {
                            "t": round(time.time() - t0, 2),
                            "serial": serial,
                            "ack_len": len(wrapped),
                            "rx_len": len(chunk),
                        }
                        res.hearts.append(entry)
                        res.heart_count = len(res.hearts)
                res.ok_heart_keepalive = res.heart_count >= 2
                res.stages.append(
                    {
                        "name": "heart_listen",
                        "s": float(heart_listen_s),
                        "heart_count": res.heart_count,
                        "agent_hb_count": res.agent_hb_count,
                        "agent_hb_every": float(agent_hb_every or 0),
                        "s2c_frame_count": res.s2c_frame_count,
                        "s2c_type_hist": dict(res.s2c_type_hist),
                        "ok": res.ok_heart_keepalive,
                    }
                )
        try:
            tls.close()
        except Exception:
            pass
    except Exception as e:
        res.error = f"{type(e).__name__}:{e}"
    return res


def main() -> int:
    import argparse
    import json
    from datetime import datetime

    ap = argparse.ArgumentParser(description="path_B CAG post-TLS REDQ+HEART LIVE (claim=false)")
    ap.add_argument("--host", default=os.environ.get("CAG_HOST", "36.212.224.105"))
    ap.add_argument("--plain", default=os.environ.get("SHORT_CONNECT_PLAIN_FILE", "/tmp/r26_t29_plain"))
    ap.add_argument("--pre", default="/tmp/t14_100")
    ap.add_argument("--post", default="/tmp/t14_tls_plain")
    ap.add_argument("--out", default="")
    ap.add_argument(
        "--heart-listen",
        type=float,
        default=0.0,
        help="seconds to listen for S2C 0x74 HEART and ACK 0x79 (vendor 0a01 wrap)",
    )
    ap.add_argument(
        "--agent-hb-every",
        type=float,
        default=0.0,
        help="seconds between C2S agent 0x6b/0x7d idle HB during heart-listen (0=off)",
    )
    ap.add_argument(
        "--agent-hb-serial",
        type=int,
        default=100,
        help="starting Spice serial for agent HB frames",
    )
    ap.add_argument(
        "--ticket-mode",
        choices=("template", "zeros", "random"),
        default="zeros",
        help="128B ticket-slot stock=zeros (Write_if g_malloc0); template|random A/B — RSA ct≠128, claim=false",
    )
    ap.add_argument(
        "--session-nudge",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="T43/T45: 1× C2S agent empty HB to nudge S2C HEART (not agent dual). "
        "Default ON when --heart-listen>0; use --no-session-nudge for pure-idle A/B",
    )
    ap.add_argument(
        "--extra-c2s",
        action="append",
        default=[],
        help="path to raw SpiceDataHeader frame(s) to C2S once at heart-listen start (T44 stock 0x6b)",
    )
    args = ap.parse_args()
    extra_frames: List[bytes] = []
    for p in args.extra_c2s or []:
        pb = Path(p)
        if pb.is_file():
            extra_frames.append(pb.read_bytes())
    heart_s = float(args.heart_listen or 0.0)
    # T45: agent S2C dual HARD_NEG; keepalive path defaults to 1× session nudge under heart-listen.
    if args.session_nudge is None:
        session_nudge = heart_s > 0.0
    else:
        session_nudge = bool(args.session_nudge)
    r = path_b_connect(
        args.host,
        plain_file=Path(args.plain),
        tmpl_pre=Path(args.pre),
        tmpl_post=Path(args.post),
        heart_listen_s=heart_s,
        agent_hb_every=float(args.agent_hb_every or 0.0),
        agent_hb_serial=int(args.agent_hb_serial),
        ticket_mode=str(args.ticket_mode),
        extra_c2s_frames=extra_frames or None,
        session_nudge=session_nudge,
    )
    out = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "production_claim": False,
        "host": r.host,
        "ok_ztec50": r.ok_ztec50,
        "ok_auth220": r.ok_auth220,
        "ok_tls": r.ok_tls,
        "ok_redq_s2c": r.ok_redq_s2c,
        "ok_heart_keepalive": r.ok_heart_keepalive,
        "heart_count": r.heart_count,
        "hearts": r.hearts,
        "agent_hb_count": r.agent_hb_count,
        "agent_hbs": r.agent_hbs,
        "s2c_frame_count": r.s2c_frame_count,
        "s2c_type_hist": r.s2c_type_hist,
        "s2c_non_heart_samples": r.s2c_non_heart_samples,
        "tls_version": r.tls_version,
        "s2c_redq_len": r.s2c_redq_len,
        "s2c_eq_t14": r.s2c_eq_t14,
        "stages": r.stages,
        "error": r.error,
    }
    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    if args.heart_listen and args.heart_listen > 0:
        return 0 if r.ok_heart_keepalive else 3
    return 0 if r.ok_redq_s2c else 2


if __name__ == "__main__":
    raise SystemExit(main())
