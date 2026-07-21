#!/usr/bin/env python3
"""Pure-Python TCP(+TLS) link for SPICE/ZTEC plane — no vendor SDK.

production_claim=false

Design:
  - Optional raw ZTEC bytes can be written first (vendor CAG :8899).
  - Then stdlib ssl.wrap_socket / SSLContext for TLS1.2.
  - Main-channel SPICE frames built by spice_frame_builder / spice_pure_proto.
  - Does NOT embed passwords, tickets, or PEM material.

Live residual26 will feed: host, port, server_name, optional ztec_c2s blob,
and later RSA ticket ciphertext when reverse closes REDQ/link auth.
"""
from __future__ import annotations

import select
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from spice_pure_proto import (  # type: ignore
    is_tls_record_prefix,
    parse_spice_frame,
    parse_ztec_preamble,
    strip_ztec_prefix,
)


@dataclass
class LinkConfig:
    host: str
    port: int = 8899
    server_hostname: Optional[str] = None  # SNI / verify name; None → host
    connect_timeout_s: float = 10.0
    io_timeout_s: float = 30.0
    # Vendor ZTEC: if set, written once before TLS handshake (bytes as-is).
    ztec_c2s_preamble: Optional[bytes] = None
    # TLS
    use_tls: bool = True
    tls_min: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    tls_max: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    # verify: default CERT_NONE for lab residual (CAG often private CA).
    # Callers may inject custom cafile via ssl_context override later.
    insecure_skip_verify: bool = True
    alpn_protocols: Optional[List[str]] = None


@dataclass
class LinkStats:
    bytes_sent: int = 0
    bytes_recv: int = 0
    frames_parsed: int = 0
    ztec_seen_s2c: bool = False
    tls_established: bool = False
    err: Optional[str] = None


class SpicePureLink:
    """Minimal duplex link with buffer for SPICE headers after TLS."""

    def __init__(self, cfg: LinkConfig):
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None
        self._rx = bytearray()
        self.stats = LinkStats()
        self._serial = 1

    @property
    def next_serial(self) -> int:
        s = self._serial
        self._serial += 1
        return s

    def connect(self) -> None:
        cfg = self.cfg
        raw = socket.create_connection(
            (cfg.host, cfg.port), timeout=cfg.connect_timeout_s
        )
        raw.settimeout(cfg.io_timeout_s)
        self.sock = raw

        # Optional ZTEC C2S before TLS (evidence: tunnel on :8899)
        if cfg.ztec_c2s_preamble:
            if not cfg.ztec_c2s_preamble.startswith(b"ZTEC"):
                raise ValueError("ztec_c2s_preamble must start with b'ZTEC'")
            self.sock.sendall(cfg.ztec_c2s_preamble)
            self.stats.bytes_sent += len(cfg.ztec_c2s_preamble)
            # Read optional S2C ZTEC (best-effort short wait)
            self._recv_some(timeout=2.0, into_buffer=True)
            if self._rx.startswith(b"ZTEC"):
                self.stats.ztec_seen_s2c = True
                z, rest = strip_ztec_prefix(bytes(self._rx))
                if z is not None and rest is not None:
                    # if peel consumed a full sample, keep remainder only
                    if rest != bytes(self._rx):
                        self._rx = bytearray(rest)

        if cfg.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = cfg.tls_min
            ctx.maximum_version = cfg.tls_max
            if cfg.insecure_skip_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if cfg.alpn_protocols:
                try:
                    ctx.set_alpn_protocols(cfg.alpn_protocols)
                except Exception:
                    pass
            server_hostname = cfg.server_hostname or cfg.host
            # When skip verify, server_hostname still used for SNI
            self.sock = ctx.wrap_socket(
                self.sock,
                server_hostname=server_hostname if cfg.server_hostname or not cfg.insecure_skip_verify else None,
            )
            self.stats.tls_established = True

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_raw(self, data: bytes) -> None:
        if not self.sock:
            raise RuntimeError("not connected")
        self.sock.sendall(data)
        self.stats.bytes_sent += len(data)

    def _recv_some(self, timeout: float = 1.0, into_buffer: bool = True) -> bytes:
        if not self.sock:
            return b""
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return b""
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            return b""
        except ssl.SSLWantReadError:
            return b""
        if not chunk:
            return b""
        self.stats.bytes_recv += len(chunk)
        if into_buffer:
            self._rx.extend(chunk)
        return chunk

    def recv_into_buffer(self, timeout: float = 1.0) -> int:
        c = self._recv_some(timeout=timeout, into_buffer=True)
        return len(c)

    def drain_spice_frames(self, max_frames: int = 32) -> List[dict]:
        """Parse as many complete SpiceDataHeader frames as possible from _rx."""
        out: List[dict] = []
        while len(out) < max_frames:
            if len(self._rx) < 16:
                break
            # size is u16 at offset 10
            _serial, typ, size, sub = struct.unpack_from("<QHHI", self._rx, 0)
            need = 16 + size
            if len(self._rx) < need:
                break
            frame = bytes(self._rx[:need])
            del self._rx[:need]
            parsed = parse_spice_frame(frame, 0)
            if parsed:
                out.append(parsed)
                self.stats.frames_parsed += 1
            else:
                break
        return out

    def __enter__(self) -> "SpicePureLink":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def selftest() -> None:
    """Offline only: config + parse path without network."""
    cfg = LinkConfig(host="127.0.0.1", port=1, use_tls=False)
    link = SpicePureLink(cfg)
    # inject synthetic HEART-sized frame into buffer
    from spice_frame_builder import build_heart_req  # type: ignore

    fr = build_heart_req(1, pad_to=0)  # 16+1=17
    link._rx.extend(fr)
    frames = link.drain_spice_frames()
    assert len(frames) == 1 and frames[0]["type"] == 0x74, frames
    # ZTEC parse on empty
    assert parse_ztec_preamble(b"nope") is None
    assert is_tls_record_prefix(bytes.fromhex("170303000100"))
    print("spice_pure_link selftest OK (offline)")
    print("  drained type", hex(frames[0]["type"]), "size", frames[0]["size"])


if __name__ == "__main__":
    selftest()
