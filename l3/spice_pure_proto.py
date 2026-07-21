#!/usr/bin/env python3
"""Pure-Python SPICE / ZTEC wire helpers (no SDK, no uSmartView).

Evidence anchors (production_claim=false):
  - SpiceDataHeader 16B LE — residual20–24 / spice_frame_builder.py
  - HEART 0x74/0x79 — LIVE C49/S53 dual-evidence
  - AGENT_DATA 0x6b + VDAgent BE type 0x7d empty HB — residual23/24
  - ZTEC tunnel magic before TLS on CAG :8899 —
    reports/A_RESIDUAL_STATUS_20260715.md + captures/ztec_preamble_samples/

This module is offline-safe: pack/parse only. Live connect lives in
spice_pure_link.py / spice_pure_session.py and still requires host/ticket.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

# Re-export main-channel builders (single source of truth for frames).
from spice_frame_builder import (  # type: ignore
    HEART_WIRE_PAD,
    MSGC_MAIN_AGENT_DATA,
    MSGC_MAIN_AGENT_START,
    SPICE_DATA_HDR,
    TYPE_C49_HEART_ACK,
    TYPE_MSG_MAIN_VM_REBOOT,
    TYPE_S53_HEART_REQ,
    VD_AGENT_HEARTBEAT,
    VD_AGENT_PROTOCOL,
    VM_REBOOT_MAGIC_LOGOUT,
    VM_REBOOT_MAGIC_OBS_T42,
    VM_REBOOT_MAGIC_QUIT,
    VM_REBOOT_MAGIC_UI_ICE,
    build_agent_data,
    build_agent_heartbeat,
    build_heart_ack,
    build_heart_req,
    pack_spice_header,
    pack_vd_agent_message,
    parse_spice_frame,
)

# ---------------------------------------------------------------------------
# Open-source SPICE link constants (RFC-ish / spice-protocol)
# REDQ magic not observed in encrypted AppData pcaps; kept for link-phase
# skeleton only — do not claim LIVE REDQ until cleartext capture proves it.
# ---------------------------------------------------------------------------
SPICE_MAGIC = b"REDQ"
SPICE_VERSION_MAJOR = 2
SPICE_VERSION_MINOR = 2

# Common channel types
SPICE_CHANNEL_MAIN = 1
SPICE_CHANNEL_DISPLAY = 2
SPICE_CHANNEL_INPUTS = 3
SPICE_CHANNEL_CURSOR = 4
SPICE_CHANNEL_PLAYBACK = 5
SPICE_CHANNEL_RECORD = 6

# ZTEC tunnel (vendor CAG plane :8899)
ZTEC_MAGIC = b"ZTEC"
# Captured samples (reports/captures/ztec_preamble_samples/):
#   heart_c2s_ztec_0_len178.bin  — clean C2S first TCP payload starting ZTEC
#   heart_s2c_ztec_0_len50.bin   — clean S2C first TCP payload starting ZTEC
# v3 pcap raw windows 386/86 may include adjacent non-TCP bytes; prefer heart_*.
ZTEC_SAMPLE_C2S_LEN_HINT = 178
ZTEC_SAMPLE_S2C_LEN_HINT = 50


@dataclass
class ZtecPreamble:
    """Parsed view of a ZTEC-leading TCP payload (best-effort, evidence-limited)."""

    raw: bytes
    magic: bytes  # b'ZTEC' or b'ZTEC,'
    size_hint: Optional[int] = None  # u16LE @ offset 4 when present
    rest: bytes = b""

    @property
    def is_ztec(self) -> bool:
        return self.raw.startswith(ZTEC_MAGIC)


def parse_ztec_preamble(buf: bytes) -> Optional[ZtecPreamble]:
    """Parse leading ZTEC magic if present. Does not invent full struct layout."""
    if not buf.startswith(ZTEC_MAGIC):
        return None
    # Observed variants: b'ZTEC,' (0x2c) and b'ZTEC\\xac' (len field high byte)
    magic = buf[:4]
    size_hint = None
    if len(buf) >= 6:
        size_hint = struct.unpack_from("<H", buf, 4)[0]
    return ZtecPreamble(raw=buf, magic=magic, size_hint=size_hint, rest=buf[4:])


def strip_ztec_prefix(buf: bytes) -> Tuple[Optional[ZtecPreamble], bytes]:
    """If buf starts with ZTEC, return (preamble, remainder); else (None, buf).

    Remainder may still be incomplete TLS records — caller must buffer.
    Full vendor size field is not fully reverse-closed; for known sample
    lengths we peel the whole first segment when len matches hints.
    """
    z = parse_ztec_preamble(buf)
    if z is None:
        return None, buf
    if not buf.startswith(b"ZTEC") or len(buf) < 6:
        return z, buf
    # Evidence peels (ztec_preamble_samples):
    #   C2S heart first: len=178, u16LE@4=0x00ac
    #   S2C heart first: len=50,  u16LE@4=0x002c
    # Note: other C2S messages may also use 0x002c — only peel exact short sample.
    u16 = struct.unpack_from("<H", buf, 4)[0]
    if u16 == 0x00AC and len(buf) >= 178:
        return parse_ztec_preamble(buf[:178]), buf[178:]
    if u16 == 0x002C and len(buf) == 50:
        return parse_ztec_preamble(buf[:50]), buf[50:]
    # Fallback: return header view without aggressive peel
    return z, buf


def pack_spice_link_mess(
    *,
    connection_id: int = 0,
    channel_type: int = SPICE_CHANNEL_MAIN,
    channel_id: int = 0,
    num_common_caps: int = 0,
    num_channel_caps: int = 0,
    caps_offset: int = 0,
    magic: bytes = SPICE_MAGIC,
    major: int = SPICE_VERSION_MAJOR,
    minor: int = SPICE_VERSION_MINOR,
) -> bytes:
    """Pack a minimal SpiceLinkMess-style header (open-source layout).

    LIVE REDQ cleartext not yet proven on :8899 (TLS after ZTEC). This is a
    structural skeleton for residual26 RSA/ticket work — production_claim=false.
    Layout (spice-protocol spice.proto / common headers):
      magic[4] | major:u32 LE | minor:u32 LE | size:u32 LE | ...
    Followed by connection_id/channel fields (classic client mess).
    """
    if magic != SPICE_MAGIC:
        raise ValueError("magic must be REDQ for classic SPICE link")
    # Body after common 16B: connection_id u32, channel_type u8, channel_id u8,
    # num_common_caps u32, num_channel_caps u32, caps_offset u32  (typical)
    body = struct.pack(
        "<IBBIII",
        connection_id & 0xFFFFFFFF,
        channel_type & 0xFF,
        channel_id & 0xFF,
        num_common_caps & 0xFFFFFFFF,
        num_channel_caps & 0xFFFFFFFF,
        caps_offset & 0xFFFFFFFF,
    )
    # size field = size of remaining message after the 16B header
    hdr = magic + struct.pack("<III", major, minor, len(body))
    return hdr + body


def parse_spice_link_header(buf: bytes, offset: int = 0) -> Optional[dict]:
    """Parse classic REDQ link header if present."""
    if offset + 16 > len(buf):
        return None
    magic = buf[offset : offset + 4]
    if magic != SPICE_MAGIC:
        return None
    major, minor, size = struct.unpack_from("<III", buf, offset + 4)
    return {
        "offset": offset,
        "magic": magic,
        "major": major,
        "minor": minor,
        "size": size,
        "body": buf[offset + 16 : offset + 16 + size]
        if offset + 16 + size <= len(buf)
        else buf[offset + 16 :],
        "truncated": offset + 16 + size > len(buf),
    }


def is_tls_record_prefix(buf: bytes) -> bool:
    """True if buffer looks like TLS record (HS/CCS/App/Alert) major=3."""
    if len(buf) < 5:
        return False
    ct = buf[0]
    maj, minor = buf[1], buf[2]
    return ct in (0x14, 0x15, 0x16, 0x17) and maj == 0x03 and minor in (0x01, 0x02, 0x03)


def selftest() -> None:
    # frame builder still works via re-export
    h = build_heart_ack(0x51, 0x00)
    assert h.hex() == "5100000000000000790001000000000000000000", h.hex()
    a = build_agent_heartbeat(1)
    assert len(a) == 36 and a[8:10] == b"\x6b\x00"
    p = parse_spice_frame(a)
    assert p and p["vd_agent"]["type"] == 0x7D

    # ZTEC samples on disk (if present)
    from pathlib import Path

    sample_dir = Path(__file__).resolve().parents[1] / "reports/captures/ztec_preamble_samples"
    c2s = sample_dir / "heart_c2s_ztec_0_len178.bin"
    s2c = sample_dir / "heart_s2c_ztec_0_len50.bin"
    if c2s.is_file():
        raw = c2s.read_bytes()
        z, rest = strip_ztec_prefix(raw)
        assert z and z.is_ztec, z
        assert z.size_hint == 0x00AC, z.size_hint
        assert len(raw) == 178
        # remainder empty when exact peel
        assert rest == b"", rest
    if s2c.is_file():
        raw = s2c.read_bytes()
        z, rest = strip_ztec_prefix(raw)
        assert z and z.is_ztec
        assert len(raw) == 50 and rest == b""

    # non-ZTEC pass-through
    app = bytes.fromhex("170303001c00")
    z, rest = strip_ztec_prefix(app)
    assert z is None and rest == app
    assert is_tls_record_prefix(app)

    # link mess skeleton
    lm = pack_spice_link_mess(channel_type=SPICE_CHANNEL_MAIN)
    assert lm.startswith(SPICE_MAGIC)
    ph = parse_spice_link_header(lm)
    assert ph and ph["major"] == 2 and not ph["truncated"]

    print("spice_pure_proto selftest OK")
    print("  heart20", h.hex())
    print("  agent36", a.hex()[:48], "...")
    print("  linkmess", lm[:16].hex())


if __name__ == "__main__":
    selftest()
