#!/usr/bin/env python3
"""SPICE main-channel frame builders (evidence-backed, production_claim=false).

Wire layout (libspice-client-glib-elink + LIVE residual23 decrypt):
  SpiceDataHeader 16B:
    serial:u64 LE | type:u16 LE | size:u16 LE | sub_list:u32 LE (=0)
  size = len(body) AFTER the 16B header.

HEART (LIVE C49):
  type=0x79, size=1, body=0x00; client often pads buffer to 20B.

AGENT_DATA (LIVE + static agent_msg_queue_many → spice_msg_out_new(..., 0x6b)):
  type=0x6b, body = VDAgentMessage in **network byte order (BE)**:
    protocol:u32 BE=1 | type:u32 BE | opaque:u64 BE=0 | size:u32 BE | data[size]

Agent heartbeat (spice_main_send_agent_heartbeat, LIVE residual23 ×10/90s):
  VDAgent type=0x7d, size=0, data empty → body len 20, frame 36B (+optional pad).
"""
from __future__ import annotations

import struct
from typing import Optional

# Main channel message types (elink)
MSGC_MAIN_AGENT_DATA = 0x6B  # 107 — spice_msg_out_new constant in elink
MSGC_MAIN_AGENT_START = 0x69  # open-source spice often 105; confirm LIVE if needed
# HEART pair (LIVE dual-evidence)
TYPE_S53_HEART_REQ = 0x74
TYPE_C49_HEART_ACK = 0x79
# S2C non-heart (T42 hist + T47 static bind): handlers[0x70] → main_handle_vm_reboot
# NOT agent-token / NOT keepalive. Body = u32 LE magic (T50 static).
TYPE_MSG_MAIN_VM_REBOOT = 0x70  # 112 — dbg.main_handle_vm_reboot @0x71f51
# main_handle_vm_reboot magics (elink channel-main.c ~3973+; T50 r2)
VM_REBOOT_MAGIC_LOGOUT = 0x87654320  # ientry "-LogOut" + enable_quit (if not local_sign_out)
VM_REBOOT_MAGIC_QUIT = 0x87654321  # enable_quit only
VM_REBOOT_MAGIC_UI_ICE = 0x12345678  # ui_callback(+0x28)(2); enable_quit if session=="ice"
# T42 LIVE sample head wire 00000020 → LE 0x20000000 (NOT 32); unmatched → no-op
VM_REBOOT_MAGIC_OBS_T42 = 0x20000000

# VDAgent
VD_AGENT_PROTOCOL = 1
VD_AGENT_HEARTBEAT = 0x7D  # elink empty HB; LIVE residual23 natural ×10/90s

# Observed client pad for HEART writes
HEART_WIRE_PAD = 20
SPICE_DATA_HDR = 16  # serial+type+size+sub_list


def pack_spice_header(serial: int, msg_type: int, body: bytes, *, sub_list: int = 0) -> bytes:
    """Pack SpiceDataHeader(16B LE) + body. size field = len(body)."""
    if serial < 0:
        raise ValueError("serial must be >= 0")
    if not (0 <= msg_type <= 0xFFFF):
        raise ValueError("msg_type out of u16")
    if len(body) > 0xFFFF:
        raise ValueError("body too large for u16 size")
    return (
        struct.pack(
            "<QHHI",
            serial & 0xFFFFFFFFFFFFFFFF,
            msg_type & 0xFFFF,
            len(body) & 0xFFFF,
            sub_list & 0xFFFFFFFF,
        )
        + body
    )


def pack_vd_agent_message(
    agent_type: int,
    data: bytes = b"",
    *,
    protocol: int = VD_AGENT_PROTOCOL,
    opaque: int = 0,
) -> bytes:
    """VDAgentMessage header (20B BE / network order) + data. LIVE residual23."""
    if len(data) > 0xFFFFFFFF:
        raise ValueError("agent data too large")
    return (
        struct.pack(
            ">IIQI",
            protocol & 0xFFFFFFFF,
            agent_type & 0xFFFFFFFF,
            opaque & 0xFFFFFFFFFFFFFFFF,
            len(data) & 0xFFFFFFFF,
        )
        + data
    )


def build_heart_ack(
    serial: int,
    body: int = 0x00,
    *,
    pad_to: int = HEART_WIRE_PAD,
) -> bytes:
    """C49 client HEART ack (type 0x79). LIVE: size=1 body=00 + pad to 20."""
    raw_body = bytes([body & 0xFF])
    frame = pack_spice_header(serial, TYPE_C49_HEART_ACK, raw_body)
    if pad_to and len(frame) < pad_to:
        frame = frame + b"\x00" * (pad_to - len(frame))
    return frame


def build_heart_req(
    serial: int,
    body: int = 0x00,
    *,
    pad_to: int = HEART_WIRE_PAD,
) -> bytes:
    """S53 server-style HEART req (type 0x74) — for parser tests / inject harness."""
    raw_body = bytes([body & 0xFF])
    frame = pack_spice_header(serial, TYPE_S53_HEART_REQ, raw_body)
    if pad_to and len(frame) < pad_to:
        frame = frame + b"\x00" * (pad_to - len(frame))
    return frame


def build_agent_data(
    serial: int,
    agent_type: int,
    data: bytes = b"",
    *,
    opaque: int = 0,
    protocol: int = VD_AGENT_PROTOCOL,
) -> bytes:
    """MSGC_MAIN_AGENT_DATA (0x6b) wrapping BE VDAgentMessage."""
    vd = pack_vd_agent_message(agent_type, data, protocol=protocol, opaque=opaque)
    return pack_spice_header(serial, MSGC_MAIN_AGENT_DATA, vd)


def build_agent_heartbeat(serial: int, *, opaque: int = 0) -> bytes:
    """Empty agent HB: type 0x7d, size 0 (LIVE residual23; static ecx=0x7d)."""
    return build_agent_data(serial, VD_AGENT_HEARTBEAT, b"", opaque=opaque)


def build_vm_reboot(serial: int, magic: int) -> bytes:
    """S2C-style main type 0x70 body = u32 LE magic (T47/T50).

    OFFLINE wire builder only. Do NOT inject LOGOUT/QUIT magics on LIVE path_B
    (would tear the desktop). T53: selftest + residual44 offline art.
    """
    body = struct.pack("<I", magic & 0xFFFFFFFF)
    return pack_spice_header(serial, TYPE_MSG_MAIN_VM_REBOOT, body)


def parse_spice_frame(buf: bytes, offset: int = 0) -> Optional[dict]:
    """Parse one SPICE main frame at offset (16B SpiceDataHeader)."""
    if offset + SPICE_DATA_HDR > len(buf):
        return None
    serial, typ, size, sub_list = struct.unpack_from("<QHHI", buf, offset)
    body_off = offset + SPICE_DATA_HDR
    end = body_off + size
    if end > len(buf):
        body = buf[body_off:]
        truncated = True
    else:
        body = buf[body_off:end]
        truncated = False
    out = {
        "offset": offset,
        "serial": serial,
        "type": typ,
        "size": size,
        "sub_list": sub_list,
        "body": body[:size] if not truncated else body[: min(size, len(body))],
        "raw_len": len(buf) - offset,
        "truncated": truncated,
    }
    if typ == MSGC_MAIN_AGENT_DATA and len(out["body"]) >= 20:
        proto, atype, opaque, asize = struct.unpack_from(">IIQI", out["body"], 0)
        out["vd_agent"] = {
            "protocol": proto,
            "type": atype,
            "opaque": opaque,
            "size": asize,
            "data": out["body"][20 : 20 + asize],
        }
    return out


def selftest() -> None:
    h = build_heart_ack(0x51, 0x00)
    assert len(h) == 20, len(h)
    # serial=0x51 type=0x79 size=1 sub_list=0 body=00 + pad
    assert h.hex() == "5100000000000000790001000000000000000000", h.hex()
    a = build_agent_heartbeat(1)
    assert len(a) == 36, len(a)  # 16 hdr + 20 VDAgent
    assert a.hex() == (
        "0100000000000000"  # serial=1
        "6b00"  # type 0x6b
        "1400"  # size 20
        "00000000"  # sub_list 0
        "00000001"  # protocol 1 BE
        "0000007d"  # type 0x7d BE
        "0000000000000000"  # opaque
        "00000000"  # size 0
    ), a.hex()
    p = parse_spice_frame(a)
    assert p and p["type"] == 0x6B and p["sub_list"] == 0
    assert p["vd_agent"]["type"] == 0x7D and p["vd_agent"]["size"] == 0
    # offline replay residual23 hex (ser=37 size=20 → 0x7d)
    live = bytes.fromhex(
        "25000000000000006b00140000000000"
        "000000010000007d000000000000000000000000"
    )
    # pad-safe: only 36 bytes needed; above is 36
    pl = parse_spice_frame(live)
    assert pl and pl["vd_agent"]["type"] == 0x7D, pl
    # 0x70 vm_reboot offline wire (T50/T53) — do not send LIVE
    r = build_vm_reboot(0x2A, VM_REBOOT_MAGIC_LOGOUT)
    assert len(r) == 20, len(r)
    pr = parse_spice_frame(r)
    assert pr and pr["type"] == TYPE_MSG_MAIN_VM_REBOOT and pr["size"] == 4
    assert pr["body"] == struct.pack("<I", VM_REBOOT_MAGIC_LOGOUT)
    r_obs = build_vm_reboot(1, VM_REBOOT_MAGIC_OBS_T42)
    assert r_obs[16:20] == b"\x00\x00\x00\x20"  # LE 0x20000000
    print("spice_frame_builder selftest OK")
    print("  heart20", h.hex())
    print("  agent36", a.hex())
    print("  reboot20", r.hex())


if __name__ == "__main__":
    selftest()
