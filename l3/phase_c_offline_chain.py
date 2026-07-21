#!/usr/bin/env python3
"""Phase C offline pure-Python assemble chain (CMSSZTE / 公众云电脑).

Evidence-correct integration of Wave-0 SoT (A/B1–B4). production_claim=false.
NO LIVE network, NO real password/token on disk, NO private-key dump.

SoT sha16 (dual-EQ Wave-0):
  A_GATE d585307f5f6266d1 · CONNECTSTR_MAP 8da2db85a743ac94 · ENCRYPT ad7100defa702251
  B1 fe6aa9ad11c27f4d · B2 7aeaf37e6bad1faa · B3 e298c098c0699af7 · B4 bb9c33e8d7df36d8

Corrections encoded:
  - `-k` = ALREADY_IN_connectStr / find-only parse-key (NOT EncryptWithKey product)
  - EncryptWithKey only guest-usr / guest-passwd path (mock material offline)
  - AesDecode: AES-128-ECB key=csap_id 16B
  - prop0x14 session 8B = raw UTF-8 string[:8] (pad/trunc); MD5 path separate
  - ticket RSA: PKCS#1 v1.5 shape stub per B3; no LIVE RSA / no pri material
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# connectstr_parse (post-AesDecode field map)
# ---------------------------------------------------------------------------

# Flag tokens from CONNECTSTR_MAP / B2 (leading dash + trailing space where LEA)
_FLAG_SPECS: Tuple[Tuple[str, str], ...] = (
    ("-h ", "host"),
    ("--hv6 ", "host_v6"),
    ("-p ", "port"),
    ("--tn-sp ", "tn_sp"),
    ("--tn-ip ", "tn_ip"),
    ("--tn-ipv6 ", "tn_ipv6"),
    ("--vmcip ", "vmcip"),
    ("--vmcport ", "vmcport"),
    ("--https ", "https"),
    ("--lang ", "lang"),
    ("--guest-usr ", "guest_usr"),
    ("--guest-passwd ", "guest_passwd"),
    ("--uactoken ", "uactoken"),
    ("-k ", "k"),  # ALREADY_IN parse-key ONLY — never EncryptWithKey product
)


@dataclass
class ConnectStrFields:
    """Parsed connectStr after AesDecode. Values are raw substrings (no decrypt)."""

    raw: str
    fields: Dict[str, str] = field(default_factory=dict)
    k_present: bool = False  # find("-k ") hit
    k_value: Optional[str] = None  # token after "-k " if present
    unknown_flags: List[str] = field(default_factory=list)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.fields.get(name, default)


def parse_connectstr(decoded: str) -> ConnectStrFields:
    """Parse post-AesDecode connectStr by flag find (MAP / AddPwd find-only for -k).

    Semantics (B1/MAP):
      AddPwd LEA `-k ` → std::string::find only; does NOT append EncryptWithKey.
      Therefore parse treats `-k` as ALREADY_IN probe + optional value window.
    """
    s = decoded if isinstance(decoded, str) else decoded.decode("utf-8", "replace")
    out = ConnectStrFields(raw=s)
    # Normalize common & / space mixed residual forms for offline fixtures
    work = s.replace("&", " ")
    for flag, name in _FLAG_SPECS:
        idx = work.find(flag)
        if idx < 0:
            # also try without trailing space
            flag2 = flag.rstrip()
            idx = work.find(flag2)
            if idx < 0:
                continue
            flag_len = len(flag2)
        else:
            flag_len = len(flag)
        start = idx + flag_len
        # value runs until next " -" flag or end
        rest = work[start:]
        m = re.match(r"(\S+)", rest)
        val = m.group(1) if m else ""
        out.fields[name] = val
        if name == "k":
            out.k_present = True
            out.k_value = val
    return out


def never_synthesize_k_from_encrypt(encrypt_product_hex: str) -> str:
    """Guard: EncryptWithKey product must not be written as `-k` argv.

    Returns empty sentinel; callers must NOT append `-k ` + product.
    """
    _ = encrypt_product_hex  # explicitly discarded
    return ""


# ---------------------------------------------------------------------------
# session_key_material (B4 prop0x14)
# ---------------------------------------------------------------------------

def session_key_8b(raw: str | bytes) -> bytes:
    """prop0x14 wire 8B = raw string UTF-8[:8] (truncate or pad with NUL).

    MD5(calc_key) is a *separate* path — not equal to this 8B slice.
    """
    if isinstance(raw, bytes):
        b = raw
    else:
        b = raw.encode("utf-8", "replace")
    if len(b) >= 8:
        return b[:8]
    return b + b"\x00" * (8 - len(b))


def session_key_md5_hex(first8: bytes) -> str:
    """Separate MD5-key derivation over the 8B material (B4 calc_key)."""
    if len(first8) != 8:
        raise ValueError("md5 path expects exactly 8 bytes")
    return hashlib.md5(first8).hexdigest()


# ---------------------------------------------------------------------------
# guest EncryptWithKey offline mock (ENCRYPT_ALGO / vdconn)
# ---------------------------------------------------------------------------

def guest_encrypt_with_key_mock(plain: str | bytes, key_material: bytes) -> bytes:
    """Offline-only mock of EncryptWithKey guest path (NOT `-k` writer).

    Uses the pure-py selfcheck pattern from vdconn_encrypt_with_key:
    per-byte XOR with rolling key (evidence unit vector). Does not touch disk.
    """
    if isinstance(plain, str):
        plain_b = plain.encode("utf-8")
    else:
        plain_b = plain
    if not key_material:
        raise ValueError("mock key_material empty")
    out = bytearray(len(plain_b))
    for i, c in enumerate(plain_b):
        out[i] = c ^ key_material[i % len(key_material)]
    return bytes(out)


# ---------------------------------------------------------------------------
# ticket / RSA stubs (B3 boundary)
# ---------------------------------------------------------------------------

# mbedtls RSA-1024 PKCS#1 v1.5: chunk = len-11 = 117; decrypt chunk = 128
RSA_ENCRYPT_CHUNK = 117
RSA_DECRYPT_CHUNK = 128
TICKET_STUB_PREFIX = "STUB_TICKET_B3_"


@dataclass
class TicketRsaBoundary:
    """Document + stub only — no private key, no LIVE HTTP."""

    scheme: str = "PKCS1_v1_5"
    encrypt_chunk: int = RSA_ENCRYPT_CHUNK
    decrypt_chunk: int = RSA_DECRYPT_CHUNK
    key_format_native: str = "hex-MPI files (syc_rsa_pub.txt / syc_rsa_pri.txt)"
    key_format_purepy: str = "PEM via ENV slot (never embedded in reports)"
    access_ticket_is_spice_session: bool = False
    produces_k_or_prop014: bool = False
    production_claim: bool = False


def ticket_rsa_stub(plain_json: str, *, dry_run: bool = True) -> str:
    """Deterministic offline stub cipher for accessTicket envelope.

    Matches B3: RSA is transport envelope for SaaS HTTP JSON `params` only.
    Does NOT produce connectStr `-k` or prop0x14 session bytes.
    """
    if not dry_run:
        # Phase C forbids LIVE; refuse non-dry without raising secrets path
        raise RuntimeError("Phase C: LIVE RSA forbidden (production_claim=false)")
    h = hashlib.sha256(plain_json.encode("utf-8")).hexdigest()[:24]
    return f"{TICKET_STUB_PREFIX}{h}"


def ticket_boundary() -> TicketRsaBoundary:
    return TicketRsaBoundary()


# ---------------------------------------------------------------------------
# spice frame dry helpers (re-export path for chain selftest)
# ---------------------------------------------------------------------------

def pack_heart_ack(serial: int = 1) -> bytes:
    """SpiceDataHeader LE + body 0x00, type=0x79 (C49 HEART ACK)."""
    body = b"\x00"
    return (
        struct.pack("<QHHI", serial & 0xFFFFFFFFFFFFFFFF, 0x79, len(body), 0)
        + body
    )


# ---------------------------------------------------------------------------
# full offline chain assemble (no network)
# ---------------------------------------------------------------------------

@dataclass
class OfflineChainResult:
    origin: str
    decoded_connectstr: str
    parsed: ConnectStrFields
    session_8b: bytes
    session_md5: str
    guest_usr_enc_hex: str
    ticket_stub: str
    heart_frame_len: int
    k_is_encrypt_product: bool
    production_claim: bool
    live_executed: bool
    notes: List[str] = field(default_factory=list)


def assemble_offline_chain(
    *,
    origin: str = "CMSSZTE",
    # post-AesDecode fixture (or pre-decoded offline sample)
    connectstr_plain: str = "-h 10.0.0.1 -p 5900 -k ALREADY_TOKEN --guest-usr alice",
    # optional: hex cipher + mock csap key → decode first
    connectstr_cipher_hex: Optional[str] = None,
    csap_key: bytes = b"3fec8a54-7e49-48",
    session_raw: str = "sesskey!EXTRA",
    guest_plain: str = "guest",
    guest_key_material: bytes = b"MOCKKEY_MATERIAL!!",  # not a real secret
    ticket_plain_json: str = '{"username":"u","timestamp":1}',
) -> OfflineChainResult:
    """Assemble evidence-correct offline path. Never sets production_claim."""
    notes: List[str] = []
    if connectstr_cipher_hex is not None:
        # local AES-128-ECB decode without reading installinfo.ini
        try:
            from Crypto.Cipher import AES  # type: ignore
        except ImportError:  # pragma: no cover
            from Cryptodome.Cipher import AES  # type: ignore
        raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", connectstr_cipher_hex))
        if len(raw) % 16:
            raw = raw + b"\x00" * (16 - len(raw) % 16)
        pt = AES.new(csap_key, AES.MODE_ECB).decrypt(raw)
        n = pt[-1] if pt else 0
        if 1 <= n <= 16 and pt.endswith(bytes([n]) * n):
            pt = pt[:-n]
        else:
            pt = pt.rstrip(b"\x00")
        decoded = pt.decode("utf-8", "replace")
        notes.append("aes_decode_ecb_csap")
    else:
        decoded = connectstr_plain
        notes.append("connectstr_plain_fixture")

    parsed = parse_connectstr(decoded)
    # Guard: k must not be treated as EncryptWithKey product
    enc_prod = guest_encrypt_with_key_mock(guest_plain, guest_key_material).hex()
    assert never_synthesize_k_from_encrypt(enc_prod) == ""
    if parsed.k_present:
        notes.append("k_ALREADY_IN_find_only")
        # Explicitly refuse equality claim with encrypt product
        if parsed.k_value and parsed.k_value == enc_prod:
            raise AssertionError("illegal: -k value equals EncryptWithKey product")

    sk = session_key_8b(session_raw)
    md5h = session_key_md5_hex(sk)
    ticket = ticket_rsa_stub(ticket_plain_json, dry_run=True)
    heart = pack_heart_ack(1)

    return OfflineChainResult(
        origin=origin,
        decoded_connectstr=decoded,
        parsed=parsed,
        session_8b=sk,
        session_md5=md5h,
        guest_usr_enc_hex=enc_prod,
        ticket_stub=ticket,
        heart_frame_len=len(heart),
        k_is_encrypt_product=False,
        production_claim=False,
        live_executed=False,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def selftest() -> None:
    # 1) parse -k find-only + host/port
    p = parse_connectstr("-h 1.2.3.4 -p 5901 -k TOK123 --guest-usr bob")
    assert p.fields.get("host") == "1.2.3.4"
    assert p.fields.get("port") == "5901"
    assert p.k_present and p.k_value == "TOK123"
    assert p.fields.get("guest_usr") == "bob"

    # 2) never synthesize -k from encrypt
    assert never_synthesize_k_from_encrypt("deadbeef") == ""

    # 3) prop0x14 8B
    assert session_key_8b("abcdefghXYZ") == b"abcdefgh"
    assert session_key_8b("short") == b"short\x00\x00\x00"
    assert len(session_key_8b("12345678")) == 8
    m = session_key_md5_hex(session_key_8b("abcdefghXYZ"))
    assert len(m) == 32 and m != "abcdefgh"

    # 4) guest encrypt mock deterministic
    e1 = guest_encrypt_with_key_mock("ab", b"K")
    e2 = guest_encrypt_with_key_mock("ab", b"K")
    assert e1 == e2 and len(e1) == 2

    # 5) ticket stub dry + boundary
    t = ticket_rsa_stub('{"a":1}', dry_run=True)
    assert t.startswith(TICKET_STUB_PREFIX)
    b = ticket_boundary()
    assert b.encrypt_chunk == 117 and b.decrypt_chunk == 128
    assert b.produces_k_or_prop014 is False
    assert b.production_claim is False
    try:
        ticket_rsa_stub("x", dry_run=False)
        raise AssertionError("LIVE RSA should raise")
    except RuntimeError:
        pass

    # 6) heart frame
    fr = pack_heart_ack(9)
    assert len(fr) == 17 and fr[8:10] == b"\x79\x00"

    # 7) full chain
    r = assemble_offline_chain(origin="CMSSZTE")
    assert r.origin == "CMSSZTE"
    assert r.production_claim is False
    assert r.live_executed is False
    assert r.k_is_encrypt_product is False
    assert r.parsed.k_present is True
    assert r.session_8b == b"sesskey!"
    assert r.ticket_stub.startswith(TICKET_STUB_PREFIX)
    assert r.heart_frame_len == 17

    # 8) aes path with encode/decode roundtrip
    try:
        from Crypto.Cipher import AES  # type: ignore
    except ImportError:  # pragma: no cover
        from Cryptodome.Cipher import AES  # type: ignore
    key = b"3fec8a54-7e49-48"
    plain = b"-h 9.9.9.9 -p 1 -k ZZ"
    n = 16 - (len(plain) % 16)
    if n == 0:
        n = 16
    padded = plain + bytes([n]) * n
    hx = AES.new(key, AES.MODE_ECB).encrypt(padded).hex()
    r2 = assemble_offline_chain(connectstr_cipher_hex=hx, csap_key=key)
    assert "9.9.9.9" in r2.decoded_connectstr
    assert r2.parsed.fields.get("host") == "9.9.9.9"
    assert r2.parsed.k_value == "ZZ"

    print("phase_c_offline_chain selftest OK")
    print("  k_present", r.parsed.k_present, "k_value", r.parsed.k_value)
    print("  session_8b", r.session_8b, "md5", r.session_md5[:16])
    print("  ticket", r.ticket_stub)
    print("  production_claim", r.production_claim, "live_executed", r.live_executed)


if __name__ == "__main__":
    selftest()
