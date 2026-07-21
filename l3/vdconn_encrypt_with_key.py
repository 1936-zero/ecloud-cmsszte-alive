#!/usr/bin/env python3
"""vdconn EncryptWithKey / calc_session_key pure-Python reimpl (from IDA MCP decomp).

Evidence:
- EncryptWithKey @ 0xa8c80 (libvdconn)
- calc_session_key @ 0x11c960
- encrypt_data @ 0x118340 (byte XOR with enc_key)
- ZTE_MD5 IVs match standard MD5

NOTE: This encrypts *guest/password cmdline fragments* (--guest-usr / --guest-passwd path).
NOT connectStr `-k` mint, NOT spice-elink session-key (prop0x14 8B raw).
N6: use l3.guest_encrypt_track (guest) vs l3.connectstr_k_session (session) — do not conflate.
"""
from __future__ import annotations
import hashlib
from typing import Tuple

def md5_digest(data: bytes) -> bytes:
    """Standard MD5 (ZTE_MD5_CTX IVs = RFC1321)."""
    return hashlib.md5(data).digest()

def byte_to_hex_str(data: bytes, upper: bool = True) -> str:
    """ByteToHexStr — case not fully proven from stub; default upper (common ZTE)."""
    h = data.hex()
    return h.upper() if upper else h.lower()

def calc_session_key_byte(hex_md5: str) -> int:
    """calc_session_key(char *hex): XOR-fold all bytes into first, then ^5; if pre-xor==5 → 10.

    Decomp loop (len>1): v10 ^= each subsequent char; write back to s[0]; finally v13=v10^5;
    special-case: if v10==5 then v13=10. Returns single-byte enc_key (also written to s[0]).
    """
    if not hex_md5:
        return 0
    b = bytearray(hex_md5.encode("ascii"))
    v10 = b[0]
    for i in range(1, len(b)):
        v10 = (v10 ^ b[i]) & 0xFF
        b[0] = v10
    if v10 == 5:
        v13 = 10
    else:
        v13 = (v10 ^ 5) & 0xFF
    return v13

def encrypt_data(data: bytes, enc_key: int) -> bytes:
    """encrypt_data: each byte XOR enc_key (no-op if enc_key==0 or empty)."""
    if not data or not enc_key:
        return bytes(data)
    k = enc_key & 0xFF
    return bytes(x ^ k for x in data)

def encrypt_with_key(value: str, key_material: str, upper_hex: bool = True) -> Tuple[str, int, str]:
    """EncryptWithKey(value, key_material) → (hex_ciphertext, enc_key, md5_hex).

    Pipeline: MD5(key) → hex → calc_session_key → XOR(value) → hex.
    """
    dig = md5_digest(key_material.encode("utf-8"))
    md5_hex = byte_to_hex_str(dig, upper=upper_hex)
    enc_key = calc_session_key_byte(md5_hex)
    ct = encrypt_data(value.encode("utf-8"), enc_key)
    return byte_to_hex_str(ct, upper=upper_hex), enc_key, md5_hex

def selfcheck() -> None:
    # deterministic vectors (algorithm-local, not LIVE)
    out, ek, hx = encrypt_with_key("hello", "testkey", upper_hex=True)
    assert ek == 10, ek
    assert out == "626F666665", out
    out2, ek2, _ = encrypt_with_key("guest", "password", upper_hex=True)
    assert ek2 == 11, ek2
    assert out2 == "6C7E6E787F", out2
    # fold edge: all zeros-ish
    assert calc_session_key_byte("05") == 10
    assert calc_session_key_byte("00") == 5  # 0^5=5
    print("selfcheck OK", out, out2)

if __name__ == "__main__":
    selfcheck()
