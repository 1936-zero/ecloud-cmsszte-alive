#!/usr/bin/env python3
"""GUEST track facade — EncryptWithKey only (N6 separation).

Re-exports pure-Python EncryptWithKey from vdconn_encrypt_with_key and
marks the track boundary so session code never imports this by accident
as prop0x14 material.

P1: EncryptWithKey @0xa8c80 libvdconn — guest/password cmdline fragments ONLY.
P2/P3: output must not be written as -k or prop0x14.
"""
from __future__ import annotations

from typing import Tuple

from l3.vdconn_encrypt_with_key import (
    calc_session_key_byte,
    encrypt_data,
    encrypt_with_key,
    md5_digest,
    byte_to_hex_str,
)

TRACK = "guest"
ENCRYPT_WITH_KEY_VA = "0xa8c80"
LIBRARY = "libvdconn.so"
# Role labels for reports / tests
ROLE = "GUEST_CMDLINE_FRAGMENT_ENCRYPT"
NOT_ROLE = (
    "prop0x14",
    "session_key_8b",
    "connectstr_-k_mint",
    "access_ticket_as_session",
    "residual_ticket_as_k",
)
# Explicit anti-import note for N6 DEEPEN static checks
SESSION_MODULE = "l3.connectstr_k_session"  # use that for prop0x14; never reverse


def guest_encrypt(value: str, key_material: str, upper_hex: bool = True) -> Tuple[str, int, str]:
    """EncryptWithKey guest path. Returns (hex_ct, enc_key_byte, md5_hex)."""
    return encrypt_with_key(value, key_material, upper_hex=upper_hex)


def never_as_prop0x14(encrypt_product_hex: str) -> bytes:
    """Explicit refuse: do not convert EWK product into session 8B."""
    raise RuntimeError(
        f"P1/P3 refuse: EncryptWithKey product {encrypt_product_hex[:16]}… "
        "must not become prop0x14; use l3.connectstr_k_session instead"
    )


def selfcheck() -> None:
    out, ek, _ = guest_encrypt("hello", "testkey", upper_hex=True)
    assert ek == 10 and out == "626F666665"
    out2, ek2, _ = guest_encrypt("guest", "password", upper_hex=True)
    assert ek2 == 11 and out2 == "6C7E6E787F"
    try:
        never_as_prop0x14(out2)
        raise AssertionError("never_as_prop0x14 should raise")
    except RuntimeError:
        pass
    print("guest_encrypt_track selfcheck OK", out, out2)


if __name__ == "__main__":
    selfcheck()
