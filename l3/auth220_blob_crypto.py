#!/usr/bin/env python3
"""auth220 blob128 crypto formula (libcag.so tn_deal) — offline, no secrets.

T52 / residual43. production_claim=false · PIN public :9222 · 禁 jtydn.
blob128 = AES(user_pt padded/trunc 0x40) || AES(pass_pt padded/trunc 0x40)

Does NOT dump -k / plain / live blob ciphertext.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

try:
    from Crypto.Cipher import AES  # pycryptodome
except ImportError:  # pragma: no cover
    AES = None  # type: ignore


Mode = Literal["ecb", "cbc"]


@dataclass(frozen=True)
class Derived:
    A: int
    B: int
    key32: str
    iv17: str
    aes_key: bytes  # 16 ASCII for AES-128 path
    iv16: bytes
    keybits: int
    mode: Mode


def derive(local_rand: int, server_key: int, bits: int = 0x1) -> Derived:
    """Derive AES key/IV material from tn_deal@0x31d7 formula.

    bits packing (recv_key body+0x1c):
      keybits = (bits & 0xff) << 7   # 0x80 → 128, 0x100 → 256
      mode_cbc = (bits >> 8) & 1     # 0=ECB, 1=CBC
    """
    local_rand &= 0xFFFFFFFF
    server_key &= 0xFFFFFFFF
    A = local_rand & 0xABACACAB
    B = server_key | 0x98979798
    Ab = A.to_bytes(4, "little")
    Bb = B.to_bytes(4, "little")
    key32 = (
        f"{local_rand:08x}{server_key:08x}"
        f"{Bb[0]:02x}{Bb[3]:02x}{Bb[2]:02x}{Bb[1]:02x}"
        f"{Ab[3]:02x}{Ab[1]:02x}{Ab[0]:02x}{Ab[2]:02x}"
    )
    # fmt@0x5278: literal "02x" + mixed-case %02X/%02x over A/B bytes
    iv17 = (
        f"02x{Ab[2]:02X}{Ab[0]:02X}{Ab[1]:02x}{Ab[3]:02X}"
        f"{Bb[1]:02x}{Bb[2]:02x}{Bb[3]:02X}"
    )
    keybits = (bits & 0xFF) << 7
    mode: Mode = "cbc" if ((bits >> 8) & 1) else "ecb"
    return Derived(
        A=A,
        B=B,
        key32=key32,
        iv17=iv17,
        aes_key=key32[:16].encode("ascii"),
        iv16=iv17[:16].encode("ascii"),
        keybits=keybits,
        mode=mode,
    )


def _pad64(data: bytes) -> bytes:
    if len(data) >= 0x40:
        return data[:0x40]
    return data + b"\x00" * (0x40 - len(data))


def encrypt_block64(pt: bytes, d: Derived) -> bytes:
    """Encrypt one 0x40 field (user or pass). Requires pycryptodome for AES-128."""
    if AES is None:
        raise RuntimeError("pycryptodome required for encrypt_block64")
    if d.keybits not in (0x80, 128):
        raise NotImplementedError(f"keybits={d.keybits:#x} not implemented in helper")
    raw = _pad64(pt)
    if d.mode == "ecb":
        c = AES.new(d.aes_key, AES.MODE_ECB)
        return c.encrypt(raw)
    c = AES.new(d.aes_key, AES.MODE_CBC, d.iv16)
    return c.encrypt(raw)


def build_blob128(user_pt: bytes, pass_pt: bytes, d: Derived) -> bytes:
    return encrypt_block64(user_pt, d) + encrypt_block64(pass_pt, d)


def decrypt_block64(ct: bytes, d: Derived) -> bytes:
    """Decrypt one 0x40 field (user or pass). Inverse of encrypt_block64.

    T53 offline helper: enables round-trip selfcheck without live secrets.
    LIVE cross (type 0x32 local_key material) still PARTIAL when capture absent.
    """
    if AES is None:
        raise RuntimeError("pycryptodome required for decrypt_block64")
    if d.keybits not in (0x80, 128):
        raise NotImplementedError(f"keybits={d.keybits:#x} not implemented in helper")
    if len(ct) != 0x40:
        raise ValueError(f"ct must be 0x40 bytes, got {len(ct)}")
    if d.mode == "ecb":
        c = AES.new(d.aes_key, AES.MODE_ECB)
        return c.decrypt(ct)
    c = AES.new(d.aes_key, AES.MODE_CBC, d.iv16)
    return c.decrypt(ct)


def parse_blob128(blob: bytes, d: Derived) -> tuple[bytes, bytes]:
    """Split blob128 → (user_pt_padded, pass_pt_padded) after AES decrypt."""
    if len(blob) != 0x80:
        raise ValueError(f"blob must be 0x80 bytes, got {len(blob)}")
    return decrypt_block64(blob[:0x40], d), decrypt_block64(blob[0x40:], d)


def selfcheck() -> None:
    # formula vectors (no live secrets)
    d = derive(0x11223344, 0x55667788, bits=0x1)
    assert d.A == 0x01202000, hex(d.A)
    assert d.B == 0xDDF7F798, hex(d.B)
    assert d.key32 == "112233445566778898ddf7f701200020", d.key32
    assert d.iv17 == "02x20002001f7f7DD", d.iv17
    assert d.aes_key == b"1122334455667788"
    assert d.iv16 == b"02x20002001f7f7D"
    assert d.keybits == 0x80
    assert d.mode == "ecb"

    d1 = derive(1, 1, bits=0x1)
    assert d1.key32 == "00000001000000019998979700000100", d1.key32
    assert d1.iv17 == "02x00010000979798", d1.iv17

    d0 = derive(0, 0, bits=0x1)
    assert d0.key32 == "00000000000000009898979700000000"
    assert d0.B == 0x98979798

    d_cbc = derive(0x11, 0x22, bits=0x101)  # lo=1 →128, bit8=1 → cbc
    assert d_cbc.keybits == 0x80
    assert d_cbc.mode == "cbc"

    if AES is not None:
        pt = b"u" * 16 + b"\x00" * 48
        ct = encrypt_block64(pt, d)
        assert len(ct) == 0x40
        assert decrypt_block64(ct, d) == pt
        ct_c = encrypt_block64(pt, d_cbc)
        assert len(ct_c) == 0x40
        assert decrypt_block64(ct_c, d_cbc) == pt
        blob = build_blob128(b"user", b"pass", d)
        assert len(blob) == 0x80
        u, p = parse_blob128(blob, d)
        assert u.startswith(b"user") and p.startswith(b"pass")
        # null-pad inverse of _pad64
        assert u == _pad64(b"user") and p == _pad64(b"pass")
    print("auth220_blob_crypto selfcheck OK")


if __name__ == "__main__":
    selfcheck()
