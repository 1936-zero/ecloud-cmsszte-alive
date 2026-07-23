#!/usr/bin/env python3
"""AESDecode / AesDecodeConnStr pure-Python — from libEncryptDll.so reverse (r26).

Evidence:
  - AESDecode @0xfac0 in libEncryptDll.so.1.0.0
  - PLT: ReadStringFromConfigFile, aes_setkey_dec(bits=0x80), aes_crypt_ecb(mode=0 decrypt)
  - Config: ../config/installinfo.ini section=[PublicKey] key=csap_id (16-char ASCII)
  - Mode: AES-128-ECB, no IV
  - AesDecodeConnStr: HexToByte then AESDecode
  - installinfo.ini path (CMSS): /opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/CMSS/config/installinfo.ini
  - csap_id observed: 3fec8a54-7e49-48

Do NOT hardcode production secrets beyond what ships in the client config.
"""
from __future__ import annotations
import re
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    from Cryptodome.Cipher import AES

try:
    from l3.platform_paths import installinfo_candidates
except ImportError:  # pragma: no cover — flat script cwd
    from platform_paths import installinfo_candidates  # type: ignore

# Kept as name for callers/tests; rebuilt each access so env overrides apply.
def _default_ini_candidates() -> list[Path]:
    return installinfo_candidates()


DEFAULT_INI_CANDIDATES = _default_ini_candidates()


def parse_installinfo(path: Path | None = None) -> dict:
    if path is None:
        for p in installinfo_candidates():
            if p.exists():
                path = p
                break
    if path is None or not Path(path).exists():
        raise FileNotFoundError(
            "installinfo.ini not found (set INSTALLINFO_PATH or place under data/config/)"
        )
    sec = None
    out: dict[str, dict[str, str]] = {}
    for ln in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith(";"):
            continue
        if ln.startswith("[") and ln.endswith("]"):
            sec = ln[1:-1]
            out.setdefault(sec, {})
            continue
        if sec is not None and "=" in ln:
            k, v = ln.split("=", 1)
            out[sec][k.strip()] = v.strip()
    return out

def get_csap_key(ini_path: Path | None = None) -> bytes:
    """ReadStringFromConfigFile("PublicKey","csap_id",...,"../config/installinfo.ini",0,1)"""
    cfg = parse_installinfo(ini_path)
    key = cfg.get("PublicKey", {}).get("csap_id")
    if not key:
        raise KeyError("PublicKey.csap_id missing in installinfo.ini")
    kb = key.encode("utf-8")
    if len(kb) != 16:
        raise ValueError(f"csap_id must be 16 bytes for AES-128, got {len(kb)}: {key!r}")
    return kb

def hex_to_bytes(hex_str: str) -> bytes:
    h = re.sub(r"[^0-9a-fA-F]", "", hex_str or "")
    if not h:
        return b""
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data.endswith(bytes([n]) * n):
        return data[:-n]
    return data.rstrip(b"\x00")

def aes_decode(cipher_hex: str, key: bytes | None = None, ini_path: Path | None = None) -> bytes:
    """AESDecode(PKci, PPc, Pi) — hex ciphertext → plaintext bytes (AES-128-ECB)."""
    if key is None:
        key = get_csap_key(ini_path)
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    raw = hex_to_bytes(cipher_hex)
    if not raw:
        return b""
    if len(raw) % 16:
        raw = raw + b"\x00" * (16 - len(raw) % 16)
    pt = AES.new(key, AES.MODE_ECB).decrypt(raw)
    return _pkcs7_unpad(pt)

def aes_encode(plain: bytes | str, key: bytes | None = None, ini_path: Path | None = None) -> str:
    """Inverse helper (AESEncode path): plaintext → hex ciphertext (PKCS7)."""
    if isinstance(plain, str):
        plain = plain.encode("utf-8")
    if key is None:
        key = get_csap_key(ini_path)
    n = 16 - (len(plain) % 16)
    if n == 0:
        n = 16
    padded = plain + bytes([n]) * n
    return AES.new(key, AES.MODE_ECB).encrypt(padded).hex()

def aes_decode_connstr(cipher_hex: str, key: bytes | None = None, ini_path: Path | None = None) -> str:
    """AesDecodeConnStr: HexToByte + AESDecode → UTF-8 connect string."""
    return aes_decode(cipher_hex, key=key, ini_path=ini_path).decode("utf-8", "replace")

if __name__ == "__main__":
    k = get_csap_key()
    print("csap_id key:", k)
    sample = b"k=test&host=1.2.3.4"
    h = aes_encode(sample, k)
    print("enc:", h)
    print("dec:", aes_decode(h, k))
