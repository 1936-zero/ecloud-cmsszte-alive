#!/usr/bin/env python3
"""CSAP / suOper encrypt:7 — AesEncodeForCsap pure-Python (offline).

T56 / residual48. production_claim=false · PIN public :9222 · ban jtydn.

Wire formula (libEncryptDll.so → AesEncodeForCsap → MyAesEncode → csa_aesEnc):
  key16  = b"SuYan@@Zte" + b"\\x00"*6   # AES-128
  mode   = AES-ECB + PKCS7
  wire   = base64(AES_ECB_encrypt(pad(plain)))

Cross-check: T15 C2S param b64 → 112B sha16=e6516e92e176a278 bit-eq re-encrypt.

Does NOT dump live secrets beyond the static public key string already in
vendor binary string pool. AesDecodeForCsap is a STUB in the DLL — decode
here is pure inverse of encode for offline analysis only.

NOTE: AESEncode (Uas path / installinfo UasKey) is a *different* cipher
path and does NOT match encrypt:7. Do not conflate.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping, Optional, Union

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:  # pragma: no cover
    AES = None  # type: ignore
    pad = unpad = None  # type: ignore

# Static CSAP key material (16 bytes) — matches MyAesEncode / AesEncodeForCsap
CSAP_KEY_ASCII = b"SuYan@@Zte"
CSAP_KEY16 = CSAP_KEY_ASCII + b"\x00" * (16 - len(CSAP_KEY_ASCII))
assert len(CSAP_KEY16) == 16

# T15 fixture (public capture; no secrets)
T15_PARAM_B64 = (
    "KQMuqugbQ4UYcQLpZ0ipCSxET2ncedirxTbyNn555O2qiz/wkxS9Ol3tqCsINxRkp27O"
    "k0h2rg1/TRC6IUMZzsK5Dnw5mSfeAlf1P0AXB0+Sx0nYRl6JhuwLmNK0ktSUiEWxdR9UITPUgtWB4YlEeg=="
)
T15_PARAM_SHA16 = "e6516e92e176a278"
T15_PLAIN_OBJ = {
    "opType": 3,
    "timestamp": "1784210423300",
    "vmid": "c0d88cfc-9135-4e24-8fe9-8a3e2af49172",
}


def _require_crypto() -> None:
    if AES is None or pad is None or unpad is None:
        raise RuntimeError("pycryptodome required: pip install pycryptodome")


def key_sha16() -> str:
    return hashlib.sha256(CSAP_KEY16).hexdigest()[:16]


def aes_encode_for_csap(plain: Union[str, bytes]) -> str:
    """AesEncodeForCsap equivalent: AES-128-ECB + PKCS7 + base64."""
    _require_crypto()
    raw = plain.encode("utf-8") if isinstance(plain, str) else plain
    ct = AES.new(CSAP_KEY16, AES.MODE_ECB).encrypt(pad(raw, 16))
    return base64.b64encode(ct).decode("ascii")


def aes_decode_for_csap(param_b64: str) -> bytes:
    """Inverse of AesEncodeForCsap (DLL stub does not export this; pure offline)."""
    _require_crypto()
    ct = base64.b64decode(param_b64)
    return unpad(AES.new(CSAP_KEY16, AES.MODE_ECB).decrypt(ct), 16)


def build_suoper_param(
    vmid: str,
    op_type: int = 3,
    timestamp: Optional[str] = None,
    *,
    language: str = "zh",
    pretty: bool = True,
) -> dict:
    """Build suOper JSON body skeleton with encrypt:7 param.

    Returns dict ready for HTTP JSON (encrypt/language/param/timestamp).
    Does not perform network I/O.
    """
    import time

    ts = timestamp if timestamp is not None else str(int(time.time() * 1000))
    if pretty:
        # vendor T15 style: tab-indent + trailing newline
        plain = (
            "{\n"
            f'\t"opType" : {int(op_type)},\n'
            f'\t"timestamp" : "{ts}",\n'
            f'\t"vmid" : "{vmid}"\n'
            "}\n"
        )
    else:
        plain = json.dumps(
            {"opType": int(op_type), "timestamp": ts, "vmid": vmid},
            separators=(",", ":"),
        )
    return {
        "encrypt": 7,
        "language": language,
        "param": aes_encode_for_csap(plain),
        "timestamp": ts,
    }


def decode_suoper_param(param_b64: str) -> Mapping[str, Any]:
    """Decode encrypt:7 param → JSON object."""
    pt = aes_decode_for_csap(param_b64)
    return json.loads(pt.decode("utf-8"))


def selfcheck() -> dict:
    """Offline bit-eq vs T15 C2S param. No network. claim=false."""
    _require_crypto()
    raw = base64.b64decode(T15_PARAM_B64)
    sha = hashlib.sha256(raw).hexdigest()[:16]
    ok_sha = sha == T15_PARAM_SHA16

    pt = aes_decode_for_csap(T15_PARAM_B64)
    obj = json.loads(pt.decode("utf-8"))
    ok_fields = (
        obj.get("opType") == T15_PLAIN_OBJ["opType"]
        and str(obj.get("vmid")) == T15_PLAIN_OBJ["vmid"]
        and str(obj.get("timestamp")) == T15_PLAIN_OBJ["timestamp"]
    )

    # re-encrypt original plain bytes must bit-eq
    re_b64 = aes_encode_for_csap(pt)
    ok_bit = re_b64 == T15_PARAM_B64

    # builder with same ts/vmid/opType must also match if pretty format used
    body = build_suoper_param(
        vmid=T15_PLAIN_OBJ["vmid"],
        op_type=int(T15_PLAIN_OBJ["opType"]),
        timestamp=str(T15_PLAIN_OBJ["timestamp"]),
        pretty=True,
    )
    ok_builder = body["param"] == T15_PARAM_B64 and body["encrypt"] == 7

    return {
        "ok": bool(ok_sha and ok_fields and ok_bit and ok_builder),
        "param_sha16": sha,
        "expect_sha16": T15_PARAM_SHA16,
        "ok_sha": ok_sha,
        "ok_fields": ok_fields,
        "ok_bit_eq": ok_bit,
        "ok_builder": ok_builder,
        "key_sha16": key_sha16(),
        "mode": "AES-128-ECB-PKCS7+base64",
        "encrypt": 7,
        "production_claim": False,
        "note": "AesEncodeForCsap offline CLOSED; not production HTTP keepalive claim",
    }


def main() -> int:
    r = selfcheck()
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
