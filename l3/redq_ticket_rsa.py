#!/usr/bin/env python3
"""REDQ S2C342 SPKI extract + ticket-slot boundary (path_B, production_claim=false).

Evidence pins (T14 / T37 LIVE, public ecloud :9222 ONLY):
  - post-TLS S2C342 body starts with magic REDQ + u32 fields + X.509 SPKI
  - SPKI is RSA **2048** (cipher block = 256 B under PKCS#1 v1.5)
  - subsequent C2S ticket-slot is **128 B** (T14 block_05 all-zero) and channel still
    proceeds to multi S2C channel msgs + HEART 0x74
  - therefore: classic SPICE RSA-1024 ticket ciphertext (128 B) is **NOT** what this
    wire uses for the 128 B slot against the REDQ SPKI (256 B cipher)

This module:
  - extracts SPKI from S2C342 / raw REDQ body (no secrets logged)
  - can PKCS1_v1_5 encrypt offline with that SPKI → always 256 B
  - documents HARD_NEG: 256 ≠ 128 slot → dual_ok for "RSA ticket" stays false
    until reverse proves another key/layout or a real non-zero 128 B cryptogram

Never prints PEM, -k, guest password, or full SPKI hex dumps by default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# production_claim always false in this residual track
PRODUCTION_CLAIM = False

# Vendor outer frame: 0a01 | u16le payload_len | payload
VENDOR_HDR = b"\x0a\x01"
REDQ_MAGIC = b"REDQ"
# DER SubjectPublicKeyInfo SEQUENCE tag
SPKI_TAG = b"\x30\x82"


class RedqTicketError(ValueError):
    pass


@dataclass
class SpkiInfo:
    spki: bytes
    n_bits: int
    cipher_block: int
    spki_offset: int  # offset in *body* (after vendor hdr if present)
    body_len: int
    redq_hdr_u32: List[int] = field(default_factory=list)
    after_spki: bytes = b""
    spki_sha16: str = ""
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # never dump full SPKI / trailing bytes; only lengths + sha16
        d.pop("spki", None)
        d.pop("after_spki", None)
        d["spki_len"] = len(self.spki)
        d["after_spki_len"] = len(self.after_spki)
        d["after_spki_sha16"] = hashlib.sha256(self.after_spki).hexdigest()[:16]
        if not d.get("spki_sha16"):
            d["spki_sha16"] = hashlib.sha256(self.spki).hexdigest()[:16]
        d["production_claim"] = PRODUCTION_CLAIM
        return d


@dataclass
class TicketBoundary:
    """Wire facts for residual#26 ticket RSA dual_ok decision."""

    wire_ticket_slot_len: int = 128
    redq_spki_n_bits: Optional[int] = None
    pkcs1_ct_len: Optional[int] = None
    t14_ticket_all_zero: bool = True
    classic_spice_rsa1024_slot: bool = False  # rejected for this product line
    size_match_slot: bool = False
    dual_ok: bool = False
    production_claim: bool = False
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def peel_vendor_frame(blob: bytes) -> Tuple[bytes, Optional[int]]:
    """Return (body, declared_len). Accept raw REDQ body or full 0a01 frame."""
    if len(blob) >= 4 and blob[:2] == VENDOR_HDR:
        plen = struct.unpack_from("<H", blob, 2)[0]
        body = blob[4 : 4 + plen]
        return body, plen
    return blob, None


def extract_spki_from_redq(blob: bytes) -> SpkiInfo:
    """Parse S2C342 / REDQ body and extract the first X.509 SPKI SEQUENCE.

    Layout observed on T14/T37 S2C342 body (338 B after 0a01|0x0152):
      REDQ | u32le×4 | SPKI(DER) | trailer (~24 B)
    SPKI starts at DER ``30 82`` (not necessarily 4-byte aligned to u32 fields).
    """
    body, decl = peel_vendor_frame(blob)
    if not body.startswith(REDQ_MAGIC):
        # allow full frame already peeled wrong — try find magic
        idx = body.find(REDQ_MAGIC)
        if idx < 0:
            raise RedqTicketError("REDQ magic not found")
        body = body[idx:]

    hdr_u32: List[int] = []
    for off in range(4, min(20, len(body) - 3), 4):
        hdr_u32.append(struct.unpack_from("<I", body, off)[0])

    idx = body.find(SPKI_TAG)
    if idx < 0:
        raise RedqTicketError("SPKI DER tag 30 82 not found in REDQ body")
    if idx + 4 > len(body):
        raise RedqTicketError("truncated SPKI header")
    # DER long-form length: 30 82 LL LL  → content length = u16be
    content_len = struct.unpack_from(">H", body, idx + 2)[0]
    spki_len = 4 + content_len
    if idx + spki_len > len(body):
        raise RedqTicketError(
            f"SPKI truncated: need {spki_len} from {idx}, body={len(body)}"
        )
    spki = body[idx : idx + spki_len]
    after = body[idx + spki_len :]

    notes: List[str] = []
    n_bits = 0
    cipher_block = 0
    try:
        from Crypto.PublicKey import RSA  # type: ignore

        key = RSA.import_key(spki)
        n_bits = int(key.size_in_bits())
        cipher_block = (n_bits + 7) // 8
    except Exception as e:  # pragma: no cover - env without pycryptodome
        notes.append(f"RSA import failed: {type(e).__name__}")
        # fall back: common RSA2048 SPKI ~294 B
        if spki_len >= 270:
            n_bits = 2048
            cipher_block = 256
            notes.append("assumed RSA2048 from SPKI length")

    if decl is not None and decl != len(body):
        notes.append(f"vendor u16le={decl} != body_len={len(body)}")

    return SpkiInfo(
        spki=spki,
        n_bits=n_bits,
        cipher_block=cipher_block,
        spki_offset=idx,
        body_len=len(body),
        redq_hdr_u32=hdr_u32,
        after_spki=after,
        spki_sha16=_sha16(spki),
        notes=notes,
    )


def encrypt_with_redq_spki(
    plain: bytes,
    spki_or_blob: bytes,
    *,
    scheme: str = "PKCS1_v1_5",
) -> bytes:
    """Encrypt ``plain`` with SPKI from REDQ frame/body (or raw SPKI).

    Returns ciphertext length == cipher_block (256 for RSA2048).
    Does **not** resize to 128 — never claim wire dual_ok from this alone.
    """
    from Crypto.PublicKey import RSA  # type: ignore
    from Crypto.Cipher import PKCS1_v1_5  # type: ignore

    raw = spki_or_blob
    if raw[:2] == VENDOR_HDR or raw[:4] == REDQ_MAGIC or (
        SPKI_TAG in raw[:40] and not raw[:2] == b"\x30"
    ):
        spki = extract_spki_from_redq(raw).spki
    else:
        spki = raw
    key = RSA.import_key(spki)
    cipher_block = (key.size_in_bits() + 7) // 8
    if scheme != "PKCS1_v1_5":
        raise RedqTicketError(f"unsupported scheme {scheme}")
    max_plain = cipher_block - 11
    if len(plain) > max_plain:
        raise RedqTicketError(
            f"plain len {len(plain)} > max {max_plain} for PKCS1_v1_5"
        )
    ct = PKCS1_v1_5.new(key).encrypt(plain)
    if len(ct) != cipher_block:
        raise RedqTicketError(f"unexpected ct len {len(ct)} != {cipher_block}")
    return ct


def ticket_boundary_from_spki(
    info: SpkiInfo,
    *,
    wire_slot_len: int = 128,
    t14_ticket_all_zero: bool = True,
) -> TicketBoundary:
    reasons: List[str] = []
    size_match = info.cipher_block == wire_slot_len
    if not size_match:
        reasons.append(
            f"PKCS1 ct_len={info.cipher_block} != wire_ticket_slot={wire_slot_len}"
        )
    if info.n_bits != 1024:
        reasons.append(
            f"REDQ SPKI n_bits={info.n_bits} (classic SPICE ticket key is RSA1024)"
        )
    if t14_ticket_all_zero:
        reasons.append("T14 C2S ticket-slot is 128×0x00 and channel still advances")
    reasons.append(
        "cannot dual_ok claim RSA-encrypted ticket on this wire without size match "
        "or reverse proof of alternate key/layout"
    )
    return TicketBoundary(
        wire_ticket_slot_len=wire_slot_len,
        redq_spki_n_bits=info.n_bits,
        pkcs1_ct_len=info.cipher_block,
        t14_ticket_all_zero=t14_ticket_all_zero,
        classic_spice_rsa1024_slot=False,
        size_match_slot=size_match,
        dual_ok=False,
        production_claim=False,
        reasons=reasons,
    )


def selfcheck(s2c_path: Path, ticket_path: Optional[Path] = None) -> Dict[str, Any]:
    blob = s2c_path.read_bytes()
    info = extract_spki_from_redq(blob)
    t_zero = True
    t_len = 128
    if ticket_path and ticket_path.is_file():
        t = ticket_path.read_bytes()
        t_len = len(t)
        t_zero = t == b"\x00" * len(t)
    bound = ticket_boundary_from_spki(
        info, wire_slot_len=t_len, t14_ticket_all_zero=t_zero
    )
    # offline encrypt smoke (8B dummy, never a real -k log)
    enc_meta: Dict[str, Any] = {"ok": False}
    try:
        ct = encrypt_with_redq_spki(b"\x00" * 8, blob)
        enc_meta = {
            "ok": True,
            "ct_len": len(ct),
            "ct_sha16": _sha16(ct),
            "eq_slot": len(ct) == bound.wire_ticket_slot_len,
        }
    except Exception as e:
        enc_meta = {"ok": False, "err": type(e).__name__}

    return {
        "production_claim": False,
        "s2c_path": str(s2c_path),
        "s2c_len": len(blob),
        "s2c_sha16": _sha16(blob),
        "spki": info.as_dict(),
        "boundary": bound.as_dict(),
        "encrypt_smoke": enc_meta,
        "verdict": "HARD_NEG_SIZE_MISMATCH" if not bound.size_match_slot else "SIZE_OK_NEED_LIVE",
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="REDQ SPKI / ticket-slot boundary (claim=false)")
    ap.add_argument(
        "--s2c",
        type=Path,
        default=Path("/tmp/t14_tls_plain/block_03_S2C_342.bin"),
        help="S2C342 capture path",
    )
    ap.add_argument(
        "--ticket",
        type=Path,
        default=Path("/tmp/t14_tls_plain/block_05_C2S_128.bin"),
        help="C2S 128B ticket-slot capture (for all-zero check)",
    )
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args(argv)

    if not args.s2c.is_file():
        print(json.dumps({"ok": False, "error": "s2c missing", "production_claim": False}))
        return 2
    report = selfcheck(args.s2c, args.ticket if args.ticket.is_file() else None)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    # exit 0 even on HARD_NEG — that is a successful measurement
    return 0


if __name__ == "__main__":
    sys.exit(main())
