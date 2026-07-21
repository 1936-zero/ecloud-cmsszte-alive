#!/usr/bin/env python3
"""ConnectStr -k → prop0x14 session-key path (SESSION track, pure-Python).

N6 sole track: SEPARATE from guest EncryptWithKey (l3.vdconn_encrypt_with_key).

Evidence pins (T25/T26 offline + LIVE cites, production_claim=false):
  - Source class: SERVER_CONNECTSTR (CSAP AesDecode → g_strConnectStr already has -k)
  - P2: -k is ALREADY_IN find-only; NOT EncryptWithKey product
  - P3: prop0x14 wire 8B = raw UTF-8 string[:8] (pad/trunc); ≠ EncryptWithKey hex out
  - Public head cite (no secret): "91723341" (T25 LIVE g_strConnectStr / fill@0x5545a0)
  - FREEZE cite: a46d55cd523da9fd

Do NOT:
  - feed EncryptWithKey ciphertext into prop0x14
  - mint -k from SaaS alone / ticket alone
  - claim production dual_evidence_ok
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Public-head fixture only (already on reports; not a secret)
PUBLIC_HEAD_K_DIGITS = "91723341"
FREEZE_CITE = "a46d55cd523da9fd"
SOURCE_CLASS = "SERVER_CONNECTSTR"  # T26-A: -k already-in after AesDecode
# Residual#26 / N5 key_provider slots that must NOT substitute for -k / prop0x14
RESIDUAL_TICKET_FIRST8_CITE = "ticket:2"  # public cite; synthetic body first8
RESIDUAL_TICKET_LEN_CITE = 69

# Flag specs aligned with phase_c_offline_chain / CONNECTSTR_MAP
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
    ("-k ", "k"),  # ALREADY_IN parse-key ONLY
)


@dataclass
class ConnectStrKFields:
    """Parsed connectStr focused on -k / session material."""

    raw: str
    fields: Dict[str, str] = field(default_factory=dict)
    k_present: bool = False
    k_value: Optional[str] = None

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.fields.get(name, default)


def parse_connectstr_k(decoded: str) -> ConnectStrKFields:
    """Parse post-AesDecode connectStr; -k is find-only ALREADY_IN.

    Semantics (B1/MAP/T26):
      AddPwd LEA `-k ` → std::string::find only; does NOT append EncryptWithKey.
    """
    s = decoded if isinstance(decoded, str) else decoded.decode("utf-8", "replace")
    out = ConnectStrKFields(raw=s)
    work = s.replace("&", " ")
    for flag, name in _FLAG_SPECS:
        idx = work.find(flag)
        if idx < 0:
            flag2 = flag.rstrip()
            idx = work.find(flag2)
            if idx < 0:
                continue
            flag_len = len(flag2)
        else:
            flag_len = len(flag)
        start = idx + flag_len
        rest = work[start:]
        m = re.match(r"(\S+)", rest)
        val = m.group(1) if m else ""
        out.fields[name] = val
        if name == "k":
            out.k_present = True
            out.k_value = val
    return out


def session_key_8b(raw: str | bytes) -> bytes:
    """prop0x14 wire 8B = raw string UTF-8[:8] (truncate or pad with NUL).

    MD5(calc_key) is a *separate* path — not equal to this 8B slice.
    Not equal to EncryptWithKey hex ciphertext.
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


def k_to_prop0x14(k_value: str | bytes) -> bytes:
    """Canonical SESSION path: connectStr -k token → prop0x14 8B."""
    if isinstance(k_value, bytes):
        return session_key_8b(k_value)
    return session_key_8b(k_value)


def refuse_ewk_as_session(encrypt_product_hex: str, session_8b: bytes) -> bool:
    """Return True iff EncryptWithKey product must NOT be accepted as prop0x14.

    Gate P3: always refuse equality / substitution of EWK hex for session 8B.
    """
    if not encrypt_product_hex:
        return True
    ewk_bytes = encrypt_product_hex.encode("ascii", "replace")
    # refuse if product hex equals session raw, or hex-decoded equals session
    if ewk_bytes[:8] == session_8b:
        return True  # refused (caller must not use)
    try:
        raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", encrypt_product_hex))
        if raw[:8] == session_8b and len(raw) >= 8:
            return True
    except ValueError:
        pass
    # structural refuse: EWK out is hex string of XOR ciphertext, not prop0x14 material
    return True


def assert_tracks_separated(k_value: Optional[str], encrypt_product_hex: str) -> None:
    """Hard gate: -k value must never equal EncryptWithKey product hex."""
    if k_value is not None and k_value and encrypt_product_hex:
        if k_value.upper() == encrypt_product_hex.upper():
            raise AssertionError(
                "P2/P3 VIOLATION: -k value equals EncryptWithKey product "
                "(guest track must not feed session track)"
            )
        sk = k_to_prop0x14(k_value)
        ewk_as_bytes = encrypt_product_hex.encode("ascii")[:8]
        if sk == ewk_as_bytes:
            raise AssertionError(
                "P3 VIOLATION: prop0x14 8B equals EncryptWithKey product prefix"
            )


def residual_ticket_boundary(
    ticket_raw: str | bytes | None,
    k_value: Optional[str],
    session_8b: Optional[bytes] = None,
    *,
    encrypt_product_hex: str = "",
) -> dict:
    """Residual#26 / N5 boundary: accessTicket ≠ -k ≠ prop0x14 ≠ EWK.

    Offline relation battery only. Does not mint session keys from ticket.
    Returns a structured verdict for pytest / reports.
    """
    if isinstance(ticket_raw, bytes):
        t_bytes = ticket_raw
        t_ascii = ticket_raw.decode("utf-8", "replace")
    elif ticket_raw is None:
        t_bytes = b""
        t_ascii = ""
    else:
        t_ascii = ticket_raw
        t_bytes = ticket_raw.encode("utf-8", "replace")

    t_first8 = t_bytes[:8] if t_bytes else b""
    sk = session_8b
    if sk is None and k_value:
        sk = k_to_prop0x14(k_value)

    reasons: List[str] = []
    ok = True

    # ticket first8 must not equal public-head -k / prop0x14
    if t_first8 and sk is not None and t_first8 == sk:
        ok = False
        reasons.append("ticket_first8_equals_prop0x14")
    if t_first8 and k_value and t_first8 == k_value.encode("utf-8", "replace")[:8]:
        ok = False
        reasons.append("ticket_first8_equals_k_value")
    # ticket body must not be treated as -k digits
    if t_ascii and k_value and t_ascii.strip() == k_value:
        ok = False
        reasons.append("ticket_body_equals_k_value")
    # ticket must not equal EWK product
    if encrypt_product_hex and t_ascii:
        if t_ascii.upper() == encrypt_product_hex.upper():
            ok = False
            reasons.append("ticket_equals_ewk_product")
        try:
            ewk_raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", encrypt_product_hex))
            if t_first8 and ewk_raw[:8] == t_first8:
                ok = False
                reasons.append("ticket_first8_equals_ewk_decoded")
        except ValueError:
            pass

    # structural: synthetic public cite "ticket:2" ≠ digits -k
    if t_first8[:8] == RESIDUAL_TICKET_FIRST8_CITE.encode("ascii") and k_value == PUBLIC_HEAD_K_DIGITS:
        # expected separation for rp001 battery
        reasons.append("expected_ticket2_ne_public_head_k")

    if ok:
        reasons.append("ticket_ne_k_ne_prop0x14_ne_ewk")

    return {
        "ok": ok,
        "track_session_isolated": ok,
        "ticket_len": len(t_bytes),
        "ticket_first8_ascii": t_first8.decode("ascii", "replace") if t_first8 else "",
        "k_value": k_value,
        "session_8b_ascii": (
            sk.decode("ascii", "replace") if sk is not None else None
        ),
        "source_class": SOURCE_CLASS,
        "mint_from_ticket": False,  # hard anti-claim
        "production_claim": False,
        "reasons": reasons,
        "freeze_cite": FREEZE_CITE,
    }


def assert_ticket_not_session(
    ticket_raw: str | bytes | None,
    k_value: Optional[str],
    encrypt_product_hex: str = "",
) -> None:
    """Raise if residual ticket collapses into session or guest track."""
    v = residual_ticket_boundary(
        ticket_raw, k_value, encrypt_product_hex=encrypt_product_hex
    )
    if not v["ok"]:
        raise AssertionError(
            "RESIDUAL_TICKET_BOUNDARY VIOLATION: " + ",".join(v["reasons"])
        )


def session_module_imports_guest() -> bool:
    """Static-ish guard: session module must not import guest/EWK modules.

    Returns True if a forbidden import is present (BAD). False = clean.
    Only inspects real import lines; docstrings/comments/strings ignored.
    """
    import l3.connectstr_k_session as self_mod

    path = getattr(self_mod, "__file__", None)
    if not path:
        return False
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # strip inline comments
        code = s.split("#", 1)[0].strip()
        if code.startswith("from l3.guest") or code.startswith("import l3.guest"):
            return True
        if code.startswith("from l3.vdconn") or code.startswith("import l3.vdconn"):
            return True
        if code.startswith("from l3.guest_encrypt") or code.startswith(
            "import l3.guest_encrypt"
        ):
            return True
    return False


def pipeline_from_plain_connectstr(
    connectstr_plain: str,
    *,
    production_claim: bool = False,
    access_ticket: str | bytes | None = None,
    encrypt_product_hex: str = "",
) -> dict:
    """Offline pipeline: plain connectStr → parse -k → prop0x14.

    Never calls EncryptWithKey. production_claim forced False for N6 gates.
    Optional residual ticket boundary check (does not feed ticket into session).
    """
    if production_claim:
        # N6 gate: refuse production flip
        production_claim = False
    parsed = parse_connectstr_k(connectstr_plain)
    session_8b = k_to_prop0x14(parsed.k_value) if parsed.k_value else None
    md5h = session_key_md5_hex(session_8b) if session_8b is not None else None
    ticket_v = None
    if access_ticket is not None or encrypt_product_hex:
        ticket_v = residual_ticket_boundary(
            access_ticket,
            parsed.k_value,
            session_8b,
            encrypt_product_hex=encrypt_product_hex,
        )
    return {
        "track": "session",
        "k_present": parsed.k_present,
        "k_value": parsed.k_value,
        "session_8b_hex": session_8b.hex() if session_8b else None,
        "session_8b_ascii": (
            session_8b.decode("ascii", "replace") if session_8b else None
        ),
        "session_md5_hex": md5h,
        "source_class": SOURCE_CLASS + "_ALREADY_IN",
        "production_claim": False,
        "live_executed": False,
        "freeze_cite": FREEZE_CITE,
        "md5_is_separate_path": True,
        "ticket_boundary": ticket_v,
        "notes": [
            "parse_find_only",
            "prop0x14_utf8_slice8",
            "no_mint_from_ticket",
            "no_ewk_to_prop0x14",
        ],
    }


def selfcheck() -> None:
    fixture = f"-h 10.0.0.1 -p 5900 -k {PUBLIC_HEAD_K_DIGITS} --guest-usr alice"
    r = pipeline_from_plain_connectstr(fixture)
    assert r["k_present"] is True
    assert r["k_value"] == PUBLIC_HEAD_K_DIGITS
    assert r["session_8b_ascii"] == PUBLIC_HEAD_K_DIGITS
    assert r["session_8b_hex"] == PUBLIC_HEAD_K_DIGITS.encode().hex()
    assert r["production_claim"] is False
    # P3: EWK product must not equal session
    fake_ewk = "6C7E6E787F"  # encrypt_with_key("guest","password") product
    assert_tracks_separated(r["k_value"], fake_ewk)
    assert refuse_ewk_as_session(fake_ewk, k_to_prop0x14(r["k_value"])) is True
    # short k pads
    assert session_key_8b("abc") == b"abc\x00\x00\x00\x00\x00"
    # long k truncates
    assert session_key_8b("1234567890") == b"12345678"
    # residual ticket boundary (public cite)
    ticket = RESIDUAL_TICKET_FIRST8_CITE + ("x" * (RESIDUAL_TICKET_LEN_CITE - 8))
    assert len(ticket) == RESIDUAL_TICKET_LEN_CITE
    tv = residual_ticket_boundary(ticket, PUBLIC_HEAD_K_DIGITS, encrypt_product_hex=fake_ewk)
    assert tv["ok"] is True, tv
    assert_ticket_not_session(ticket, PUBLIC_HEAD_K_DIGITS, fake_ewk)
    assert session_module_imports_guest() is False
    # MD5 path separate from raw 8B
    assert session_key_md5_hex(b"91723341") != PUBLIC_HEAD_K_DIGITS
    assert r["md5_is_separate_path"] is True
    print("connectstr_k_session selfcheck OK", r["session_8b_ascii"], "ticket_ok")


if __name__ == "__main__":
    selfcheck()
