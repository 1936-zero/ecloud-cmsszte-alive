#!/usr/bin/env python3
"""auth220 pre-TLS frame layout + refresh policy (#26 / T51).

production_claim=false · dual_evidence_ok=false · agent_dual_ok=false
PIN: public ecloud :9222 ONLY · 禁 jtydn/爱家 · FREEZE a46d55cd523da9fd

Evidence (static T14 capture /tmp/t14_100/f23_C2S_220.bin):
  AUTH220_SIZE = 220
  port@0 u32LE | ipv6@4 16B | vmid@20 36B ascii | z@56 4B
  blob128@60 (high entropy, sticky template body)
  flag@188 u32LE (=1 on T14) | pad@192 28B zeros

Facts:
  - plain `-k` (8-digit) is **NOT** present in auth220 bytes
  - path_b `build_packets_from_templates` only rewrites header
    (port/ip6/vmid/z56); blob@60 stays from GUI capture template
  - `-k` is injected only into post-TLS REDQ163 as `k||vmid` (44B)
  - T49 LIVE: aged plain (~1h18m) + sticky blob → ok_auth220 + HEART×3

Refresh policy (two planes — do not merge):
  A) plain refresh  → -k / vmid / hv6 / port / sport
     source: getDeviceInfo → connectStr / cmdline export (SHORT_CONNECT_PLAIN_FILE)
     when: before short connect if session aged / peer change
     affects: REDQ163 k||vmid; auth220 **header** only; c108/c116 sport
  B) auth220 blob refresh → blob128@60 + flag@188 (+ whole pre-TLS set)
     source: re-capture GUI CAG pre-TLS (f23_C2S_220.bin + siblings)
     when: ok_auth220 fails OR ack36 shape drifts OR ZTEC handshake fails
     NOT required solely because plain aged (T49 counter-example)
  C) production connectStr AES refresh chain → **out of this slot**
     (量产客户端路径；本 residual 只钉 path_B 模板策略)

Does NOT:
  - claim production keepalive / dual_evidence_ok
  - dump -k / plain / blob ciphertext values to logs
  - invent blob crypto reverse (layout only)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FREEZE_CITE = "a46d55cd523da9fd"
PRODUCTION_CLAIM = False
DUAL_EVIDENCE_OK = False
AGENT_DUAL_OK = False

AUTH220_SIZE = 220
OFF_PORT = 0
OFF_IPV6 = 4
OFF_VMID = 20
OFF_Z56 = 56
OFF_BLOB = 60
OFF_FLAG = 188
OFF_PAD = 192
LEN_IPV6 = 16
LEN_VMID = 36
LEN_Z56 = 4
LEN_BLOB = 128
LEN_FLAG = 4
LEN_PAD = 28  # 192..220

# T14 sticky template (public sha only; never embed secret bytes)
T14_AUTH220_SHA16 = "d215596e0a2c5f16"
T14_BLOB128_SHA16 = "4612a09e631c2037"
T14_FLAG_U32 = 1
T14_ACK36_U32_0 = 200  # first u32 of f25_S2C_36.bin

DEFAULT_TMPL_PRE = Path(os.environ.get("PATH_B_TMPL_PRE", "/tmp/t14_100"))
DEFAULT_TMPL_NAME = "f23_C2S_220.bin"


@dataclass
class Auth220View:
    """Secret-safe structural view of an auth220 frame."""

    size: int
    port: int
    ipv6_hex: str
    vmid: str
    z56_hex: str
    blob128_sha16: str
    blob128_entropy_proxy: float  # unique-byte ratio 0..1 (not full Shannon)
    flag_u32: int
    pad_zeros: int
    full_sha16: str
    k_present_ascii: bool = False  # always expect False for honest templates
    notes: List[str] = field(default_factory=list)

    def as_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RefreshDecision:
    """What to refresh for next path_B dial (secret-free)."""

    plain_refresh: bool
    blob_recapture: bool
    reason: str
    affects: List[str]
    production_claim: bool = False

    def as_public_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def _unique_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return len(set(b)) / float(len(b))


def parse_auth220(buf: bytes, *, k_probe: Optional[str] = None) -> Auth220View:
    """Parse layout. Never logs k. Optional k_probe only sets boolean presence."""
    if len(buf) != AUTH220_SIZE:
        raise ValueError(f"auth220 size {len(buf)} != {AUTH220_SIZE}")
    port = struct.unpack_from("<I", buf, OFF_PORT)[0]
    ipv6 = buf[OFF_IPV6 : OFF_IPV6 + LEN_IPV6]
    vmid_raw = buf[OFF_VMID : OFF_VMID + LEN_VMID]
    try:
        vmid = vmid_raw.decode("ascii")
    except UnicodeDecodeError:
        vmid = f"non-ascii:{vmid_raw.hex()}"
    z56 = buf[OFF_Z56 : OFF_Z56 + LEN_Z56]
    blob = buf[OFF_BLOB : OFF_BLOB + LEN_BLOB]
    flag = struct.unpack_from("<I", buf, OFF_FLAG)[0]
    pad = buf[OFF_PAD:AUTH220_SIZE]
    notes: List[str] = []
    if z56 != b"\x00" * LEN_Z56:
        notes.append("z56_nonzero")
    if pad != b"\x00" * LEN_PAD:
        notes.append("pad_nonzero")
    if flag != T14_FLAG_U32:
        notes.append(f"flag_ne_t14({flag})")
    k_present = False
    if k_probe is not None and k_probe:
        k_present = k_probe.encode("ascii", errors="ignore") in buf
        if k_present:
            notes.append("UNEXPECTED_k_in_auth220")
    return Auth220View(
        size=len(buf),
        port=port,
        ipv6_hex=ipv6.hex(),
        vmid=vmid,
        z56_hex=z56.hex(),
        blob128_sha16=_sha16(blob),
        blob128_entropy_proxy=round(_unique_ratio(blob), 4),
        flag_u32=flag,
        pad_zeros=pad.count(0),
        full_sha16=_sha16(buf),
        k_present_ascii=k_present,
        notes=notes,
    )


def rewrite_header(
    tmpl: bytes,
    *,
    port: int,
    hv6: str,
    vmid: str,
) -> bytes:
    """Mirror path_b header rewrite; blob@60 sticky."""
    if len(tmpl) != AUTH220_SIZE:
        raise ValueError(f"tmpl size {len(tmpl)} != {AUTH220_SIZE}")
    if len(vmid) != LEN_VMID:
        raise ValueError(f"vmid len {len(vmid)} != {LEN_VMID}")
    out = bytearray(tmpl)
    struct.pack_into("<I", out, OFF_PORT, int(port) & 0xFFFFFFFF)
    ip6 = socket.inet_pton(socket.AF_INET6, hv6.split("%")[0])
    out[OFF_IPV6 : OFF_IPV6 + LEN_IPV6] = ip6
    out[OFF_VMID : OFF_VMID + LEN_VMID] = vmid.encode("ascii")
    out[OFF_Z56 : OFF_Z56 + LEN_Z56] = b"\x00" * LEN_Z56
    # blob + flag + pad untouched
    return bytes(out)


def layout_spec() -> Dict[str, Any]:
    return {
        "AUTH220_SIZE": AUTH220_SIZE,
        "fields": [
            {"name": "port", "off": OFF_PORT, "len": 4, "type": "u32le"},
            {"name": "ipv6", "off": OFF_IPV6, "len": LEN_IPV6, "type": "bytes"},
            {"name": "vmid", "off": OFF_VMID, "len": LEN_VMID, "type": "ascii"},
            {"name": "z56", "off": OFF_Z56, "len": LEN_Z56, "type": "zeros"},
            {"name": "blob128", "off": OFF_BLOB, "len": LEN_BLOB, "type": "opaque"},
            {"name": "flag", "off": OFF_FLAG, "len": LEN_FLAG, "type": "u32le"},
            {"name": "pad", "off": OFF_PAD, "len": LEN_PAD, "type": "zeros"},
        ],
        "k_in_auth220": False,
        "k_injection_site": "post-TLS REDQ163 k||vmid (44B ascii)",
        "t14_auth220_sha16": T14_AUTH220_SHA16,
        "t14_blob128_sha16": T14_BLOB128_SHA16,
        "t14_flag_u32": T14_FLAG_U32,
        "production_claim": PRODUCTION_CLAIM,
        "freeze": FREEZE_CITE,
    }


def refresh_policy(
    *,
    plain_aged: bool = False,
    ok_auth220_last: Optional[bool] = None,
    ack36_drift: bool = False,
    ztec_fail: bool = False,
    peer_or_vmid_changed: bool = False,
) -> RefreshDecision:
    """Decide plain vs blob recapture. Evidence-backed; no crypto guess."""
    affects: List[str] = []
    plain = False
    blob = False
    reasons: List[str] = []

    if plain_aged or peer_or_vmid_changed:
        plain = True
        affects.extend(
            [
                "REDQ163_k_vmid",
                "auth220_header_port_ip6_vmid",
                "c108_c116_sport",
            ]
        )
        reasons.append("plain_aged_or_peer_change")

    # blob recapture only on handshake structural failure / drift
    if ok_auth220_last is False or ack36_drift or ztec_fail:
        blob = True
        plain = True  # always refresh plain when recapturing pre-TLS set
        affects.extend(
            [
                "auth220_blob128_sticky_template",
                "preTLS_ZTEC50_ack50_c116_bundle",
                "REDQ163_k_vmid",
                "auth220_header_port_ip6_vmid",
                "c108_c116_sport",
            ]
        )
        reasons.append("preTLS_handshake_fail_or_ack_drift")

    if not plain and not blob:
        reasons.append("no_refresh_needed_sticky_ok")

    # T49: plain age alone does NOT force blob recapture
    if plain_aged and ok_auth220_last is True and not ack36_drift and not ztec_fail:
        # ensure policy does not flip blob true
        blob = False
        if "preTLS_handshake_fail_or_ack_drift" in reasons:
            reasons.remove("preTLS_handshake_fail_or_ack_drift")
        reasons.append("t49_aged_plain_heart_ok_blob_sticky")

    return RefreshDecision(
        plain_refresh=plain,
        blob_recapture=blob,
        reason="+".join(reasons) if reasons else "none",
        affects=sorted(set(affects)),
        production_claim=False,
    )


def selfcheck(tmpl_pre: Path = DEFAULT_TMPL_PRE) -> Dict[str, Any]:
    """Offline structural selfcheck against T14 template. No network. No -k dump."""
    path = tmpl_pre / DEFAULT_TMPL_NAME
    out: Dict[str, Any] = {
        "ok": False,
        "tmpl": str(path),
        "production_claim": PRODUCTION_CLAIM,
        "freeze": FREEZE_CITE,
        "checks": [],
    }
    if not path.is_file():
        out["error"] = "tmpl_missing"
        return out
    raw = path.read_bytes()
    view = parse_auth220(raw)
    checks: List[Dict[str, Any]] = []

    def add(name: str, cond: bool, detail: Any = None) -> None:
        checks.append({"name": name, "pass": bool(cond), "detail": detail})

    add("size_220", view.size == AUTH220_SIZE, view.size)
    add("full_sha16_t14", view.full_sha16 == T14_AUTH220_SHA16, view.full_sha16)
    add("blob_sha16_t14", view.blob128_sha16 == T14_BLOB128_SHA16, view.blob128_sha16)
    add("flag_u32_1", view.flag_u32 == T14_FLAG_U32, view.flag_u32)
    add("z56_zero", view.z56_hex == "00000000", view.z56_hex)
    add("pad_all_zero", view.pad_zeros == LEN_PAD, view.pad_zeros)
    add("blob_high_unique", view.blob128_entropy_proxy >= 0.5, view.blob128_entropy_proxy)
    add("vmid_len36", len(view.vmid) == LEN_VMID, len(view.vmid))
    add("port_5100", view.port == 5100, view.port)

    # rewrite keeps blob
    new = rewrite_header(raw, port=5100, hv6="::1", vmid=view.vmid)
    v2 = parse_auth220(new)
    add("rewrite_blob_sticky", v2.blob128_sha16 == view.blob128_sha16, v2.blob128_sha16)
    add("rewrite_port", v2.port == 5100, v2.port)
    add("rewrite_ip6_loopback", v2.ipv6_hex == socket.inet_pton(socket.AF_INET6, "::1").hex())

    # policy unit
    d1 = refresh_policy(plain_aged=True, ok_auth220_last=True)
    add("policy_aged_plain_no_blob", d1.plain_refresh and not d1.blob_recapture, d1.as_public_dict())
    d2 = refresh_policy(ok_auth220_last=False)
    add("policy_auth_fail_blob", d2.blob_recapture and d2.plain_refresh, d2.as_public_dict())

    # k not in template (without reading plain file if absent)
    plain_path = Path(os.environ.get("SHORT_CONNECT_PLAIN_FILE", "/tmp/r26_t29_plain"))
    k_probe = None
    if plain_path.is_file():
        # extract -k without storing into out
        parts = plain_path.read_text(encoding="utf-8", errors="replace").split()
        for i, tok in enumerate(parts):
            if tok in ("-k", "--k") and i + 1 < len(parts):
                k_probe = parts[i + 1]
                break
        if k_probe:
            v3 = parse_auth220(raw, k_probe=k_probe)
            add("k_not_in_auth220", not v3.k_present_ascii, "redacted")
            # also ensure k sha only
            out["k_sha16"] = _sha16(k_probe.encode("ascii", errors="ignore"))
            out["k_len"] = len(k_probe)

    out["checks"] = checks
    out["view"] = view.as_public_dict()
    out["layout"] = layout_spec()
    out["ok"] = all(c["pass"] for c in checks)
    out["ts"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="auth220 layout + refresh policy (claim=false)")
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--tmpl-pre", default=str(DEFAULT_TMPL_PRE))
    ap.add_argument("--json-out", default="")
    ap.add_argument("--print-layout", action="store_true")
    args = ap.parse_args()

    if args.print_layout:
        print(json.dumps(layout_spec(), indent=2, ensure_ascii=False))
        return 0

    if args.selfcheck:
        res = selfcheck(Path(args.tmpl_pre))
        text = json.dumps(res, indent=2, ensure_ascii=False)
        if args.json_out:
            Path(args.json_out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0 if res.get("ok") else 2

    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
