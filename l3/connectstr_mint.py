#!/usr/bin/env python3
"""connectStr production mint/refresh via CAG cs_suOperDesktop (encrypt:7).

T59 / residual52. production_claim=false · PIN public ecloud :9222 · ban jtydn.

Wire (T15/T29 LIVE capture):
  POST http://{cag_host}:8899/cs/cs_suOperDesktop.action
  Headers:
    Content-Type: application/xml   # vendor quirk; body is JSON
    X-Ap-sHost: {csapip}            # e.g. 192.168.1.200:30087
    Accept: */*
  Body JSON:
    {
      "encrypt": 7,
      "language": "zh",
      "param": <AesEncodeForCsap(pretty JSON {opType,timestamp,vmid})>,
      "timestamp": "<ms>"
    }
  Response JSON:
    { "result":"0", "success":true, "connectStr":"<HEX>", "encryption":"0", "mesg":"..." }

  connectStr hex → AesDecodeConnStr(csap_id from installinfo.ini) → plain CLI string
  plain contains -k / --hv6 / --vmid … → write SHORT_CONNECT_PLAIN_FILE (0600), never log -k.

Default pins (public path only):
  CAG   = 36.212.224.105:8899
  csapip= 192.168.1.200:30087   # from customLoginParams / D2 LIVE
  vmid  = cloud_pc.json machine_id / T15 fixture
  opType= 3                     # T15 observed (desktop connect / mint)

Does NOT claim production_ready / dual_evidence_ok.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Mapping, Optional

import requests

# repo-local imports (l3 on path when run from repo / via python -m)
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from csap_aes_encode import build_suoper_param  # noqa: E402
from aes_decode_connstr import aes_decode_connstr, get_csap_key  # noqa: E402

# ── pins ────────────────────────────────────────────────────────────────────
DEFAULT_CAG_HOST = "36.212.224.105"
DEFAULT_CAG_PORT = 8899
DEFAULT_CSAPIP = "192.168.1.200:30087"
DEFAULT_OP_TYPE = 3
DEFAULT_PLAIN_PATH = Path(
    os.environ.get("SHORT_CONNECT_PLAIN_FILE", "/tmp/r26_t29_plain")
)
DEFAULT_CLOUD_PC = _REPO / "cloud_pc.json"
FREEZE_CITE = "a46d55cd523da9fd"
PRODUCTION_CLAIM = False
PIN_PRODUCT_LINE = "public_ecloud_9222"
BAN_LINES = ("jtydn", "爱家", "cmcc-jtydn:9223")


def _sha16(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:16]


def _redact_plain(plain: str) -> str:
    """Never expose -k / long tokens in logs or public meta."""
    s = plain
    s = re.sub(r"(?:(?<=\s)|^)-k\s+\S+", "-k <REDACTED>", s)
    s = re.sub(r"(?:(?<=\s)|^)k=\S+", "k=<REDACTED>", s)
    s = re.sub(r"(--hv6)\s+\S+", r"\1 <REDACTED_V6>", s)
    # long hex blobs
    s = re.sub(r"\b[0-9a-fA-F]{32,}\b", lambda m: f"<HEX len={len(m.group(0))}>", s)
    return s


def _plain_public_fields(plain: str) -> dict:
    """Extract non-secret flags for meta only."""
    out: dict[str, Any] = {}
    m = re.search(r"--vmid\s+(\S+)", plain)
    if m:
        out["vmid"] = m.group(1)
    m = re.search(r"(?:^|\s)-p\s+(\S+)", plain)
    if m:
        out["port"] = m.group(1)
    m = re.search(r"(?:^|\s)-h\s+(\S+)", plain)
    if m:
        out["host"] = m.group(1)
    out["has_k"] = bool(re.search(r"(?:^|\s)-k\s+\S+", plain)) or " k=" in f" {plain}"
    out["has_hv6"] = bool(re.search(r"--hv6\s+\S+", plain))
    out["plain_len"] = len(plain)
    out["plain_sha16"] = _sha16(plain)
    return out


def load_vmid_from_cloud_pc(path: Path = DEFAULT_CLOUD_PC) -> Optional[str]:
    if not path.exists():
        return None
    try:
        j = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return j.get("machine_id") or j.get("vmid") or j.get("machineId")


@dataclass
class MintRequest:
    cag_host: str = DEFAULT_CAG_HOST
    cag_port: int = DEFAULT_CAG_PORT
    csapip: str = DEFAULT_CSAPIP
    vmid: str = ""
    op_type: int = DEFAULT_OP_TYPE
    language: str = "zh"
    timeout_s: float = 20.0

    def url(self) -> str:
        return f"http://{self.cag_host}:{self.cag_port}/cs/cs_suOperDesktop.action"


@dataclass
class MintResult:
    ok: bool
    production_claim: bool = PRODUCTION_CLAIM
    dual_evidence_ok: bool = False
    pin_product_line: str = PIN_PRODUCT_LINE
    freeze_cite: str = FREEZE_CITE
    http_status: Optional[int] = None
    result_code: Optional[str] = None
    success: Optional[bool] = None
    encryption: Optional[str] = None
    connectstr_hex_len: Optional[int] = None
    connectstr_hex_sha16: Optional[str] = None
    plain_path: Optional[str] = None
    plain_fields: Optional[dict] = None
    plain_redacted: Optional[str] = None
    written: bool = False
    error: Optional[str] = None
    url: Optional[str] = None
    csapip: Optional[str] = None
    vmid: Optional[str] = None
    op_type: Optional[int] = None
    request_ts: Optional[str] = None

    def as_public_dict(self) -> dict:
        return asdict(self)


def mint_connectstr(
    req: MintRequest,
    *,
    plain_path: Path = DEFAULT_PLAIN_PATH,
    write_plain: bool = True,
    dry_run: bool = False,
) -> MintResult:
    """LIVE (or dry) mint: suOper → decrypt connectStr → optional write plain."""
    if not req.vmid:
        return MintResult(ok=False, error="vmid required")

    body = build_suoper_param(
        vmid=req.vmid,
        op_type=int(req.op_type),
        language=req.language,
        pretty=True,
    )
    ts = str(body.get("timestamp") or "")
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/xml",
        "X-Ap-sHost": req.csapip,
    }
    url = req.url()
    base = MintResult(
        ok=False,
        url=url,
        csapip=req.csapip,
        vmid=req.vmid,
        op_type=int(req.op_type),
        request_ts=ts,
    )

    if dry_run:
        base.ok = True
        base.error = "dry_run: no HTTP"
        base.plain_fields = {
            "body_keys": sorted(body.keys()),
            "param_b64_len": len(body.get("param") or ""),
            "param_sha16": _sha16(body.get("param") or ""),
            "encrypt": body.get("encrypt"),
        }
        return base

    try:
        resp = requests.post(
            url,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False),
            timeout=req.timeout_s,
        )
    except requests.RequestException as e:
        base.error = f"http_error:{type(e).__name__}:{e}"
        return base

    base.http_status = resp.status_code
    try:
        j = resp.json()
    except Exception:
        base.error = f"non_json status={resp.status_code} body_len={len(resp.content)}"
        return base

    base.result_code = str(j.get("result")) if j.get("result") is not None else None
    base.success = bool(j.get("success")) if "success" in j else None
    base.encryption = str(j.get("encryption")) if j.get("encryption") is not None else None

    cstr = j.get("connectStr") or j.get("connectstr") or ""
    if not cstr:
        base.error = (
            f"no_connectStr result={base.result_code} success={base.success} "
            f"keys={list(j.keys())[:12]}"
        )
        return base

    cstr = str(cstr).strip()
    base.connectstr_hex_len = len(cstr)
    base.connectstr_hex_sha16 = _sha16(cstr)

    try:
        # ensure key available (client installinfo)
        _ = get_csap_key()
        plain = aes_decode_connstr(cstr)
    except Exception as e:
        base.error = f"decode_error:{type(e).__name__}:{e}"
        return base

    if not plain or not plain.strip():
        base.error = "decode_empty_plain"
        return base

    plain = plain.strip()
    base.plain_fields = _plain_public_fields(plain)
    base.plain_redacted = _redact_plain(plain)
    base.plain_path = str(plain_path)

    if write_plain:
        plain_path = Path(plain_path)
        tmp = plain_path.with_suffix(plain_path.suffix + ".tmp")
        tmp.write_text(plain + ("\n" if not plain.endswith("\n") else ""), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(plain_path)
        os.chmod(plain_path, 0o600)
        base.written = True

    base.ok = True
    return base


def selfcheck_offline() -> dict:
    """No network: builder + csap key load + redactor."""
    checks: dict[str, bool] = {}
    notes: list[str] = []
    try:
        body = build_suoper_param(
            vmid="c0d88cfc-9135-4e24-8fe9-8a3e2af49172",
            op_type=3,
            timestamp="1784210423300",
            pretty=True,
        )
        checks["builder_encrypt7"] = body.get("encrypt") == 7 and bool(body.get("param"))
    except Exception as e:
        checks["builder_encrypt7"] = False
        notes.append(f"builder:{e}")

    try:
        k = get_csap_key()
        checks["csap_key_16"] = len(k) == 16
        notes.append(f"csap_id_sha16={_sha16(k)}")
    except Exception as e:
        checks["csap_key_16"] = False
        notes.append(f"csap_key:{e}")

    sample = "-p 5100 -k SECRETKEY --vmid abc --hv6 dead::beef"
    red = _redact_plain(sample)
    checks["redact_k"] = "SECRETKEY" not in red and "<REDACTED>" in red
    checks["redact_hv6"] = "dead::beef" not in red

    vmid = load_vmid_from_cloud_pc()
    checks["cloud_pc_vmid"] = bool(vmid)
    if vmid:
        notes.append(f"vmid={vmid}")

    return {
        "ok": all(checks.values()),
        "checks": checks,
        "notes": notes,
        "production_claim": False,
        "pin_product_line": PIN_PRODUCT_LINE,
        "freeze_cite": FREEZE_CITE,
        "ban_lines": list(BAN_LINES),
        "default_cag": f"{DEFAULT_CAG_HOST}:{DEFAULT_CAG_PORT}",
        "default_csapip": DEFAULT_CSAPIP,
        "default_op_type": DEFAULT_OP_TYPE,
        "plain_path": str(DEFAULT_PLAIN_PATH),
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Mint/refresh connectStr via CAG suOper (encrypt:7)")
    ap.add_argument("--selfcheck", action="store_true", help="offline only")
    ap.add_argument("--dry-run", action="store_true", help="build body, no HTTP")
    ap.add_argument("--no-write", action="store_true", help="do not write plain file")
    ap.add_argument("--cag-host", default=DEFAULT_CAG_HOST)
    ap.add_argument("--cag-port", type=int, default=DEFAULT_CAG_PORT)
    ap.add_argument("--csapip", default=DEFAULT_CSAPIP)
    ap.add_argument("--vmid", default="", help="default: cloud_pc.json machine_id")
    ap.add_argument("--op-type", type=int, default=DEFAULT_OP_TYPE)
    ap.add_argument("--plain-path", default=str(DEFAULT_PLAIN_PATH))
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args(argv)

    if args.selfcheck:
        r = selfcheck_offline()
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if r["ok"] else 1

    vmid = args.vmid or load_vmid_from_cloud_pc() or ""
    if not vmid:
        print(json.dumps({"ok": False, "error": "vmid missing (pass --vmid or cloud_pc.json)"}, indent=2))
        return 2

    req = MintRequest(
        cag_host=args.cag_host,
        cag_port=args.cag_port,
        csapip=args.csapip,
        vmid=vmid,
        op_type=args.op_type,
        timeout_s=args.timeout,
    )
    res = mint_connectstr(
        req,
        plain_path=Path(args.plain_path),
        write_plain=not args.no_write,
        dry_run=args.dry_run,
    )
    print(json.dumps(res.as_public_dict(), ensure_ascii=False, indent=2))
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
