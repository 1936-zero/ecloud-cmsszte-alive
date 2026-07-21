#!/usr/bin/env python3
"""N8 · NO_SDK_BOUNDARY — pure-Python L-proto vs optional vendor SDK lanes.

production_claim=false

Defines which capabilities **must** be self-implemented in pure Python
(no commercial client SDK as the sole path) vs which may *optionally*
assist via vendor binaries / soft crypto deps.

Does NOT:
  - require uSmartView / libvdconn / Qt VDI to import L-proto modules
  - embed secrets
  - claim dual_evidence_ok or production login
"""
from __future__ import annotations

import ast
import importlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

FREEZE_CITE = "a46d55cd523da9fd"
PRODUCTION_CLAIM = False
DUAL_EVIDENCE_OK = False

_L3 = Path(__file__).resolve().parent
_NEST = _L3.parent


# ---------------------------------------------------------------------------
# Lanes
# ---------------------------------------------------------------------------

LANE_L_PROTO = "L_PROTO_PURE"  # must self-implement; no vendor SDK required
LANE_OPTIONAL_VENDOR = "OPTIONAL_VENDOR_ASSIST"  # Path A launch only; never sole
LANE_SOFT_CRYPTO = "SOFT_CRYPTO"  # PyCryptodome etc.; open dep, not VDI SDK
LANE_HOST_PROBE = "HOST_PROBE"  # path constants / existence checks only


@dataclass(frozen=True)
class BoundaryRow:
    capability: str
    must_self_impl: bool
    lane: str
    modules: Tuple[str, ...]
    notes: str
    align: str = ""  # N5/N6/N7 alignment


# Core accept: boundary table (static contract)
BOUNDARY_TABLE: Tuple[BoundaryRow, ...] = (
    BoundaryRow(
        capability="SPICE frame build/parse (HEART/AGENT)",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.spice_frame_builder", "l3.spice_pure_proto"),
        notes="stdlib struct only; offline vectors",
        align="N5/N7",
    ),
    BoundaryRow(
        capability="Handshake state machine (LINK→AUTH→CAPS→HB)",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.spice_handshake", "l3.key_provider"),
        notes="injectable KeyProvider; MissingKeyError explainable; no SDK",
        align="N5",
    ),
    BoundaryRow(
        capability="Keepalive / reconnect loop (offline-first)",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.spice_pure_session", "l3.spice_pure_link"),
        notes="default dry_run; socket/ssl stdlib; no uSmartView",
        align="N7",
    ),
    BoundaryRow(
        capability="ConnectStr / -k → prop0x14 session track",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.connectstr_k_session",),
        notes="ALREADY_IN parse; never EncryptWithKey product",
        align="N6",
    ),
    BoundaryRow(
        capability="Guest EncryptWithKey@0xa8c80 pure reimpl",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.guest_encrypt_track", "l3.vdconn_encrypt_with_key"),
        notes="algorithm-local; guest cmdline only; P1–P3",
        align="N6",
    ),
    BoundaryRow(
        capability="Key material injection (no secrets in repo)",
        must_self_impl=True,
        lane=LANE_L_PROTO,
        modules=("l3.key_provider",),
        notes="NullKeyProvider + slots; callers inject",
        align="N5/N7",
    ),
    BoundaryRow(
        capability="Vendor path constants + origin route table",
        must_self_impl=False,
        lane=LANE_HOST_PROBE,
        modules=("l3.vendor_paths", "l3.vendor_resolver"),
        notes="paths/slots only; supports_path_a gate; no secrets",
        align="Path-A control plane",
    ),
    BoundaryRow(
        capability="VDI process launch (uSmartView wrapper)",
        must_self_impl=False,
        lane=LANE_OPTIONAL_VENDOR,
        modules=("l3.vdi_launcher",),
        notes="default dry_run; LiveLaunchDenied unless allow_live; never sole L-proto path",
        align="Path-A optional",
    ),
    BoundaryRow(
        capability="RSA connect shell / AESDecode connstr",
        must_self_impl=True,
        lane=LANE_SOFT_CRYPTO,
        modules=("l3.rsa_connect", "l3.aes_decode_connstr", "l3.phase_c_offline_chain"),
        notes="PyCryptodome soft; pure algo preferred; not commercial VDI SDK",
        align="control plane",
    ),
)


# Modules that L-proto pure path must import without vendor binaries present
L_PROTO_IMPORT_SAFE: Tuple[str, ...] = (
    "l3.spice_frame_builder",
    "l3.spice_pure_proto",
    "l3.spice_handshake",
    "l3.spice_pure_session",
    "l3.spice_pure_link",
    "l3.key_provider",
    "l3.connectstr_k_session",
    "l3.guest_encrypt_track",
    "l3.vdconn_encrypt_with_key",
    "l3.no_sdk_boundary",
)

# Third-party / vendor markers (substring match on import root)
VENDOR_SDK_MARKERS: Tuple[str, ...] = (
    "uSmartView",
    "usmartview",
    "vdclient",
    "libvdconn",
    "libspice",
    "PyQt5",
    "PySide2",
    "shiboken",
)

# Soft crypto (allowed as optional open-source dep, NOT VDI SDK)
SOFT_CRYPTO_MARKERS: Tuple[str, ...] = (
    "Crypto",
    "Cryptodome",
)

# stdlib / local roots that are never "vendor SDK"
_LOCAL_OR_STDLIB = frozenset(
    {
        "abc",
        "argparse",
        "ast",
        "base64",
        "binascii",
        "collections",
        "contextlib",
        "copy",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "hashlib",
        "hmac",
        "importlib",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "os",
        "pathlib",
        "re",
        "select",
        "socket",
        "ssl",
        "struct",
        "subprocess",  # used only behind LiveLaunchDenied gate
        "sys",
        "threading",
        "time",
        "typing",
        "unittest",
        "warnings",
        "__future__",
        "l3",
        # relative / same-package
        "spice_frame_builder",
        "spice_pure_proto",
        "spice_pure_link",
        "spice_handshake",
        "spice_pure_session",
        "key_provider",
        "connectstr_k_session",
        "guest_encrypt_track",
        "vdconn_encrypt_with_key",
        "vendor_paths",
        "vendor_resolver",
        "vdi_launcher",
        "connect_schema",
        "local_15900",
        "rsa_connect",
        "aes_decode_connstr",
        "phase_c_offline_chain",
        "no_sdk_boundary",
        "path_a_session",
        "longtest_runner",
    }
)


@dataclass
class ImportProbeResult:
    module: str
    ok: bool
    error: str = ""
    top_level_imports: List[str] = field(default_factory=list)
    vendor_sdk_hits: List[str] = field(default_factory=list)
    soft_crypto_hits: List[str] = field(default_factory=list)
    false_positive_notes: List[str] = field(default_factory=list)


def _module_path(modname: str) -> Path:
    """Map l3.foo → nest/l3/foo.py."""
    parts = modname.split(".")
    if parts[0] != "l3":
        raise ValueError(f"only l3.* supported: {modname}")
    return _NEST.joinpath(*parts).with_suffix(".py")


def static_import_roots(py_path: Path) -> List[str]:
    """AST top-level import roots (no execution)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    roots: List[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                roots.append(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            if n.module:
                roots.append(n.module.split(".")[0])
    return sorted(set(roots))


def classify_import_root(root: str) -> Tuple[str, str]:
    """Return (class, note). class ∈ local_stdlib|soft_crypto|vendor_sdk|third_party."""
    if root in SOFT_CRYPTO_MARKERS or root.startswith("Crypto"):
        return "soft_crypto", "PyCryptodome/PyCrypto — open soft dep, not VDI SDK"
    for m in VENDOR_SDK_MARKERS:
        if m.lower() in root.lower():
            return "vendor_sdk", f"matched marker {m!r}"
    if root in _LOCAL_OR_STDLIB:
        return "local_stdlib", ""
    # ctypes loading .so by string is separate; bare ctypes is stdlib
    if root == "ctypes":
        return "local_stdlib", "stdlib; only host-probe if used to dlopen vendor .so"
    return "third_party", "unlisted third-party — review if hard dep for L-proto"


def probe_module_static(modname: str) -> ImportProbeResult:
    path = _module_path(modname)
    if not path.is_file():
        return ImportProbeResult(module=modname, ok=False, error=f"missing file {path}")
    roots = static_import_roots(path)
    vendor_hits: List[str] = []
    soft_hits: List[str] = []
    notes: List[str] = []
    for r in roots:
        cls, note = classify_import_root(r)
        if cls == "vendor_sdk":
            vendor_hits.append(r)
        elif cls == "soft_crypto":
            soft_hits.append(r)
        if note and cls != "local_stdlib":
            notes.append(f"{r}: {note}")
    # False-positive guidance: path strings mentioning .so in docstrings ≠ import
    text = path.read_text(encoding="utf-8", errors="replace")
    if "libvdconn" in text or "uSmartView" in text or "libspice" in text:
        if not vendor_hits:
            notes.append(
                "doc/path string mentions vendor binary name but no vendor SDK import "
                "(false-positive if grepping source strings only)"
            )
    ok = len(vendor_hits) == 0
    return ImportProbeResult(
        module=modname,
        ok=ok,
        top_level_imports=roots,
        vendor_sdk_hits=vendor_hits,
        soft_crypto_hits=soft_hits,
        false_positive_notes=notes,
    )


def probe_import_runtime(modname: str) -> ImportProbeResult:
    """Actually import module; L-proto set must succeed without vendor .so present.

    Several L-proto modules use sibling bare imports (``from spice_frame_builder``)
    for script-mode; ensure ``l3/`` is on ``sys.path`` (same pattern as
    spice_pure_session). That is **not** a vendor SDK dependency.
    """
    static = probe_module_static(modname)
    if not static.ok and static.error:
        return static
    l3_str = str(_L3)
    inserted = False
    if l3_str not in sys.path:
        sys.path.insert(0, l3_str)
        inserted = True
    try:
        importlib.import_module(modname)
        return static
    except Exception as e:  # noqa: BLE001 — probe must surface any failure
        static.ok = False
        static.error = f"{type(e).__name__}: {e}"
        return static
    finally:
        # keep path if other nest code needs it; only drop if we added and import failed
        if inserted and not static.ok and l3_str in sys.path:
            try:
                sys.path.remove(l3_str)
            except ValueError:
                pass


def probe_l_proto_lane(*, runtime: bool = True) -> List[ImportProbeResult]:
    out: List[ImportProbeResult] = []
    for m in L_PROTO_IMPORT_SAFE:
        out.append(probe_import_runtime(m) if runtime else probe_module_static(m))
    return out


def vendor_binary_presence() -> Dict[str, Any]:
    """Optional host probe — absence must NOT block L-proto imports."""
    try:
        from l3 import vendor_paths as vp
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "required_for_l_proto": False}
    paths = {
        "CMSS_VDI_WRAPPER": getattr(vp, "CMSS_VDI_WRAPPER", ""),
        "CMSS_VDI_CLIENT": getattr(vp, "CMSS_VDI_CLIENT", ""),
        "CMSS_SPICE_CONF": getattr(vp, "CMSS_SPICE_CONF", ""),
    }
    presence = {}
    for k, p in paths.items():
        pth = Path(p) if p else None
        presence[k] = {
            "path": p,
            "exists": bool(pth and pth.exists()),
        }
    return {
        "required_for_l_proto": False,
        "lane": LANE_OPTIONAL_VENDOR,
        "binaries": presence,
        "note": "missing binaries → Path A launch blocked; L-proto pure path remains usable",
    }


def boundary_table_as_dicts() -> List[Dict[str, Any]]:
    rows = []
    for r in BOUNDARY_TABLE:
        d = asdict(r)
        d["modules"] = list(r.modules)
        rows.append(d)
    return rows


def selfcheck() -> Dict[str, Any]:
    """Runnable check for N8 accept: boundary + import probe + vendor optional."""
    probes = probe_l_proto_lane(runtime=True)
    failed = [p for p in probes if not p.ok or p.vendor_sdk_hits]
    vendor = vendor_binary_presence()
    # Align surfaces N5/N6/N7
    align = {
        "N5": ["l3.spice_handshake", "l3.key_provider", "l3.spice_frame_builder"],
        "N6": ["l3.connectstr_k_session", "l3.guest_encrypt_track", "l3.vdconn_encrypt_with_key"],
        "N7": ["l3.spice_pure_session", "l3.spice_pure_link"],
    }
    report = {
        "task": "N8_NO_SDK_BOUNDARY",
        "production_claim": PRODUCTION_CLAIM,
        "dual_evidence_ok": DUAL_EVIDENCE_OK,
        "freeze_cite": FREEZE_CITE,
        "l_proto_probe_pass": len(failed) == 0,
        "l_proto_failures": [
            {"module": p.module, "error": p.error, "vendor_sdk_hits": p.vendor_sdk_hits}
            for p in failed
        ],
        "probes": [asdict(p) for p in probes],
        "boundary_table": boundary_table_as_dicts(),
        "vendor_binary_presence": vendor,
        "align": align,
        "forbid_held": [
            "commercial_SDK_as_sole_path=false",
            "secrets_not_in_module=true",
            f"FREEZE_unchanged={FREEZE_CITE}",
        ],
    }
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    rep = selfcheck()
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0 if rep["l_proto_probe_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
