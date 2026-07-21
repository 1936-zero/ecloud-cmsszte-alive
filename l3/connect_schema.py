"""Connect JSON plain builder for Path A (CMSS / CMSSZTE).

Assembles the Electron-equivalent cleartext object that later goes into
RSA `--json` / `--detect`. No encryption, no PEM, no secret material stored
in this module. Field names follow reports/connect_json_schema.md §3.1.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Mapping, MutableMapping, Optional, Union

from .vendor_resolver import UnknownVendor, normalize_origin

# Origins that use the CMSS plain field table (Path A first vendor).
CMSS_ORIGINS = frozenset({"CMSS", "CMSSZTE"})

# Direct 1:1 src → plain keys (value copied when present / not None).
_DIRECT_KEYS = (
    "adUser",
    "adPassword",
    "customParams",
    "customLoginParams",
    "customPrivateLoginParams",
    "forcePreemption",
    "isThinClient",
    "vmName",
    "httpProxyParams",
    "operatePolicys",
    "perssionObject",  # Electron typo retained on purpose
    "userInfo",
    "osVersion",
    "desktopname",
    "isSpecialLine",
    "isShowCooperate",
    "virtualAppParams",
)

# Optional cluster: write only if key exists on src (even if False/0/"").
_OPTIONAL_IF_PRESENT = (
    "clientVersion",
    "clientType",
    "accessTicket",
    "updateReqUrl",
    "deviceId",
    "isDev",
    "connectSession",
    "desktopStatus",
    "watchMode",
    "adDomain",
)

# SPICE-side keys seen in VDI/so strings — must NOT be invented into Electron plain.
FORBIDDEN_SPICE_PLAIN_KEYS = frozenset(
    {
        "host",
        "hostip",
        "port",
        "tls-port",
        "password",
        "vm-proxy-port",
        "publicKey",
    }
)


class ConnectSchemaError(ValueError):
    """Invalid origin or missing required inputs for plain assembly."""


def _as_mapping(obj: Any) -> Dict[str, Any]:
    """Normalize desktop/session to a plain dict (shallow)."""
    if obj is None:
        return {}
    if isinstance(obj, Mapping):
        return dict(obj)
    # dataclass / simple namespace
    out: Dict[str, Any] = {}
    for name in dir(obj):
        if name.startswith("_"):
            continue
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        if callable(val):
            continue
        out[name] = val
    return out


def _get(src: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in src and src[k] is not None:
            return src[k]
    return default


def _has(src: Mapping[str, Any], key: str) -> bool:
    return key in src


def _merge_src(desktop: Any, session: Any) -> Dict[str, Any]:
    """Electron deviceInfo-like view: session overlays desktop."""
    base = _as_mapping(desktop)
    over = _as_mapping(session)
    merged = dict(base)
    merged.update(over)
    return merged


def _resolve_origin(desktop: Any, session: Any, origin: Optional[str]) -> str:
    if origin:
        return normalize_origin(origin)
    src = _merge_src(desktop, session)
    raw = _get(
        src,
        "originCompanyCode",
        "origin_company_code",
        "origin",
        default="",
    )
    return normalize_origin(raw)


def _machine_id(src: Mapping[str, Any]) -> str:
    mid = _get(
        src,
        "machineId",
        "machine_id",
        "instanceId",
        "desktopId",
        "id",
        "vmid",
        default="",
    )
    return "" if mid is None else str(mid)


def build_plain(
    desktop: Any = None,
    session: Any = None,
    socket_port: Union[int, str, None] = None,
    *,
    origin_company_code: Optional[str] = None,
    timestamp_ms: Optional[Union[int, str]] = None,
    include_none: bool = False,
) -> Dict[str, Any]:
    """Build CMSS/CMSSZTE connect plain dict.

    Parameters
    ----------
    desktop, session
        Mappings or objects providing Electron `deviceInfo`-like fields.
        `session` overrides `desktop` on key conflict.
    socket_port
        Actual Local15900 bound port; written as string `socketPort`.
    origin_company_code
        Optional explicit origin; otherwise read from desktop/session.
    timestamp_ms
        Override for tests; default `str(int(time.time() * 1000))`.
    include_none
        If True, copy direct keys even when value is None (default False).

    Returns
    -------
    dict suitable for JSON.stringify → RSA encrypt (caller does encrypt).

    Raises
    ------
    ConnectSchemaError
        Unsupported origin or missing socket_port / vmid core inputs.
    """
    code = _resolve_origin(desktop, session, origin_company_code)
    if not code:
        raise ConnectSchemaError("empty origin_company_code")
    if code not in CMSS_ORIGINS:
        raise ConnectSchemaError(
            f"connect_schema supports CMSS/CMSSZTE only, got {code!r}"
        )

    if socket_port is None:
        raise ConnectSchemaError("socket_port is required (runtime bound port)")

    src = _merge_src(desktop, session)
    vmid = _machine_id(src)
    if not vmid:
        raise ConnectSchemaError("machineId/vmid missing on desktop/session")

    if timestamp_ms is None:
        ts = str(int(time.time() * 1000))
    else:
        ts = str(timestamp_ms)

    plain: Dict[str, Any] = {
        "vmid": vmid,
        "timestamp": ts,
        "socketPort": str(socket_port),
    }

    for key in _DIRECT_KEYS:
        if key not in src:
            continue
        val = src[key]
        if val is None and not include_none:
            continue
        plain[key] = val

    # CMSS mapping: isOpen → vm_start (key rename)
    if "isOpen" in src:
        val = src["isOpen"]
        if val is not None or include_none:
            plain["vm_start"] = val
    elif "vm_start" in src:
        val = src["vm_start"]
        if val is not None or include_none:
            plain["vm_start"] = val

    # httpProxyParams: schema notes "if truthy write again" — keep single write if truthy/present
    if "httpProxyParams" in src and src["httpProxyParams"]:
        plain["httpProxyParams"] = src["httpProxyParams"]

    for key in _OPTIONAL_IF_PRESENT:
        if _has(src, key):
            plain[key] = src[key]

    # Hard guard: never invent SPICE rail keys into Electron plain.
    for bad in FORBIDDEN_SPICE_PLAIN_KEYS:
        # Only strip if we did not intentionally get them from src direct table
        # (they are not in _DIRECT_KEYS / optional). If caller stuffed them into
        # customParams that is their object; top-level must stay clean.
        if bad in plain and bad not in src:
            del plain[bad]
        elif bad in plain and bad in FORBIDDEN_SPICE_PLAIN_KEYS:
            # even if present on src, Electron plain top-level must not carry them
            del plain[bad]

    return plain


def build_cmss(
    desktop: Any = None,
    session: Any = None,
    socket_port: Union[int, str, None] = None,
    **kw: Any,
) -> Dict[str, Any]:
    """Alias used by path_a skeleton pseudocode."""
    return build_plain(desktop, session, socket_port, **kw)


def build_plain_json(
    desktop: Any = None,
    session: Any = None,
    socket_port: Union[int, str, None] = None,
    **kw: Any,
) -> str:
    """JSON string form of build_plain (compact, UTF-8, stable separators)."""
    import json

    plain = build_plain(desktop, session, socket_port, **kw)
    return json.dumps(plain, ensure_ascii=False, separators=(",", ":"))


def redact_plain_for_log(plain: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a log-safe copy: sensitive values → length-only markers."""
    sensitive = {"adPassword", "accessTicket", "password"}
    out: Dict[str, Any] = {}
    for k, v in plain.items():
        if k in sensitive:
            if v is None:
                out[k] = None
            elif isinstance(v, str):
                out[k] = f"<redacted len={len(v)}>"
            else:
                out[k] = f"<redacted type={type(v).__name__}>"
        else:
            out[k] = v
    return out


def supports_origin(origin_company_code: Optional[str]) -> bool:
    return normalize_origin(origin_company_code) in CMSS_ORIGINS


__all__ = [
    "CMSS_ORIGINS",
    "FORBIDDEN_SPICE_PLAIN_KEYS",
    "ConnectSchemaError",
    "build_cmss",
    "build_plain",
    "build_plain_json",
    "redact_plain_for_log",
    "supports_origin",
]
