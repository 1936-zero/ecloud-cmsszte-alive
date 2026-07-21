"""VendorResolver — originCompanyCode → VendorProfile (Path A gate).

First implementer: CMSSZTE only. Other known origins raise VendorNotImplemented.
Never silently fall back to /opt/ZTE. No secrets in this module.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from . import vendor_paths as paths


class VendorError(Exception):
    """Base vendor routing error."""


class UnknownVendor(VendorError):
    """origin empty or not in the route table."""


class VendorNotImplemented(VendorError):
    """origin known but Path A not implemented yet."""


class VendorBinaryMissing(VendorError):
    """required VDI binary path missing or not executable."""


@dataclass(frozen=True)
class VendorProfile:
    vendor_id: str
    service_name: str
    connect_schema_id: str
    pubkey_slot: str
    vdi_wrapper_path: str
    vdi_client_path: str
    spice_conf_path: Optional[str]
    supports_path_a: bool
    notes: str = ""


def normalize_origin(code: Optional[str]) -> str:
    """Strip + upper; keep ZTEECloud distinct from ZTE."""
    if code is None:
        return ""
    return str(code).strip().upper()


def _stub(
    vendor_id: str,
    service_name: str,
    connect_schema_id: str,
    pubkey_slot: str,
    notes: str = "",
) -> VendorProfile:
    return VendorProfile(
        vendor_id=vendor_id,
        service_name=service_name,
        connect_schema_id=connect_schema_id,
        pubkey_slot=pubkey_slot,
        vdi_wrapper_path="",
        vdi_client_path="",
        spice_conf_path=None,
        supports_path_a=False,
        notes=notes or "Path A not implemented for this vendor",
    )


# Static route table. CMSSZTE is the only Path-A supported entry.
_ROUTE_TABLE: dict[str, VendorProfile] = {
    "CMSSZTE": VendorProfile(
        vendor_id="CMSSZTE",
        service_name="CmssService",
        connect_schema_id="cmsszte",
        pubkey_slot=paths.PUBKEY_SLOT_CMSSZTE,
        vdi_wrapper_path=paths.CMSS_VDI_WRAPPER,
        vdi_client_path=paths.CMSS_VDI_CLIENT,
        spice_conf_path=paths.CMSS_SPICE_CONF,
        supports_path_a=True,
        notes="Path A first vendor; CMSS wrapper → uSmartView_VDI_Client",
    ),
    "ZTE": _stub(
        "ZTE",
        "ZTEService",
        "zte",
        paths.PUBKEY_SLOT_ZTE,
        notes="registered stub; must not be default for CMSSZTE desktops",
    ),
    # Normalized form of ZTEECloud (strip+upper); kept distinct from ZTE.
    "ZTEECLOUD": _stub(
        "ZTEECLOUD",
        "ZTEService",
        "zte",
        paths.PUBKEY_SLOT_ZTE,
        notes="shares ZTE schema id; still NotImplemented for Path A",
    ),
    "H3C": _stub(
        "H3C",
        "H3CService",
        "h3c",
        paths.PUBKEY_SLOT_H3C,
    ),
    "INSPUR": _stub(
        "INSPUR",
        "InspurService",
        "inspur",
        paths.PUBKEY_SLOT_INSPUR,
    ),
}


def list_known() -> list[str]:
    return sorted(_ROUTE_TABLE.keys())


def list_supported() -> list[str]:
    return sorted(k for k, p in _ROUTE_TABLE.items() if p.supports_path_a)


def _assert_binary(path: str, label: str) -> None:
    if not path:
        raise VendorBinaryMissing(f"{label}: empty path")
    if not os.path.exists(path):
        raise VendorBinaryMissing(f"{label}: missing path {path}")
    if not os.access(path, os.X_OK):
        raise VendorBinaryMissing(f"{label}: not executable: {path}")


def resolve(
    origin_company_code: Optional[str],
    *,
    require_binaries: bool = True,
) -> VendorProfile:
    """Resolve originCompanyCode to a VendorProfile.

    require_binaries=False is for unit tests / dry design checks.
    require_binaries=True checks wrapper + client executables on disk.
    """
    code = normalize_origin(origin_company_code)
    if not code:
        raise UnknownVendor("empty origin_company_code")

    profile = _ROUTE_TABLE.get(code)
    if profile is None:
        raise UnknownVendor(code)
    if not profile.supports_path_a:
        raise VendorNotImplemented(code)

    if require_binaries:
        _assert_binary(profile.vdi_wrapper_path, "vdi_wrapper")
        _assert_binary(profile.vdi_client_path, "vdi_client")

    return profile


def _origin_from_desktop(desktop: Any) -> Optional[str]:
    if desktop is None:
        return None
    if isinstance(desktop, Mapping):
        return desktop.get("origin_company_code") or desktop.get("originCompanyCode")
    return getattr(desktop, "origin_company_code", None)


def resolve_desktop(desktop: Any, **kw: Any) -> VendorProfile:
    """Resolve from desktop_list.Desktop (or mapping with origin_company_code)."""
    return resolve(_origin_from_desktop(desktop), **kw)
