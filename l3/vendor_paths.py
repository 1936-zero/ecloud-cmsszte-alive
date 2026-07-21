"""Vendor filesystem path constants (no secrets, no default-to-ZTE)."""

from __future__ import annotations

# Official ecloudcomputer CMSS stack (Path A first vendor).
CMSS_DRIVER_ROOT = "/opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/CMSS"
CMSS_VDI_WRAPPER = f"{CMSS_DRIVER_ROOT}/bin/uSmartView_VDI_exe"
CMSS_VDI_CLIENT = f"{CMSS_DRIVER_ROOT}/bin/uSmartView_VDI_Client"
CMSS_SPICE_CONF = f"{CMSS_DRIVER_ROOT}/config/spice_conf.ini"

# Slot names only — never embed PEM/key material.
PUBKEY_SLOT_CMSSZTE = "privateSetting.SDKSecretKey.publicKey.CMSSZTE"
PUBKEY_SLOT_ZTE = "privateSetting.SDKSecretKey.publicKey.ZTE"
PUBKEY_SLOT_H3C = "privateSetting.SDKSecretKey.publicKey.H3C"
PUBKEY_SLOT_INSPUR = "privateSetting.SDKSecretKey.publicKey.INSPUR"
