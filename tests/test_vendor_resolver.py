"""Unit tests for l3.vendor_resolver (Path A gate)."""

from __future__ import annotations

import os
import unittest
from dataclasses import dataclass
from unittest.mock import patch

from l3.vendor_resolver import (
    UnknownVendor,
    VendorBinaryMissing,
    VendorNotImplemented,
    VendorProfile,
    list_known,
    list_supported,
    normalize_origin,
    resolve,
    resolve_desktop,
)


class NormalizeOriginTests(unittest.TestCase):
    def test_strip_upper(self):
        self.assertEqual(normalize_origin("  cmsszte "), "CMSSZTE")

    def test_none_empty(self):
        self.assertEqual(normalize_origin(None), "")
        self.assertEqual(normalize_origin(""), "")

    def test_zteecloud_distinct(self):
        # strip+upper keeps ZTEECloud distinct from ZTE (ZTEECLOUD != ZTE)
        self.assertEqual(normalize_origin("ZTEECloud"), "ZTEECLOUD")
        self.assertNotEqual(normalize_origin("ZTEECloud"), normalize_origin("ZTE"))
        self.assertEqual(normalize_origin("zte"), "ZTE")


class ResolveCmssTests(unittest.TestCase):
    def test_cmsszte_without_binaries(self):
        p = resolve("CMSSZTE", require_binaries=False)
        self.assertIsInstance(p, VendorProfile)
        self.assertEqual(p.vendor_id, "CMSSZTE")
        self.assertEqual(p.service_name, "CmssService")
        self.assertEqual(p.connect_schema_id, "cmsszte")
        self.assertIn("CMSSZTE", p.pubkey_slot)
        self.assertTrue(p.supports_path_a)
        self.assertIn("/drivers/CMSS/", p.vdi_wrapper_path)
        self.assertIn("uSmartView_VDI_exe", p.vdi_wrapper_path)
        self.assertIn("uSmartView_VDI_Client", p.vdi_client_path)
        # must not default to /opt/ZTE
        self.assertNotIn("/opt/ZTE", p.vdi_wrapper_path)
        self.assertNotIn("/opt/ZTE", p.vdi_client_path)

    def test_cmsszte_require_binaries_if_present(self):
        p0 = resolve("CMSSZTE", require_binaries=False)
        if os.path.exists(p0.vdi_wrapper_path) and os.path.exists(p0.vdi_client_path):
            p = resolve("CMSSZTE", require_binaries=True)
            self.assertEqual(p.vendor_id, "CMSSZTE")
        else:
            with self.assertRaises(VendorBinaryMissing):
                resolve("CMSSZTE", require_binaries=True)

    def test_cmsszte_binary_missing_raises(self):
        with patch("l3.vendor_resolver.os.path.exists", return_value=False):
            with self.assertRaises(VendorBinaryMissing):
                resolve("CMSSZTE", require_binaries=True)


class ResolveNegativeTests(unittest.TestCase):
    def test_empty_unknown(self):
        with self.assertRaises(UnknownVendor):
            resolve("", require_binaries=False)
        with self.assertRaises(UnknownVendor):
            resolve(None, require_binaries=False)

    def test_unknown_origin(self):
        with self.assertRaises(UnknownVendor):
            resolve("ACMEVDI", require_binaries=False)

    def test_zte_not_implemented_not_silent_fallback(self):
        with self.assertRaises(VendorNotImplemented):
            resolve("ZTE", require_binaries=False)
        with self.assertRaises(VendorNotImplemented):
            resolve("ZTEECloud", require_binaries=False)

    def test_h3c_inspur_not_implemented(self):
        with self.assertRaises(VendorNotImplemented):
            resolve("H3C", require_binaries=False)
        with self.assertRaises(VendorNotImplemented):
            resolve("INSPUR", require_binaries=False)
        with self.assertRaises(VendorNotImplemented):
            resolve("inspur", require_binaries=False)


class ResolveDesktopTests(unittest.TestCase):
    def test_desktop_attr(self):
        @dataclass
        class D:
            origin_company_code: str

        p = resolve_desktop(D("CMSSZTE"), require_binaries=False)
        self.assertEqual(p.vendor_id, "CMSSZTE")

    def test_desktop_mapping(self):
        p = resolve_desktop({"originCompanyCode": "cmsszte"}, require_binaries=False)
        self.assertEqual(p.vendor_id, "CMSSZTE")

    def test_desktop_empty(self):
        with self.assertRaises(UnknownVendor):
            resolve_desktop({"origin_company_code": ""}, require_binaries=False)


class CatalogTests(unittest.TestCase):
    def test_supported_only_cmsszte(self):
        self.assertEqual(list_supported(), ["CMSSZTE"])

    def test_known_includes_stubs(self):
        known = list_known()
        for k in ("CMSSZTE", "ZTE", "ZTEECLOUD", "H3C", "INSPUR"):
            self.assertIn(k, known)


if __name__ == "__main__":
    unittest.main()
