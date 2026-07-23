#!/usr/bin/env python3
"""N8 · NO_SDK_BOUNDARY — pure L-proto vs optional vendor SDK.

accept:
  - boundary table present
  - L-proto modules import without vendor SDK
  - vendor binaries optional (absence ≠ L-proto fail)
  - no commercial SDK as sole path
  - production_claim=false; FREEZE held

production_claim remains false. No LIVE connect.
"""
from __future__ import annotations

import importlib
import unittest
from pathlib import Path

from l3.no_sdk_boundary import (
    BOUNDARY_TABLE,
    DUAL_EVIDENCE_OK,
    FREEZE_CITE,
    L_PROTO_IMPORT_SAFE,
    LANE_L_PROTO,
    LANE_OPTIONAL_VENDOR,
    PRODUCTION_CLAIM,
    classify_import_root,
    probe_l_proto_lane,
    probe_module_static,
    selfcheck,
    vendor_binary_presence,
)


class N8BoundaryContractTests(unittest.TestCase):
    def test_pins(self):
        self.assertIs(PRODUCTION_CLAIM, False)
        self.assertIs(DUAL_EVIDENCE_OK, False)
        self.assertEqual(FREEZE_CITE, "a46d55cd523da9fd")

    def test_boundary_table_nonempty_and_lanes(self):
        self.assertGreaterEqual(len(BOUNDARY_TABLE), 6)
        must = [r for r in BOUNDARY_TABLE if r.must_self_impl]
        self.assertGreaterEqual(len(must), 4)
        lanes = {r.lane for r in BOUNDARY_TABLE}
        self.assertIn(LANE_L_PROTO, lanes)
        self.assertIn(LANE_OPTIONAL_VENDOR, lanes)
        # every must_self_impl row is L_PROTO or SOFT_CRYPTO (not vendor sole)
        for r in must:
            self.assertNotEqual(
                r.lane,
                LANE_OPTIONAL_VENDOR,
                msg=f"must_self_impl cannot be optional vendor sole: {r.capability}",
            )

    def test_align_n5_n6_n7_mentioned(self):
        blob = " ".join(r.align for r in BOUNDARY_TABLE)
        for tag in ("N5", "N6", "N7"):
            self.assertIn(tag, blob)

    def test_vdi_launch_not_must_self_impl(self):
        # Match capability only — notes may say "not commercial VDI SDK"
        vdi = [
            r
            for r in BOUNDARY_TABLE
            if "VDI" in r.capability or "uSmartView" in r.capability
        ]
        self.assertTrue(vdi)
        for r in vdi:
            self.assertFalse(r.must_self_impl)
            self.assertEqual(r.lane, LANE_OPTIONAL_VENDOR)


class N8ImportProbeTests(unittest.TestCase):
    def test_static_l_proto_no_vendor_sdk_imports(self):
        for mod in L_PROTO_IMPORT_SAFE:
            pr = probe_module_static(mod)
            self.assertTrue(pr.ok, msg=f"{mod}: {pr.error}")
            self.assertEqual(
                pr.vendor_sdk_hits,
                [],
                msg=f"{mod} vendor hits {pr.vendor_sdk_hits}",
            )

    def test_runtime_l_proto_imports(self):
        # Ensure nest root on path
        probes = probe_l_proto_lane(runtime=True)
        failed = [p for p in probes if not p.ok]
        self.assertEqual(failed, [], msg=str(failed))

    def test_classify_soft_crypto_not_vendor(self):
        cls, note = classify_import_root("Crypto")
        self.assertEqual(cls, "soft_crypto")
        self.assertNotIn("vendor", cls)
        cls2, _ = classify_import_root("json")
        self.assertEqual(cls2, "local_stdlib")

    def test_vendor_binary_optional(self):
        info = vendor_binary_presence()
        self.assertFalse(info.get("required_for_l_proto", True))
        # L-proto still importable regardless of exists flags
        importlib.import_module("l3.spice_handshake")
        importlib.import_module("l3.connectstr_k_session")

    def test_selfcheck_pass(self):
        rep = selfcheck()
        self.assertTrue(rep["l_proto_probe_pass"])
        self.assertIs(rep["production_claim"], False)
        self.assertIs(rep["dual_evidence_ok"], False)
        self.assertEqual(rep["freeze_cite"], FREEZE_CITE)
        self.assertIn("N5", rep["align"])
        self.assertIn("N6", rep["align"])
        self.assertIn("N7", rep["align"])
        self.assertGreaterEqual(len(rep["boundary_table"]), 6)

    def test_false_positive_docstring_vendor_name(self):
        """Mentioning libvdconn in comments/doc is not an SDK import hit."""
        pr = probe_module_static("l3.vdconn_encrypt_with_key")
        self.assertEqual(pr.vendor_sdk_hits, [])
        # notes may explain false-positive string mentions
        self.assertTrue(pr.ok)


class N8NoSdkAsSolePathTests(unittest.TestCase):
    def test_handshake_module_doc_declares_no_sdk(self):
        p = Path(__file__).resolve().parents[1] / "l3" / "spice_handshake.py"
        text = p.read_text(encoding="utf-8")
        self.assertIn("no vendor SDK", text.lower() + " " + text)
        # softer: production_claim=false in head
        self.assertIn("production_claim=false", text)

    def test_pure_session_default_dry_run(self):
        from l3.spice_pure_session import SessionConfig

        cfg = SessionConfig()
        self.assertTrue(cfg.dry_run)

    def test_vdi_launcher_live_denied_by_default(self):
        from l3.vdi_launcher import LiveLaunchDenied, live_start
        from l3.vendor_resolver import resolve

        profile = resolve("CMSSZTE", require_binaries=False)
        with self.assertRaises(LiveLaunchDenied):
            live_start(profile, "cipher-fixture", allow_live=False)


if __name__ == "__main__":
    unittest.main()
