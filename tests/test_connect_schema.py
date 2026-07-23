"""Unit tests for l3.connect_schema (CMSS/CMSSZTE plain builder)."""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass

from l3.connect_schema import (
    CMSS_ORIGINS,
    FORBIDDEN_SPICE_PLAIN_KEYS,
    ConnectSchemaError,
    build_cmss,
    build_plain,
    build_plain_json,
    redact_plain_for_log,
    supports_origin,
)


class SupportsOriginTests(unittest.TestCase):
    def test_cmss_family(self):
        self.assertTrue(supports_origin("CMSS"))
        self.assertTrue(supports_origin("cmsszte"))
        self.assertTrue(supports_origin("  CMSSZTE "))
        self.assertEqual(CMSS_ORIGINS, frozenset({"CMSS", "CMSSZTE"}))

    def test_others_false(self):
        self.assertFalse(supports_origin("ZTE"))
        self.assertFalse(supports_origin("H3C"))
        self.assertFalse(supports_origin(""))
        self.assertFalse(supports_origin(None))


class BuildPlainCoreTests(unittest.TestCase):
    def test_core_fields_string_socket(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "vm-001",
        }
        plain = build_plain(desktop, None, 15900, timestamp_ms=1700000000123)
        self.assertEqual(plain["vmid"], "vm-001")
        self.assertEqual(plain["socketPort"], "15900")
        self.assertIsInstance(plain["socketPort"], str)
        self.assertEqual(plain["timestamp"], "1700000000123")
        self.assertIsInstance(plain["timestamp"], str)

    def test_machine_id_aliases(self):
        for key, val in (
            ("machineId", "a"),
            ("instanceId", "b"),
            ("desktopId", "c"),
            ("id", "d"),
        ):
            desktop = {"originCompanyCode": "CMSS", key: val}
            plain = build_plain(desktop, socket_port=15901, timestamp_ms=1)
            self.assertEqual(plain["vmid"], val)

    def test_session_overrides_desktop(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "from-desktop",
            "adUser": "desk",
        }
        session = {"machineId": "from-session", "adUser": "sess"}
        plain = build_plain(desktop, session, 15900, timestamp_ms=1)
        self.assertEqual(plain["vmid"], "from-session")
        self.assertEqual(plain["adUser"], "sess")

    def test_is_open_maps_to_vm_start(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "m1",
            "isOpen": 1,
            "isShowCooperate": True,
            "virtualAppParams": {"app": "x"},
        }
        plain = build_plain(desktop, socket_port=15900, timestamp_ms=1)
        self.assertEqual(plain["vm_start"], 1)
        self.assertNotIn("isOpen", plain)
        self.assertTrue(plain["isShowCooperate"])
        self.assertEqual(plain["virtualAppParams"], {"app": "x"})

    def test_optional_cluster_only_if_present(self):
        desktop = {
            "originCompanyCode": "CMSS",
            "machineId": "m1",
            "clientVersion": "3.7.6",
            "isDev": False,  # False must still be written (key present)
        }
        plain = build_plain(desktop, socket_port=15900, timestamp_ms=1)
        self.assertEqual(plain["clientVersion"], "3.7.6")
        self.assertIs(plain["isDev"], False)
        self.assertNotIn("accessTicket", plain)
        self.assertNotIn("watchMode", plain)

    def test_direct_sensitive_fields_pass_through_memory_only(self):
        # Values may exist at runtime; module must not invent them.
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "m1",
            "adUser": "u1",
            "adPassword": "secret-runtime-only",
            "accessTicket": "ticket-runtime",
        }
        plain = build_plain(desktop, socket_port=15900, timestamp_ms=1)
        self.assertEqual(plain["adPassword"], "secret-runtime-only")
        red = redact_plain_for_log(plain)
        self.assertIn("len=", red["adPassword"])
        self.assertNotIn("secret-runtime-only", json.dumps(red))

    def test_no_spice_keys_invented(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "m1",
            "host": "should-not-top-level",
            "password": "spice-pw",
            "port": 5900,
        }
        plain = build_plain(desktop, socket_port=15900, timestamp_ms=1)
        for k in FORBIDDEN_SPICE_PLAIN_KEYS:
            self.assertNotIn(k, plain)

    def test_origin_from_kw_and_snake_case(self):
        desktop = {"origin_company_code": "cmsszte", "machine_id": "mx"}
        plain = build_plain(desktop, socket_port=16000, timestamp_ms=9)
        self.assertEqual(plain["vmid"], "mx")
        self.assertEqual(plain["socketPort"], "16000")

    def test_explicit_origin_kw(self):
        desktop = {"machineId": "m1"}  # no origin on desktop
        plain = build_plain(
            desktop,
            socket_port=15900,
            origin_company_code="CMSS",
            timestamp_ms=1,
        )
        self.assertEqual(plain["vmid"], "m1")


class BuildPlainErrorTests(unittest.TestCase):
    def test_unsupported_vendor(self):
        with self.assertRaises(ConnectSchemaError) as ctx:
            build_plain(
                {"originCompanyCode": "ZTE", "machineId": "m"},
                socket_port=15900,
            )
        self.assertIn("CMSS", str(ctx.exception))

    def test_missing_port(self):
        with self.assertRaises(ConnectSchemaError):
            build_plain({"originCompanyCode": "CMSS", "machineId": "m"})

    def test_missing_vmid(self):
        with self.assertRaises(ConnectSchemaError):
            build_plain({"originCompanyCode": "CMSS"}, socket_port=15900)

    def test_empty_origin(self):
        with self.assertRaises(ConnectSchemaError):
            build_plain({"machineId": "m"}, socket_port=15900)


class AliasAndJsonTests(unittest.TestCase):
    def test_build_cmss_alias(self):
        plain = build_cmss(
            {"originCompanyCode": "CMSSZTE", "machineId": "z"},
            socket_port=15900,
            timestamp_ms=1,
        )
        self.assertEqual(plain["vmid"], "z")

    def test_build_plain_json(self):
        s = build_plain_json(
            {"originCompanyCode": "CMSS", "machineId": "j1"},
            socket_port=15900,
            timestamp_ms=42,
        )
        data = json.loads(s)
        self.assertEqual(data["vmid"], "j1")
        self.assertEqual(data["socketPort"], "15900")
        self.assertNotIn(" ", s)  # compact separators


class DataclassDesktopTests(unittest.TestCase):
    def test_object_desktop(self):
        @dataclass
        class Desk:
            origin_company_code: str = "CMSSZTE"
            machineId: str = "obj-1"
            isOpen: int = 0
            vmName: str = "n1"

        plain = build_plain(Desk(), socket_port=15902, timestamp_ms=1)
        self.assertEqual(plain["vmid"], "obj-1")
        self.assertEqual(plain["vm_start"], 0)
        self.assertEqual(plain["vmName"], "n1")


class HttpProxyTruthyTests(unittest.TestCase):
    def test_falsey_proxy_not_forced(self):
        desktop = {
            "originCompanyCode": "CMSS",
            "machineId": "m",
            "httpProxyParams": {},
        }
        plain = build_plain(desktop, socket_port=1, timestamp_ms=1)
        # empty dict is falsey → second truthy write skipped; first direct copy
        # also skips empty if we only copy when present — empty dict is present
        # Direct keys copy when present and not None: {} is kept.
        self.assertEqual(plain.get("httpProxyParams"), {})

    def test_truthy_proxy(self):
        proxy = {"host": "p", "port": 8080}
        desktop = {
            "originCompanyCode": "CMSS",
            "machineId": "m",
            "httpProxyParams": proxy,
        }
        plain = build_plain(desktop, socket_port=1, timestamp_ms=1)
        self.assertEqual(plain["httpProxyParams"], proxy)


if __name__ == "__main__":
    unittest.main()
