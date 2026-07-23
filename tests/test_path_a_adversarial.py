"""Adversarial / negative dry-pipeline suite for Path A (P8-B).

Dry-only: no live VDI, no PEM material, no secrets in assertions/logs.
Covers reject edges across vendor_resolver, connect_schema, rsa_connect,
vdi_launcher, path_a_session, longtest_runner.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from l3.connect_schema import (
    FORBIDDEN_SPICE_PLAIN_KEYS,
    ConnectSchemaError,
    build_plain,
    redact_plain_for_log,
)
from l3.longtest_runner import (
    GATE_FAIL,
    GATE_PASS,
    GATE_WEAK,
    Sample,
    run_sim,
    score_samples,
)
from l3.path_a_session import PathASession
from l3.rsa_connect import (
    DRY_STUB_PREFIX,
    RsaConnectError,
    encrypt_connect_params,
    encrypt_plain,
)
from l3.vendor_resolver import (
    UnknownVendor,
    VendorNotImplemented,
    resolve,
)
from l3.vdi_launcher import (
    REDACTED,
    EmptyCipher,
    InvalidArgvMode,
    LiveLaunchDenied,
    argv_for_display,
    build_argv,
    dry_run_plan,
    live_start,
)


_INJECT_CIPHER = (
    "STUB; rm -rf /; echo $(whoami) `id` && cat /etc/passwd\n"
    "--help\0injected"
)


class VendorRejectTests(unittest.TestCase):
    """origin / vendor gate negatives."""

    def test_unknown_origin_rejected(self):
        with self.assertRaises(UnknownVendor):
            resolve("", require_binaries=False)
        with self.assertRaises(UnknownVendor):
            resolve("NOT_A_VENDOR", require_binaries=False)

    def test_known_but_unimplemented_origins_raise(self):
        for origin in ("ZTE", "ZTEECLOUD", "H3C", "INSPUR"):
            with self.subTest(origin=origin):
                with self.assertRaises(VendorNotImplemented):
                    resolve(origin, require_binaries=False)

    def test_path_a_session_prepare_rejects_zte(self):
        sess = PathASession(origin_company_code="ZTE", machine_id="adv-zte")
        with self.assertRaises(VendorNotImplemented):
            sess.prepare()


class ConnectSchemaNegativeTests(unittest.TestCase):
    """schema rejects + no spice invention."""

    def test_missing_vmid_raises(self):
        with self.assertRaises(ConnectSchemaError):
            build_plain(
                {"originCompanyCode": "CMSSZTE"},
                socket_port=15900,
                timestamp_ms=1,
            )

    def test_unsupported_origin_raises(self):
        with self.assertRaises(ConnectSchemaError):
            build_plain(
                {
                    "originCompanyCode": "H3C",
                    "machineId": "m-h3c",
                },
                socket_port=15900,
                timestamp_ms=1,
            )

    def test_spice_keys_not_invented_from_desktop(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "m-spice",
            "host": "evil.example",
            "hostip": "10.0.0.1",
            "port": 5900,
            "tls-port": 5901,
            "password": "spice-pw-must-not-top-level",
            "publicKey": "PEM-MUST-NOT-LEAK",
            "vm-proxy-port": 1234,
        }
        plain = build_plain(desktop, socket_port=15901, timestamp_ms=42)
        for bad in FORBIDDEN_SPICE_PLAIN_KEYS:
            self.assertNotIn(bad, plain)
        self.assertEqual(plain["vmid"], "m-spice")
        self.assertEqual(str(plain["socketPort"]), "15901")

    def test_redact_plain_masks_secrets(self):
        plain = build_plain(
            {
                "originCompanyCode": "CMSSZTE",
                "machineId": "m-sec",
                "adPassword": "super-secret-pass-NEVER",
                "accessTicket": "ticket-SECRET-xyz",
            },
            socket_port=15902,
            timestamp_ms=7,
        )
        red = redact_plain_for_log(plain)
        blob = json.dumps(red, ensure_ascii=False)
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("ticket-SECRET", blob)
        self.assertIn("redacted", blob.lower())


class RsaStubNegativeTests(unittest.TestCase):
    """RSA dry/stub edges — no PEM committed."""

    def test_dry_run_stub_prefix_and_empty_plain(self):
        c_empty = encrypt_plain("", dry_run=True)
        c_body = encrypt_plain('{"vmid":"x"}', dry_run=True)
        self.assertTrue(c_empty.startswith(DRY_STUB_PREFIX))
        self.assertTrue(c_body.startswith(DRY_STUB_PREFIX))
        self.assertNotEqual(c_empty, c_body)

    def test_missing_pubkey_path_falls_to_stub(self):
        c = encrypt_plain("payload", pubkey_path=None, dry_run=False)
        self.assertTrue(c.startswith(DRY_STUB_PREFIX))
        c2 = encrypt_plain(
            "payload",
            pubkey_path="/no/such/pubkey-adversarial.pem",
            dry_run=False,
        )
        self.assertTrue(c2.startswith(DRY_STUB_PREFIX))

    def test_invalid_pem_material_raises(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "not_a_key.pem"
            bad.write_text("this is not a PUBLIC KEY file\n", encoding="utf-8")
            with self.assertRaises(RsaConnectError):
                encrypt_plain("payload", pubkey_path=str(bad), dry_run=False)

    def test_encrypt_connect_params_dry_with_profile(self):
        profile = resolve("CMSSZTE", require_binaries=False)
        c = encrypt_connect_params(
            '{"vmid":"m"}',
            profile,
            dry_run=True,
        )
        self.assertTrue(c.startswith(DRY_STUB_PREFIX))


class VdiLauncherNegativeTests(unittest.TestCase):
    """argv injection + live gate + empty cipher."""

    def _profile(self):
        return resolve("CMSSZTE", require_binaries=False)

    def test_empty_cipher_rejected(self):
        p = self._profile()
        with self.assertRaises(EmptyCipher):
            build_argv(p, "")
        with self.assertRaises(EmptyCipher):
            build_argv(p, None)  # type: ignore[arg-type]

    def test_invalid_mode_rejected(self):
        p = self._profile()
        with self.assertRaises(InvalidArgvMode):
            build_argv(p, "CIPHER", mode="exec")
        with self.assertRaises(InvalidArgvMode):
            build_argv(p, "CIPHER", mode="--shell")

    def test_injection_chars_stay_single_argv_element(self):
        p = self._profile()
        argv = build_argv(p, _INJECT_CIPHER, mode="json")
        # shell_wrapper (default/P17): [shell, wrapper, --json|--detect, cipher] → len 4
        # direct_client: [client, --json|--detect, cipher] → len 3
        self.assertIn(len(argv), (3, 4))
        self.assertEqual(argv[-2], "--json")
        # metacharacters must NOT split into extra argv slots — cipher is one trailing element
        self.assertEqual(argv[-1], _INJECT_CIPHER)
        self.assertEqual(sum(1 for a in argv if a == _INJECT_CIPHER), 1)
        # display never leaks full cipher
        disp = argv_for_display(argv)
        self.assertEqual(disp[-1], REDACTED)

    def test_live_start_default_denied_no_popen(self):
        p = self._profile()
        mock_popen = MagicMock()
        with self.assertRaises(LiveLaunchDenied):
            live_start(p, "CIPHER", allow_live=False, popen_func=mock_popen)
        mock_popen.assert_not_called()

    def test_dry_run_plan_never_live(self):
        plan = dry_run_plan(
            self._profile(),
            cipher=_INJECT_CIPHER,
            mode="json",
            require_binaries=False,
            origin="CMSSZTE",
        )
        d = plan.to_dict() if hasattr(plan, "to_dict") else dict(plan)
        # Live must stay false; cipher redacted in display fields
        blob = json.dumps(d, default=str)
        self.assertNotIn("whoami", blob)
        self.assertIn(REDACTED, blob)


class PathAPipelineAdversarialTests(unittest.TestCase):
    """end-to-end dry pipeline under hostile desktop inputs."""

    def test_unprepared_connect_json_raises(self):
        sess = PathASession(origin_company_code="CMSSZTE", machine_id="adv-u")
        with self.assertRaises(RuntimeError):
            sess.connect_json_socket_fields()

    def test_dry_pipeline_hostile_desktop_redacts_and_no_live(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "machineId": "adv-hostile-1",
            "adPassword": "super-secret-pass-NEVER",
            "accessTicket": "ticket-SECRET-xyz",
            "password": "spice-pw-should-strip",
            "host": "evil-host.example",
            "port": 5900,
            "publicKey": "BEGIN PUBLIC KEY FAKE",
        }
        sess = PathASession(
            origin_company_code="CMSSZTE",
            machine_id="adv-hostile-1",
            start_port=30200,
        )
        try:
            plan = sess.dry_run_pipeline(desktop=desktop, rsa_dry_run=True)
        finally:
            sess.stop()

        blob = json.dumps(plan, default=str)
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("ticket-SECRET", blob)
        self.assertNotIn("spice-pw", blob)
        self.assertNotIn("BEGIN PUBLIC KEY", blob)
        self.assertFalse(plan["live_vdi"])
        self.assertTrue(plan["rsa"]["cipher_is_stub"])
        self.assertEqual(plan["rsa"]["cipher_display"], REDACTED)
        self.assertFalse(plan["heart_auto_reply"])
        plain_r = plan["plain_redacted"]
        for bad in ("host", "port", "password", "publicKey"):
            self.assertNotIn(bad, plain_r)

    def test_dry_pipeline_rejects_non_path_a_origin(self):
        sess = PathASession(origin_company_code="H3C", machine_id="adv-h3c")
        with self.assertRaises(VendorNotImplemented):
            sess.dry_run_pipeline(
                desktop={"originCompanyCode": "H3C", "machineId": "adv-h3c"},
                rsa_dry_run=True,
            )


class LongtestHonestyTests(unittest.TestCase):
    """production_claim always false; weird scenarios honest."""

    def test_all_scenarios_production_claim_false(self):
        root = Path(".")
        scenarios = (
            "l3_pass",
            "l3_weak",
            "l3_fail_biz",
            "l3_fail_proto",
            "l2_only",
        )
        for sc in scenarios:
            with self.subTest(scenario=sc):
                result, _, _ = run_sim(
                    nest_root=root, tier="S0", scenario=sc, write=False
                )
                self.assertIs(result.production_claim, False)
                self.assertIn(
                    result.gate, (GATE_PASS, GATE_WEAK, GATE_FAIL)
                )

    def test_unknown_scenario_raises(self):
        with self.assertRaises(ValueError):
            run_sim(
                nest_root=Path("."),
                tier="S0",
                scenario="adversarial_unknown",
                write=False,
            )

    def test_empty_samples_fail_no_production_claim(self):
        r = score_samples([], tier="S0", mode="sim")
        self.assertEqual(r.gate, GATE_FAIL)
        self.assertIs(r.production_claim, False)

    def test_l2_only_never_pass_as_l3(self):
        # pure L2 uptime samples must not score L3 PASS
        samples = [
            Sample(
                t_s=i * 60,
                arm="l2_only",
                resource_status="available",
                desktop_uptime_s=3600 + i * 60,
                process_alive=True,
                protocol_signal=False,
                spice_hold=False,
                heart_type1=False,
                notes="l2_only_baseline",
            )
            for i in range(5)
        ]
        r = score_samples(samples, tier="S0", mode="sim")
        self.assertNotEqual(r.gate, GATE_PASS)
        self.assertIs(r.production_claim, False)


if __name__ == "__main__":
    unittest.main()
