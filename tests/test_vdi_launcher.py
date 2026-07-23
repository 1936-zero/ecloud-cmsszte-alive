"""Unit tests for l3.vdi_launcher (dry-run default; no real VDI)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from l3.vendor_resolver import (
    VendorNotImplemented,
    VendorProfile,
    resolve,
)
from l3.vdi_launcher import (
    LAUNCH_DIRECT_CLIENT,
    LAUNCH_SHELL_WRAPPER,
    MODE_DETECT,
    MODE_JSON,
    REDACTED,
    EmptyCipher,
    InvalidArgvMode,
    InvalidLaunchStyle,
    LaunchPlan,
    LiveLaunchDenied,
    VdiLauncherError,
    argv_for_display,
    build_argv,
    dry_run_plan,
    dry_run_plan_text,
    is_shell_wrapper,
    live_start,
    pick_shell,
    plan_cwd,
    plan_env,
    plan_from_origin,
    redact_cipher,
)


def _cmss_profile() -> VendorProfile:
    return resolve("CMSSZTE", require_binaries=False)


def _profile_with_wrapper(wrapper: str) -> VendorProfile:
    return VendorProfile(
        vendor_id="CMSSZTE",
        service_name="CmssService",
        connect_schema_id="cmss",
        pubkey_slot="privateSetting.SDKSecretKey.publicKey.CMSS",
        vdi_wrapper_path=wrapper,
        vdi_client_path="/opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/CMSS/bin/uSmartView_VDI_Client",
        spice_conf_path=None,
        supports_path_a=True,
    )


class ShellPolicyHelpers(unittest.TestCase):
    def test_is_shell_wrapper_cmss_ascii(self):
        p = _cmss_profile()
        # Real CMSS wrapper is ASCII shell without shebang (P16 ENOEXEC residual)
        if os.path.isfile(p.vdi_wrapper_path):
            self.assertTrue(is_shell_wrapper(p.vdi_wrapper_path))
            # Client is ELF → not shell
            if os.path.isfile(p.vdi_client_path):
                self.assertFalse(is_shell_wrapper(p.vdi_client_path))

    def test_is_shell_wrapper_elf_false(self):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "fake_elf"
            elf.write_bytes(b"\x7fELF" + b"\x00" * 20)
            self.assertFalse(is_shell_wrapper(str(elf)))

    def test_is_shell_wrapper_shebang(self):
        with tempfile.TemporaryDirectory() as td:
            sh = Path(td) / "w.sh"
            sh.write_text("#!/bin/sh\necho hi\n")
            self.assertTrue(is_shell_wrapper(str(sh)))

    def test_pick_shell_exists(self):
        s = pick_shell()
        self.assertTrue(s.startswith("/"))
        self.assertTrue(os.path.isfile(s) or s == "/bin/sh")


class BuildArgvTests(unittest.TestCase):
    def test_cmsszte_json_argv_shell_prefix(self):
        p = _cmss_profile()
        argv = build_argv(p, "CIPHER_ABC", mode="json")
        # Shell-wrapper policy: [shell, wrapper, --json, cipher]
        self.assertEqual(len(argv), 4)
        self.assertIn(argv[0], ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"))
        self.assertEqual(argv[1], p.vdi_wrapper_path)
        self.assertEqual(argv[2], "--json")
        self.assertEqual(argv[3], "CIPHER_ABC")
        self.assertIn("/drivers/CMSS/", argv[1])
        self.assertIn("uSmartView_VDI_exe", argv[1])
        self.assertNotIn("/opt/ZTE", argv[0])
        self.assertNotIn("/opt/ZTE", argv[1])

    def test_elf_wrapper_no_shell_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "uSmartView_VDI_exe"
            elf.write_bytes(b"\x7fELF" + b"\x01" * 32)
            p = _profile_with_wrapper(str(elf))
            argv = build_argv(p, "CIPHER_ABC", mode="json")
            self.assertEqual(len(argv), 3)
            self.assertEqual(argv[0], str(elf))
            self.assertEqual(argv[1], "--json")
            self.assertEqual(argv[2], "CIPHER_ABC")

    def test_detect_mode(self):
        p = _cmss_profile()
        argv = build_argv(p, "X", mode="detect")
        # flag is second-to-last before cipher; with shell prefix index 2
        self.assertEqual(argv[-2], "--detect")
        self.assertEqual(argv[-1], "X")
        argv2 = build_argv(p, "X", mode="--detect")
        self.assertEqual(argv2[-2], "--detect")

    def test_empty_cipher_raises(self):
        p = _cmss_profile()
        with self.assertRaises(EmptyCipher):
            build_argv(p, "")
        with self.assertRaises(EmptyCipher):
            build_argv(p, None)  # type: ignore[arg-type]

    def test_invalid_mode(self):
        p = _cmss_profile()
        with self.assertRaises(InvalidArgvMode):
            build_argv(p, "C", mode="plain")

    def test_unsupported_profile_raises(self):
        stub = VendorProfile(
            vendor_id="ZTE",
            service_name="ZteService",
            connect_schema_id="zte",
            pubkey_slot="privateSetting.SDKSecretKey.publicKey.ZTE",
            vdi_wrapper_path="/opt/ZTE/bin/foo",
            vdi_client_path="/opt/ZTE/bin/bar",
            spice_conf_path=None,
            supports_path_a=False,
        )
        with self.assertRaises(VendorNotImplemented):
            build_argv(stub, "C")

    def test_refuse_opt_zte_wrapper_even_if_flagged(self):
        bad = VendorProfile(
            vendor_id="FAKE",
            service_name="Fake",
            connect_schema_id="fake",
            pubkey_slot="slot",
            vdi_wrapper_path="/opt/ZTE/bin/uSmartView_VDI_exe",
            vdi_client_path="/opt/ZTE/bin/client",
            spice_conf_path=None,
            supports_path_a=True,
        )
        with self.assertRaises(VdiLauncherError):
            build_argv(bad, "C")


class DryRunPlanTests(unittest.TestCase):
    def test_cmsszte_plan_paths(self):
        plan = dry_run_plan("CMSSZTE", cipher="SECRET_CIPHER_VALUE_12345", mode="json")
        self.assertIsInstance(plan, LaunchPlan)
        self.assertTrue(plan.dry_run)
        self.assertEqual(plan.vendor_id, "CMSSZTE")
        self.assertIn("/drivers/CMSS/", plan.wrapper_path)
        self.assertIn("uSmartView_VDI_Client", plan.client_path)
        self.assertNotIn("/opt/ZTE", plan.wrapper_path)
        # shell-prefix: --json at -2, cipher at -1
        self.assertEqual(plan.argv[-2], "--json")
        self.assertEqual(plan.argv[-1], "SECRET_CIPHER_VALUE_12345")
        self.assertEqual(len(plan.argv), 4)
        # display redacts full cipher (auto index after --json)
        self.assertEqual(plan.argv_display[-1], REDACTED)
        text = plan.format_text()
        self.assertNotIn("SECRET_CIPHER_VALUE_12345", text)
        self.assertIn(REDACTED, text)
        self.assertIn("no Popen", text)
        self.assertTrue(any("shell-wrapper" in n for n in plan.notes))
        d = plan.to_dict()
        self.assertNotIn("SECRET_CIPHER_VALUE_12345", str(d))

    def test_plan_text_helper(self):
        t = dry_run_plan_text("CMSSZTE", cipher="FULL_SECRET_XYZ")
        self.assertIn("CMSSZTE", t)
        self.assertNotIn("FULL_SECRET_XYZ", t)

    def test_net_detect_plan(self):
        plan = plan_from_origin("CMSSZTE", net_detect=True, cipher="STUB")
        self.assertEqual(plan.mode, MODE_DETECT)
        self.assertEqual(plan.argv[-2], "--detect")

    def test_zte_negative(self):
        with self.assertRaises(VendorNotImplemented):
            dry_run_plan("ZTE", cipher="C")
        with self.assertRaises(VendorNotImplemented):
            plan_from_origin("ZTE")


class RedactTests(unittest.TestCase):
    def test_redact_default(self):
        self.assertEqual(redact_cipher("abc"), REDACTED)
        self.assertEqual(redact_cipher(None), REDACTED)

    def test_argv_for_display_legacy_len3(self):
        a = argv_for_display(["/w", "--json", "CIPHER"])
        self.assertEqual(a[2], REDACTED)
        self.assertEqual(a[0], "/w")

    def test_argv_for_display_shell_prefix_len4(self):
        a = argv_for_display(["/bin/sh", "/w", "--json", "CIPHER"])
        self.assertEqual(a[3], REDACTED)
        self.assertEqual(a[0], "/bin/sh")
        self.assertEqual(a[2], "--json")


class LiveStartGateTests(unittest.TestCase):
    def test_default_denied_no_popen(self):
        p = _cmss_profile()
        mock_popen = MagicMock()
        with self.assertRaises(LiveLaunchDenied):
            live_start(p, "C", allow_live=False, popen_func=mock_popen)
        mock_popen.assert_not_called()

    def test_allow_live_uses_popen_once_shell_prefix(self):
        p = _cmss_profile()
        mock_proc = MagicMock()
        mock_proc.pid = 4242
        mock_popen = MagicMock(return_value=mock_proc)
        res = live_start(p, "CIPHER", allow_live=True, popen_func=mock_popen)
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        argv = args[0]
        self.assertEqual(len(argv), 4)
        self.assertIn(argv[0], ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"))
        self.assertEqual(argv[1], p.vdi_wrapper_path)
        self.assertEqual(argv[2], "--json")
        self.assertEqual(argv[3], "CIPHER")
        self.assertEqual(res.pid, 4242)
        self.assertTrue(res.allow_live)

    def test_default_tests_never_touch_subprocess(self):
        # dry path must not import-call real Popen
        with patch("l3.vdi_launcher.subprocess.Popen") as popen:
            dry_run_plan("CMSSZTE", cipher="STUB")
            build_argv(_cmss_profile(), "STUB", mode=MODE_JSON)
            dry_run_plan("CMSSZTE", cipher="STUB", launch_style=LAUNCH_DIRECT_CLIENT)
            build_argv(
                _cmss_profile(), "STUB", mode=MODE_JSON, launch_style=LAUNCH_DIRECT_CLIENT
            )
            popen.assert_not_called()


class DirectClientLaunchStyleTests(unittest.TestCase):
    """P18-B: launch_style=direct_client argv0=ELF Client + cwd/env."""

    def test_default_style_remains_shell_wrapper(self):
        p = _cmss_profile()
        argv = build_argv(p, "STUB")
        self.assertIn(argv[0], ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"))
        self.assertEqual(argv[1], p.vdi_wrapper_path)
        plan = dry_run_plan(p, "STUB")
        self.assertEqual(plan.launch_style, LAUNCH_SHELL_WRAPPER)
        # shell-wrapper: cwd None (wrapper cds); no forced LD_LIBRARY_PATH delta
        self.assertIsNone(plan.cwd)
        self.assertEqual(plan.env, {})

    def test_direct_client_argv_shape(self):
        p = _cmss_profile()
        argv = build_argv(p, "CIPHER_X", mode=MODE_JSON, launch_style=LAUNCH_DIRECT_CLIENT)
        self.assertEqual(len(argv), 3)
        self.assertEqual(argv[0], p.vdi_client_path)
        self.assertEqual(argv[1], "--json")
        self.assertEqual(argv[2], "CIPHER_X")
        # no shell, no wrapper, no sudo
        for a in argv:
            self.assertNotIn("sudo", a.lower() if isinstance(a, str) else "")
        self.assertNotEqual(argv[0], p.vdi_wrapper_path)
        self.assertFalse(argv[0].endswith("uSmartView_VDI_exe"))

    def test_direct_client_detect_flag(self):
        p = _cmss_profile()
        argv = build_argv(p, "C", mode=MODE_DETECT, launch_style="direct_client")
        self.assertEqual(argv[1], "--detect")
        self.assertEqual(argv[0], p.vdi_client_path)

    def test_direct_client_cwd_and_ld_library_path(self):
        p = _cmss_profile()
        cwd = plan_cwd(p, LAUNCH_DIRECT_CLIENT)
        env = plan_env(p, LAUNCH_DIRECT_CLIENT)
        self.assertEqual(cwd, os.path.dirname(p.vdi_client_path))
        self.assertTrue(cwd.endswith("/CMSS/bin") or cwd.endswith("CMSS/bin"))
        self.assertIn("LD_LIBRARY_PATH", env)
        self.assertTrue(env["LD_LIBRARY_PATH"].endswith("/CMSS/lib") or "/CMSS/lib" in env["LD_LIBRARY_PATH"])
        # lib path is sibling of bin under CMSS
        bin_dir = os.path.dirname(p.vdi_client_path)
        cmss_root = os.path.dirname(bin_dir)
        self.assertEqual(env["LD_LIBRARY_PATH"].split(os.pathsep)[0], os.path.join(cmss_root, "lib"))

    def test_direct_client_dry_run_plan_fields(self):
        p = _cmss_profile()
        plan = dry_run_plan(p, "SECRET_DIRECT_CIPHER", launch_style=LAUNCH_DIRECT_CLIENT)
        self.assertEqual(plan.launch_style, LAUNCH_DIRECT_CLIENT)
        self.assertEqual(plan.argv[0], p.vdi_client_path)
        self.assertEqual(plan.argv_display[-1], REDACTED)
        self.assertNotIn("SECRET_DIRECT_CIPHER", plan.format_text())
        self.assertNotIn("SECRET_DIRECT_CIPHER", str(plan.to_dict()))
        self.assertEqual(plan.cwd, plan_cwd(p, LAUNCH_DIRECT_CLIENT))
        self.assertEqual(plan.env.get("LD_LIBRARY_PATH"), plan_env(p, LAUNCH_DIRECT_CLIENT)["LD_LIBRARY_PATH"])
        self.assertTrue(any("direct_client" in n for n in plan.notes))
        d = plan.to_dict()
        self.assertEqual(d["launch_style"], LAUNCH_DIRECT_CLIENT)
        self.assertEqual(d["cwd"], plan.cwd)

    def test_direct_client_live_start_applies_cwd_env(self):
        p = _cmss_profile()
        mock_proc = MagicMock()
        mock_proc.pid = 7777
        mock_popen = MagicMock(return_value=mock_proc)
        res = live_start(
            p,
            "CIPHER",
            allow_live=True,
            popen_func=mock_popen,
            launch_style=LAUNCH_DIRECT_CLIENT,
        )
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        argv = args[0]
        self.assertEqual(argv[0], p.vdi_client_path)
        self.assertEqual(len(argv), 3)
        self.assertEqual(kwargs.get("cwd"), plan_cwd(p, LAUNCH_DIRECT_CLIENT))
        child_env = kwargs.get("env") or {}
        expected_lib = plan_env(p, LAUNCH_DIRECT_CLIENT)["LD_LIBRARY_PATH"]
        self.assertTrue(
            child_env.get("LD_LIBRARY_PATH", "").startswith(expected_lib)
            or expected_lib in child_env.get("LD_LIBRARY_PATH", "")
        )
        self.assertEqual(res.pid, 7777)

    def test_invalid_launch_style(self):
        p = _cmss_profile()
        with self.assertRaises(InvalidLaunchStyle):
            build_argv(p, "C", launch_style="bogus_style")

    def test_alias_direct(self):
        p = _cmss_profile()
        argv = build_argv(p, "C", launch_style="direct")
        self.assertEqual(argv[0], p.vdi_client_path)

    def test_direct_client_missing_client_path(self):
        p = VendorProfile(
            vendor_id="CMSSZTE",
            service_name="CmssService",
            connect_schema_id="cmss",
            pubkey_slot="privateSetting.SDKSecretKey.publicKey.CMSS",
            vdi_wrapper_path="/tmp/w",
            vdi_client_path="",
            spice_conf_path=None,
            supports_path_a=True,
        )
        with self.assertRaises(VdiLauncherError):
            build_argv(p, "C", launch_style=LAUNCH_DIRECT_CLIENT)


if __name__ == "__main__":
    unittest.main()
