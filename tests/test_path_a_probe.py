"""Offline tests for main.py path-a-probe CLI (no network)."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")


def _run(*extra: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # force offline: empty config path so no token/secrets are loaded
    env["CLOUD_PC_CONFIG_FILE"] = os.path.join(ROOT, ".nonexistent_cloud_pc_for_probe_test.json")
    return subprocess.run(
        [sys.executable, MAIN, "path-a-probe", *extra],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )


class PathAProbeCliTests(unittest.TestCase):
    def test_cmsszte_mock_ok(self):
        r = _run("--origin-company-code", "CMSSZTE", "--skip-binary-check")
        self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
        self.assertIn("vendor_id=CMSSZTE", r.stdout)
        self.assertIn("connect_schema_id=cmsszte", r.stdout)
        self.assertIn("supports_path_a=True", r.stdout)
        self.assertIn("dry-run", r.stdout)
        # no secret-looking dumps
        self.assertNotIn("password", r.stdout.lower())
        self.assertNotIn("access_token", r.stdout.lower())

    def test_zte_not_implemented(self):
        r = _run("--origin-company-code", "ZTE", "--skip-binary-check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("VendorNotImplemented", r.stderr + r.stdout)

    def test_unknown_vendor(self):
        r = _run("--origin-company-code", "NOPE", "--skip-binary-check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("UnknownVendor", r.stderr + r.stdout)

    def test_empty_requires_token_or_origin(self):
        r = _run()
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
