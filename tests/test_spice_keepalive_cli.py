"""Offline tests for main.py spice-keepalive CLI (no network / no live VDI)."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "main.py")


def _run(*extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, MAIN, "spice-keepalive", *extra],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=60,
    )


class TestSpiceKeepaliveCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run(
            [sys.executable, MAIN, "spice-keepalive", "-h"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=30,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("dry-run", r.stdout)
        self.assertIn("i-know-risks", r.stdout)

    def test_dry_run_mock_origin(self):
        r = _run(
            "--dry-run",
            "--origin-company-code",
            "CMSSZTE",
            "--skip-binary-check",
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
        out = r.stdout
        self.assertIn("dry-run", out)
        self.assertIn("origin=CMSSZTE", out)
        self.assertIn("argv_display=", out)
        # No secrets
        self.assertNotIn("access_token", out.lower())
        self.assertNotIn("password", out.lower())
        # Cipher redacted (not raw base64 blob in argv)
        self.assertIn("REDACTED", out)

    def test_unknown_vendor(self):
        r = _run(
            "--dry-run",
            "--origin-company-code",
            "NOPE_VENDOR_XYZ",
            "--skip-binary-check",
        )
        self.assertNotEqual(r.returncode, 0)
        blob = r.stderr + r.stdout
        self.assertTrue(
            "UnknownVendor" in blob or "unknown" in blob.lower(),
            msg=blob,
        )

    def test_live_without_risks_stays_dry(self):
        """Without --i-know-risks, even if user omits --dry-run, stay dry."""
        r = _run(
            "--origin-company-code",
            "CMSSZTE",
            "--skip-binary-check",
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
        self.assertIn("dry-run", r.stdout)
        self.assertNotIn("LIVE (allow_live", r.stdout)


if __name__ == "__main__":
    unittest.main()
