"""Unit tests for #75fixam login rate limit (10min / 3 attempts)."""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path


class LoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.path = Path(self._td.name) / "login_rate_limit.json"
        os.environ["ECLOUD_LOGIN_RATE_LIMIT_FILE"] = str(self.path)
        # reload module state against temp file
        import login_rate_limit as m

        m.reset_for_tests()
        # force re-bind path
        m._loaded_path = None
        m._state.clear()
        self.m = m

    def tearDown(self):
        try:
            self.m.reset_for_tests()
        except Exception:
            pass
        self._td.cleanup()
        os.environ.pop("ECLOUD_LOGIN_RATE_LIMIT_FILE", None)

    def test_three_allowed_fourth_locked(self):
        u = "user_a"
        self.assertIsNone(self.m.guard_login(u))
        self.assertIsNone(self.m.guard_login(u))
        self.assertIsNone(self.m.guard_login(u))
        err = self.m.guard_login(u)
        self.assertIsNotNone(err)
        self.assertEqual(err.get("status"), "locked")
        self.assertTrue(err.get("locked"))
        self.assertIn("锁定", err.get("error") or "")

    def test_window_prunes(self):
        u = "user_b"
        # backdate three attempts outside window
        now = time.time()
        with self.m._lock:
            self.m._state[u] = [now - 700, now - 650, now - 620]
            self.m._save_unlocked(self.m._path())
        # should allow again
        self.assertIsNone(self.m.guard_login(u))

    def test_normalize_strip(self):
        self.assertIsNone(self.m.guard_login("  u1  "))
        st = self.m.status("u1")
        self.assertEqual(st["count"], 1)


if __name__ == "__main__":
    unittest.main()
