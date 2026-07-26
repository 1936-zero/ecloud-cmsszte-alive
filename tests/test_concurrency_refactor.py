"""Tests for the concurrency-refactor branch (deferred WebUI items)."""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from keepalive import KeepaliveOutcome

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeRegistry:
    def __init__(self, root: Path):
        self.root = root

    def append_global_log(self, *a, **k):
        pass


def _make_account():
    from web.account_runtime import AccountRuntime

    tmp = Path(tempfile.mkdtemp(prefix="acct_"))
    acc = AccountRuntime(_FakeRegistry(tmp), {"id": "t", "label": "t"})
    with acc._lock:
        acc._cfg = {"username": "u", "password": "p", "access_token": "old"}
    return acc


class TestReloginCoalesce(unittest.TestCase):
    """#2: concurrent relogins collapse to a single password login."""

    def test_concurrent_relogin_calls_login_once(self):
        acc = _make_account()
        gate = threading.Event()
        calls = []

        def fake_login(u, p, quiet=False):
            calls.append(1)
            gate.wait(timeout=5)
            with acc._lock:
                acc._cfg["access_token"] = "new"
            return {"status": "success", "access_token": "new"}

        acc.login = fake_login
        results = {}

        def worker(name):
            results[name] = acc.relogin()

        ta = threading.Thread(target=worker, args=("a",))
        ta.start()
        # wait until A is inside login (holding _relogin_lock)
        for _ in range(200):
            if calls:
                break
            time.sleep(0.01)
        self.assertEqual(len(calls), 1)

        tb = threading.Thread(target=worker, args=("b",))
        tb.start()
        time.sleep(0.15)  # let B block on _relogin_lock
        gate.set()
        ta.join(timeout=5)
        tb.join(timeout=5)

        self.assertEqual(len(calls), 1, "second relogin should coalesce, not re-login")
        self.assertEqual(results.get("a"), "new")
        self.assertEqual(results.get("b"), "new")


class TestAsyncStartKeepalive(unittest.TestCase):
    """#1: keepalive/start returns immediately; power-on runs in background."""

    def test_start_is_nonblocking_and_reports_starting(self):
        acc = _make_account()
        with acc._lock:
            acc._cfg = {
                "username": "u", "password": "p", "access_token": "tok",
                "instance_id": "CCA-1",
            }
        gate = threading.Event()
        body_done = threading.Event()

        def fake_body(instance_id="", machine_id="", interval=300):
            gate.wait(timeout=5)
            body_done.set()
            return {"ok": True}

        acc._start_keepalive_body = fake_body

        t0 = time.time()
        res = acc.start_keepalive(instance_id="CCA-1", interval=300)
        elapsed = time.time() - t0

        self.assertLess(elapsed, 1.0, "request must not block on power-on/preflight")
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("status"), "starting")
        self.assertTrue(acc.public_meta().get("starting"))

        # second start while starting is rejected by the reentrancy guard
        res2 = acc.start_keepalive(instance_id="CCA-1", interval=300)
        self.assertFalse(res2.get("ok"))

        gate.set()
        self.assertTrue(body_done.wait(timeout=5))
        for _ in range(200):
            if not acc.public_meta().get("starting"):
                break
            time.sleep(0.01)
        self.assertFalse(acc.public_meta().get("starting"))


class TestWebUiKeepaliveTristate(unittest.TestCase):
    """WebUI account keepalive honours keepalive_once's tri-state."""

    def _manager(self):
        from web.keepalive_manager import AccountKeepaliveManager

        m = AccountKeepaliveManager()
        m._running = True
        return m

    def test_transient_none_does_not_relogin(self):
        """None (all-fail, non-token) -> retry next round, NO password relogin;
        the real server error is surfaced into the account log."""
        m = self._manager()
        relogin = Mock(return_value="tok")
        with patch(
            "web.keepalive_manager.account_keepalive.keepalive_probe",
            return_value=KeepaliveOutcome(ok=None, error="[502] bad gateway"),
        ) as ka_probe, patch(
            "web.keepalive_manager.time.sleep",
            side_effect=lambda _s: m._stop_event.set(),
        ):
            m._run(Mock(), 1, relogin)
        ka_probe.assert_called_once()
        relogin.assert_not_called()
        self.assertIn("502", m._last_error)  # real error surfaced, not generic

    def test_token_expiry_false_still_relogins(self):
        """False (real token expiry) -> relogin + refresh token, then retry."""
        m = self._manager()
        fake_http = Mock()
        relogin = Mock(return_value="fresh-token")
        with patch(
            "web.keepalive_manager.account_keepalive.keepalive_probe",
            side_effect=[KeepaliveOutcome(ok=False, error="[401] 登录已过期"), KeepaliveOutcome(ok=True)],
        ) as ka_probe, patch(
            "web.keepalive_manager.time.sleep",
            side_effect=lambda _s: m._stop_event.set(),
        ):
            m._run(fake_http, 1, relogin)
        self.assertEqual(ka_probe.call_count, 2)
        relogin.assert_called_once()
        fake_http.set_token.assert_called_once_with("fresh-token")


class TestKeepaliveAutoResume(unittest.TestCase):
    """Persist keepalive_desired + resume it on WebUI startup."""

    def test_start_keepalive_persists_desired(self):
        import json

        acc = _make_account()
        with acc._lock:
            acc._cfg = {
                "username": "u", "password": "p",
                "access_token": "tok", "instance_id": "CCA-1",
            }
        acc._start_keepalive_body = lambda **k: {"ok": True}  # no real network
        res = acc.start_keepalive(instance_id="CCA-1", interval=300)
        self.assertTrue(res.get("ok"))
        self.assertTrue(acc._cfg.get("keepalive_desired"))
        self.assertTrue(json.load(open(acc.config_path))["keepalive_desired"])

    def test_stop_keepalive_clears_desired(self):
        import json

        acc = _make_account()
        with acc._lock:
            acc._cfg = {"keepalive_desired": True, "access_token": "tok"}
            acc._save_cfg()
        acc.stop_keepalive()
        self.assertFalse(acc._cfg.get("keepalive_desired"))
        self.assertFalse(json.load(open(acc.config_path))["keepalive_desired"])

    def test_resume_only_desired_and_logged_in(self):
        from web.account_runtime import AccountRegistry

        reg = AccountRegistry(root=Path(tempfile.mkdtemp(prefix="reg_")))
        reg.create(label="a1", username="15700000001", password="p")
        reg.create(label="a2", username="15700000002", password="p")
        reg.create(label="a3", username="15700000003", password="p")
        accs = list(reg._accounts.values())
        a1, a2, a3 = accs[0], accs[1], accs[2]
        with a1._lock:  # desired + logged in -> resume
            a1._cfg.update({"keepalive_desired": True, "access_token": "tok", "instance_id": "CCA-1"})
        with a2._lock:  # not desired -> skip
            a2._cfg.update({"keepalive_desired": False, "access_token": "tok"})
        with a3._lock:  # desired but NOT logged in -> skip
            a3._cfg.update({"keepalive_desired": True})
            a3._cfg.pop("access_token", None)
        for a in (a1, a2, a3):
            a.start_keepalive = Mock(return_value={"ok": True, "status": "starting"})
            a.start_account_keepalive = Mock(return_value={"ok": True})

        n = reg.resume_desired_keepalive()

        self.assertEqual(n, 1)
        a1.start_keepalive.assert_called_once()
        a2.start_keepalive.assert_not_called()
        a3.start_keepalive.assert_not_called()


if __name__ == "__main__":
    unittest.main()
