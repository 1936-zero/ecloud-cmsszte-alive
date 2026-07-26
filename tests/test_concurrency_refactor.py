"""Tests for the concurrency-refactor branch (deferred WebUI items)."""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
