"""Regression tests for the inspector-batch fixes (2026-07-26).

Each test pins one fixed defect so it cannot silently regress.
"""
import os
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
import keepalive  # noqa: E402
import login  # noqa: E402
import login_rate_limit  # noqa: E402
from ecloud_client import EcloudError  # noqa: E402
from l3.gateway_config import (  # noqa: E402
    DEFAULT_CAG_HOST,
    apply_device_gateway_from_clp,
    resolve_gateway,
)


class TestH3ClpWeakHostGuard(unittest.TestCase):
    """H3: a csapip-only / IPv6-only CLP must not overwrite a good region CAG."""

    def test_csapip_only_preserves_strong_cag(self):
        cfg = {
            "cag_host": "36.139.178.146",
            "cag_port": 8899,
            "gateway_source": "device_customLoginParams",
        }
        clp = {
            "csapip": "192.168.1.200:30087",
            "cagList": [{"addr": "2409:8c85::1", "port": 8899, "name": "v6only"}],
        }
        cfg2, gw = apply_device_gateway_from_clp(cfg, clp, only_missing=False)
        self.assertIsNone(gw)
        self.assertEqual(cfg2["cag_host"], "36.139.178.146")

    def test_real_ipv4_clp_still_applies(self):
        cfg = {
            "cag_host": "36.139.178.146",
            "gateway_source": "device_customLoginParams",
        }
        clp = {
            "csapip": "192.168.1.200:30087",
            "cagList": [{"addr": "36.140.1.5", "port": 8899, "name": "v4"}],
        }
        cfg2, gw = apply_device_gateway_from_clp(cfg, clp, only_missing=False)
        self.assertIsNotNone(gw)
        self.assertEqual(cfg2["cag_host"], "36.140.1.5")

    def test_no_good_host_still_allows_default(self):
        # nothing strong to preserve → weak GZ4 may still land (fallback)
        cfg = {}
        clp = {"csapip": "192.168.1.200:30087", "cagList": []}
        cfg2, gw = apply_device_gateway_from_clp(cfg, clp, only_missing=False)
        self.assertIsNotNone(gw)
        self.assertEqual(cfg2["cag_host"], DEFAULT_CAG_HOST)


class TestH2ResolveGatewayCfg(unittest.TestCase):
    """H2: resolve_gateway(cfg=...) uses the in-memory config, not a CWD file."""

    def test_cfg_cag_host_is_used(self):
        for var in ("CAG_HOST", "ECLOUD_CAG_HOST", "CAG_PORT", "ECLOUD_CAG_PORT",
                    "CSAPIP", "ECLOUD_CSAPIP"):
            os.environ.pop(var, None)
        gw = resolve_gateway(
            cfg={"cag_host": "36.140.9.9", "cag_port": 8899, "csapip": "1.2.3.4:30087"},
            try_client_discovery=False,
        )
        self.assertEqual(gw.cag_host, "36.140.9.9")


class TestLoginMissingTicket(unittest.TestCase):
    """MED: OK envelope without accessTicket/errorCode must be FAILED, not SUCCESS."""

    def test_no_ticket_no_error_is_failed(self):
        http = Mock()
        http.post.return_value = {}  # no accessTicket, no errorCode
        r = login.login_with_password(http, "user", "pw")
        self.assertEqual(r["status"], login.LoginResult.FAILED)
        self.assertIsNone(r["access_token"])


class TestRateLimit(unittest.TestCase):
    """MED: guard blocks the (MAX+1)th attempt; the legitimate MAXth is allowed."""

    def setUp(self):
        login_rate_limit.reset_for_tests("rl-user")

    def tearDown(self):
        login_rate_limit.reset_for_tests("rl-user")

    def test_allows_up_to_max_then_blocks(self):
        for _ in range(login_rate_limit.MAX_ATTEMPTS):
            self.assertIsNone(login_rate_limit.guard_login("rl-user"))
        # next attempt is blocked
        self.assertIsNotNone(login_rate_limit.guard_login("rl-user"))

    def test_refuse_branch_marks_not_recorded(self):
        for _ in range(login_rate_limit.MAX_ATTEMPTS):
            login_rate_limit.record_attempt("rl-user")
        st = login_rate_limit.record_attempt("rl-user")  # over max → refused
        self.assertTrue(st["locked"])
        self.assertFalse(st.get("recorded", True))


class TestKeepaliveTristate(unittest.TestCase):
    """MED: keepalive_once returns True/False/None; non-token failures = None."""

    def _http(self, side_effect):
        http = Mock()
        http.post.side_effect = side_effect
        return http

    def test_success_true(self):
        http = self._http(lambda ep, *a, **k: {"ok": True})
        self.assertIs(keepalive.keepalive_once(http), True)

    def test_token_expiry_false(self):
        def se(ep, *a, **k):
            raise EcloudError({"errorCode": "401", "errorMessage": "token expired"})
        self.assertIs(keepalive.keepalive_once(self._http(se)), False)

    def test_all_transient_none(self):
        def se(ep, *a, **k):
            raise EcloudError({"errorCode": "502", "errorMessage": "upstream 502 bad gateway"})
        self.assertIsNone(keepalive.keepalive_once(self._http(se)))


class TestRedqBareSpki(unittest.TestCase):
    """MED: encrypt_with_redq_spki must accept a raw SPKI (0x30 0x82 ...)."""

    def test_bare_spki_encrypts(self):
        from Crypto.PublicKey import RSA

        from l3.redq_ticket_rsa import encrypt_with_redq_spki

        key = RSA.generate(2048)
        spki_der = key.publickey().export_key(format="DER")
        self.assertEqual(spki_der[:2], b"\x30\x82")
        ct = encrypt_with_redq_spki(b"hello-ticket", spki_der)
        self.assertEqual(len(ct), 256)  # RSA-2048 block


class TestH4AccountKeepalivePerWorkerEvent(unittest.TestCase):
    """H4: per-worker Event so an orphaned old worker cannot resurrect / clobber."""

    def _mgr(self):
        from web.keepalive_manager import AccountKeepaliveManager

        return AccountKeepaliveManager()

    def test_orphaned_worker_does_not_clear_running(self):
        m = self._mgr()
        m._running = True
        current_ev = m._stop_event  # belongs to the (newer) live worker
        orphan_ev = threading.Event()
        orphan_ev.set()  # orphan already told to stop
        with patch(
            "web.keepalive_manager.account_keepalive.keepalive_once",
            return_value=True,
        ) as ka_once:
            m._run(Mock(), 1, relogin_fn=None, stop_ev=orphan_ev)
        ka_once.assert_not_called()  # loop exits immediately on a set Event
        self.assertTrue(m._running)  # newer worker's flag untouched
        self.assertIs(m._stop_event, current_ev)

    def test_current_worker_clears_running_on_exit(self):
        m = self._mgr()
        m._running = True
        ev = m._stop_event
        ev.set()
        with patch(
            "web.keepalive_manager.account_keepalive.keepalive_once",
            return_value=True,
        ):
            m._run(Mock(), 1, relogin_fn=None, stop_ev=ev)
        self.assertFalse(m._running)

    def test_start_binds_fresh_event(self):
        m = self._mgr()
        ev_before = m._stop_event
        with patch(
            "web.keepalive_manager.account_keepalive.keepalive_once",
            return_value=True,
        ), patch(
            "web.keepalive_manager.time.sleep",
            side_effect=lambda _s: m._stop_event.set(),
        ):
            self.assertTrue(m.start(Mock(), interval=1, relogin_fn=None))
            if m._thread is not None:
                m._thread.join(timeout=3.0)
        self.assertIsNot(m._stop_event, ev_before)


if __name__ == "__main__":
    unittest.main()
