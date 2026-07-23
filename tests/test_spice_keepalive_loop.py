"""N7 offline tests: PY_KEEPALIVE_LOOP.

production_claim=false
- reconnect + exponential backoff
- heartbeat via N5 skeleton (default ≥3 rounds)
- N6 SLOT_SESSION_KEY / SLOT_PROP0X14 bind surface
- key_provider inject / MissingKeyError explainable
- residual26 hook surface
- no vendor SDK import
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class TestImportsNoSDK(unittest.TestCase):
    def test_module_imports(self):
        m = importlib.import_module("l3.spice_keepalive_loop")
        self.assertFalse(getattr(m, "production_claim", False))
        src_path = os.path.join(ROOT, "l3", "spice_keepalive_loop.py")
        with open(src_path, encoding="utf-8") as f:
            src = f.read()
        bans = [
            "spice-client" + "-glib",
            "ctypes" + "." + "CDLL",
            "cdll" + "." + "LoadLibrary",
        ]
        for ban in bans:
            self.assertNotIn(ban, src)
        import re
        self.assertIsNone(re.search(r"^\s*(import|from)\s+\S*" + "uSmart", src, re.M))

    def test_no_sdk_in_handshake_deps(self):
        # transitive pure-python surface from N5
        for mod in ("l3.spice_handshake", "l3.key_provider", "l3.spice_keepalive_loop"):
            importlib.import_module(mod)


class TestMissingKey(unittest.TestCase):
    def test_null_provider_stops_early(self):
        from l3.key_provider import NullKeyProvider
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        r = SpiceKeepaliveLoop(
            NullKeyProvider(), KeepaliveConfig(max_attempts=5)
        ).run_offline()
        self.assertFalse(r.ok)
        self.assertEqual(r.sessions_ok, 0)
        self.assertEqual(len(r.attempts), 1)
        self.assertEqual(r.attempts[0].error["error"], "MissingKeyError")
        self.assertFalse(r.production_claim)
        self.assertFalse(r.as_dict()["production_claim"])


class TestGreenPath(unittest.TestCase):
    def _kp(self):
        from l3.key_provider import (
            SLOT_PROP0X14,
            SLOT_SESSION_KEY,
            SLOT_TICKET,
            DictKeyProvider,
        )

        return DictKeyProvider(
            {
                SLOT_TICKET: b"\xaa" * 16,
                SLOT_SESSION_KEY: b"\x11" * 16,
                SLOT_PROP0X14: b"\x14" * 8,
            }
        )

    def test_default_heart_rounds_ge_3(self):
        from l3.spice_keepalive_loop import KeepaliveConfig

        self.assertGreaterEqual(KeepaliveConfig().max_heart_rounds, 3)
        self.assertTrue(KeepaliveConfig().bind_n6_slots)

    def test_green_default_three_hearts(self):
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        r = SpiceKeepaliveLoop(
            self._kp(),
            KeepaliveConfig(max_attempts=1, max_success_sessions=1),
        ).run_offline()
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.sessions_ok, 1)
        self.assertEqual(r.total_c49, 3)
        self.assertEqual(r.total_agent_hb, 3)
        self.assertEqual(r.total_s53, 3)
        self.assertFalse(r.production_claim)

    def test_n6_slots_bound(self):
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        r = SpiceKeepaliveLoop(
            self._kp(),
            KeepaliveConfig(max_attempts=1, max_heart_rounds=1, send_agent_hb=False),
        ).run_offline()
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.total_session_key_bound, 1)
        self.assertEqual(r.total_prop0x14_bound, 1)
        self.assertIsNotNone(r.last_n6_bind)
        self.assertTrue(r.last_n6_bind["session_key_present"])
        self.assertTrue(r.last_n6_bind["prop0x14_present"])
        self.assertEqual(r.last_n6_bind["session_key_len"], 16)
        self.assertEqual(r.last_n6_bind["prop0x14_len"], 8)
        # no raw secrets in as_dict
        blob = str(r.as_dict())
        self.assertNotIn("\\x11" * 4, blob)

    def test_green_custom_heart_rounds(self):
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        r = SpiceKeepaliveLoop(
            self._kp(),
            KeepaliveConfig(
                max_attempts=1,
                max_success_sessions=1,
                max_heart_rounds=2,
            ),
        ).run_offline()
        self.assertTrue(r.ok)
        self.assertEqual(r.total_c49, 2)
        self.assertEqual(r.total_agent_hb, 2)

    def test_bind_n6_slots_false_skips(self):
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        r = SpiceKeepaliveLoop(
            self._kp(),
            KeepaliveConfig(
                max_attempts=1,
                max_heart_rounds=1,
                send_agent_hb=False,
                bind_n6_slots=False,
            ),
        ).run_offline()
        self.assertTrue(r.ok)
        # skeleton still may record zeros when bind disabled
        self.assertEqual(r.total_session_key_bound, 0)
        self.assertEqual(r.total_prop0x14_bound, 0)


class TestReconnectBackoff(unittest.TestCase):
    def test_reconnect_after_fails(self):
        from l3.key_provider import SLOT_TICKET, DictKeyProvider
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        kp = DictKeyProvider({SLOT_TICKET: b"\xcc" * 8})
        r = SpiceKeepaliveLoop(
            kp,
            KeepaliveConfig(
                max_attempts=4,
                max_success_sessions=1,
                max_heart_rounds=1,
                send_agent_hb=False,
                simulate_fail_attempts=(1, 2),
                backoff_base_s=0.01,
                backoff_factor=2.0,
                backoff_max_s=0.1,
                real_sleep=False,
            ),
        ).run_offline()
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.sessions_ok, 1)
        self.assertEqual(len(r.attempts), 3)
        self.assertFalse(r.attempts[0].ok)
        self.assertFalse(r.attempts[1].ok)
        self.assertTrue(r.attempts[2].ok)
        self.assertAlmostEqual(r.total_backoff_s, 0.03)
        self.assertEqual(r.attempts[0].backoff_s, 0.01)
        self.assertEqual(r.attempts[1].backoff_s, 0.02)
        self.assertEqual(r.attempts[2].backoff_s, 0.0)

    def test_backoff_capped(self):
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        loop = SpiceKeepaliveLoop(
            config=KeepaliveConfig(
                backoff_base_s=1.0, backoff_factor=10.0, backoff_max_s=2.5
            )
        )
        self.assertEqual(loop._backoff_for(0), 1.0)
        self.assertEqual(loop._backoff_for(1), 2.5)  # capped
        self.assertEqual(loop._backoff_for(5), 2.5)

    def test_all_fails_not_ok(self):
        from l3.key_provider import SLOT_TICKET, DictKeyProvider
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        kp = DictKeyProvider({SLOT_TICKET: b"\xee" * 8})
        r = SpiceKeepaliveLoop(
            kp,
            KeepaliveConfig(
                max_attempts=3,
                max_success_sessions=1,
                simulate_fail_attempts=(1, 2, 3),
                real_sleep=False,
            ),
        ).run_offline()
        self.assertFalse(r.ok)
        self.assertEqual(r.sessions_ok, 0)
        self.assertEqual(len(r.attempts), 3)
        self.assertEqual(r.attempts[-1].error["error"], "SimulatedDisconnect")


class TestResidual26Hooks(unittest.TestCase):
    def test_hook_pre_handshake(self):
        from l3.key_provider import SLOT_TICKET, DictKeyProvider, KeyProvider
        from l3.spice_keepalive_loop import KeepaliveConfig, SpiceKeepaliveLoop

        seen = []

        def hook(keys: KeyProvider, ctx: dict) -> None:
            seen.append(ctx)
            self.assertIsNotNone(keys.get(SLOT_TICKET))

        kp = DictKeyProvider({SLOT_TICKET: b"\xff" * 8})
        r = SpiceKeepaliveLoop(
            kp,
            KeepaliveConfig(max_attempts=1, max_heart_rounds=1, send_agent_hb=False),
            residual26_hooks=[hook],
        ).run_offline()
        self.assertTrue(r.ok)
        self.assertEqual(r.residual26_hooks_fired, 1)
        self.assertEqual(seen[0]["stage"], "pre_handshake")
        self.assertFalse(seen[0]["production_claim"])


class TestSelftest(unittest.TestCase):
    def test_selftest(self):
        from l3 import spice_keepalive_loop

        spice_keepalive_loop.selftest()


if __name__ == "__main__":
    unittest.main()
