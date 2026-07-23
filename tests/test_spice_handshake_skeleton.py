"""N5 offline tests: PY_SPICE_HANDSHAKE_SKELETON (deepen: reconnect + N6 + ≥3 HB).

production_claim=false
- key_provider inject surface
- missing key explainable
- handshake + heart state machine dry path
- reconnect SM offline (disconnect → re-auth → ≥3 HB total)
- N6 slot bind: SLOT_SESSION_KEY + SLOT_PROP0X14
- no vendor SDK import
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
L3 = os.path.join(ROOT, "l3")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if L3 not in sys.path:
    sys.path.insert(0, L3)


class TestKeyProvider(unittest.TestCase):
    def test_null_require_raises_explainable(self):
        from l3.key_provider import MissingKeyError, NullKeyProvider, SLOT_TICKET

        n = NullKeyProvider()
        with self.assertRaises(MissingKeyError) as cm:
            n.require(SLOT_TICKET, stage="AUTH")
        e = cm.exception
        self.assertEqual(e.slot, SLOT_TICKET)
        self.assertEqual(e.stage, "AUTH")
        d = e.as_dict()
        self.assertFalse(d["production_claim"])
        self.assertIn("missing", d["reason"].lower())

    def test_dict_provider_roundtrip(self):
        from l3.key_provider import DictKeyProvider, SLOT_SESSION_KEY, SLOT_TICKET

        p = DictKeyProvider({SLOT_TICKET: b"\x01\x02\x03", SLOT_SESSION_KEY: b"k" * 16})
        self.assertEqual(p.require(SLOT_TICKET), b"\x01\x02\x03")
        self.assertTrue(p.has(SLOT_SESSION_KEY))
        desc = p.describe()
        self.assertEqual(desc["slots"][SLOT_TICKET]["len"], 3)
        self.assertFalse(desc["production_claim"])

    def test_make_key_provider_variants(self):
        from l3.key_provider import (
            DictKeyProvider,
            NullKeyProvider,
            SLOT_ZTEC_C2S,
            make_key_provider,
        )

        self.assertIsInstance(make_key_provider(None), NullKeyProvider)
        self.assertIsInstance(make_key_provider({SLOT_ZTEC_C2S: b"ZTEC"}), DictKeyProvider)
        self.assertEqual(make_key_provider(lambda s: b"x" if s == "ticket" else None).get("ticket"), b"x")

    def test_no_str_secrets_in_dict_provider(self):
        from l3.key_provider import DictKeyProvider

        with self.assertRaises(TypeError):
            DictKeyProvider({"ticket": "not-bytes"})  # type: ignore[dict-item]


class TestSpiceHandshakeSkeleton(unittest.TestCase):
    def test_missing_ticket_fails_explainable(self):
        from l3.key_provider import NullKeyProvider
        from l3.spice_handshake import SpiceHandshakeSkeleton

        r = SpiceHandshakeSkeleton(NullKeyProvider()).run_offline()
        self.assertFalse(r.ok)
        self.assertIsNotNone(r.error)
        self.assertEqual(r.error["error"], "MissingKeyError")
        self.assertEqual(r.error["slot"], "ticket")
        self.assertEqual(r.error["stage"], "AUTH")
        self.assertFalse(r.production_claim)
        self.assertFalse(r.as_dict()["production_claim"])
        self.assertEqual(r.stats["auth_missing_key"], 1)
        self.assertEqual(r.stats["link_mess_built"], 1)

    def test_with_ticket_full_offline_green(self):
        from l3.key_provider import DictKeyProvider, SLOT_SESSION_KEY, SLOT_TICKET
        from l3.spice_handshake import HandshakeConfig, HandshakePhase, SpiceHandshakeSkeleton

        kp = DictKeyProvider(
            {
                SLOT_TICKET: b"\xaa" * 32,
                SLOT_SESSION_KEY: b"\x11" * 16,
            }
        )
        sm = SpiceHandshakeSkeleton(kp, HandshakeConfig(max_heart_rounds=3))
        r = sm.run_offline()
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.phase, HandshakePhase.CLOSED.value)
        self.assertEqual(r.stats["link_mess_built"], 1)
        self.assertEqual(r.stats["auth_ok"], 1)
        self.assertEqual(r.stats["caps_ok"], 1)
        self.assertEqual(r.stats["s53_seen"], 3)
        self.assertEqual(r.stats["c49_sent"], 3)
        self.assertEqual(r.stats["agent_hb_sent"], 3)
        self.assertEqual(r.stats["heart_rounds_completed"], 3)
        self.assertFalse(r.production_claim)
        # REDQ link mess first
        self.assertTrue(r.tx_frames[0].startswith(b"REDQ"))

    def test_auth_skip_dry(self):
        from l3.key_provider import NullKeyProvider
        from l3.spice_handshake import HandshakeConfig, SpiceHandshakeSkeleton

        r = SpiceHandshakeSkeleton(
            NullKeyProvider(),
            HandshakeConfig(allow_auth_skip=True, max_heart_rounds=1, send_agent_hb=False),
        ).run_offline()
        self.assertTrue(r.ok)
        self.assertEqual(r.stats["c49_sent"], 1)
        self.assertEqual(r.stats["agent_hb_sent"], 0)

    def test_step_auth_raises_missing(self):
        from l3.key_provider import MissingKeyError, NullKeyProvider
        from l3.spice_handshake import SpiceHandshakeSkeleton

        sm = SpiceHandshakeSkeleton(NullKeyProvider())
        sm.step_init()
        sm.step_link_mess()
        with self.assertRaises(MissingKeyError) as cm:
            sm.step_auth()
        self.assertIn("slot='ticket'", str(cm.exception))

    def test_forbids_production_claim_flag(self):
        from l3.spice_handshake import HandshakeConfig, SpiceHandshakeSkeleton

        with self.assertRaises(ValueError):
            SpiceHandshakeSkeleton(config=HandshakeConfig(production_claim=True))

    def test_heart_frame_types(self):
        from l3.key_provider import DictKeyProvider, SLOT_TICKET
        from l3.spice_frame_builder import TYPE_C49_HEART_ACK, parse_spice_frame
        from l3.spice_handshake import HandshakeConfig, SpiceHandshakeSkeleton

        sm = SpiceHandshakeSkeleton(
            DictKeyProvider({SLOT_TICKET: b"t"}),
            HandshakeConfig(max_heart_rounds=1, send_agent_hb=True),
        )
        r = sm.run_offline()
        self.assertTrue(r.ok)
        # find a C49 among tx (skip REDQ + AUTH_TOKEN)
        found_c49 = False
        found_agent = False
        for fr in r.tx_frames:
            p = parse_spice_frame(fr)
            if p and p["type"] == TYPE_C49_HEART_ACK:
                found_c49 = True
            if p and p["type"] == 0x6B:
                found_agent = True
        self.assertTrue(found_c49)
        self.assertTrue(found_agent)

    def test_n6_slot_bind_session_and_prop0x14(self):
        """N5 deepen: key_provider inject aligns N6 SLOT_SESSION_KEY + SLOT_PROP0X14."""
        from l3.key_provider import (
            DictKeyProvider,
            SLOT_PROP0X14,
            SLOT_SESSION_KEY,
            SLOT_TICKET,
        )
        from l3.spice_handshake import HandshakeConfig, SpiceHandshakeSkeleton

        kp = DictKeyProvider(
            {
                SLOT_TICKET: b"\xaa" * 16,
                SLOT_SESSION_KEY: b"\x55" * 16,
                SLOT_PROP0X14: b"\x14" * 12,
            }
        )
        sm = SpiceHandshakeSkeleton(kp, HandshakeConfig(max_heart_rounds=3, bind_n6_slots=True))
        r = sm.run_offline()
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.stats["session_key_bound"], 1)
        self.assertEqual(r.stats["prop0x14_bound"], 1)
        self.assertEqual(r.stats["heart_rounds_completed"], 3)
        binds = [e for e in r.events if e.action == "n6_slot_bind"]
        self.assertEqual(len(binds), 1)
        self.assertTrue(binds[0].detail["session_key_present"])
        self.assertTrue(binds[0].detail["prop0x14_present"])
        self.assertEqual(binds[0].detail["session_key_len"], 16)
        self.assertEqual(binds[0].detail["prop0x14_len"], 12)
        self.assertTrue(binds[0].detail["n6_align"])
        # no secret material in event detail
        dump = str(binds[0].detail)
        self.assertNotIn("\\x55", dump)

    def test_reconnect_offline_ge3_hearts(self):
        """N5 deepen: disconnect mid-session → reconnect → re-auth → ≥3 HB total green."""
        from l3.key_provider import (
            DictKeyProvider,
            SLOT_PROP0X14,
            SLOT_SESSION_KEY,
            SLOT_TICKET,
        )
        from l3.spice_handshake import HandshakeConfig, HandshakePhase, SpiceHandshakeSkeleton

        kp = DictKeyProvider(
            {
                SLOT_TICKET: b"\xab" * 32,
                SLOT_SESSION_KEY: b"\xcd" * 16,
                SLOT_PROP0X14: b"\xef" * 8,
            }
        )
        sm = SpiceHandshakeSkeleton(kp, HandshakeConfig(max_heart_rounds=3))
        r = sm.run_offline_with_reconnect(disconnect_after_hearts=1)
        self.assertTrue(r.ok, r.as_dict())
        self.assertEqual(r.phase, HandshakePhase.CLOSED.value)
        self.assertEqual(r.stats["disconnects"], 1)
        self.assertEqual(r.stats["reconnects"], 1)
        self.assertEqual(r.stats["link_mess_built"], 2)
        self.assertEqual(r.stats["auth_ok"], 2)
        self.assertEqual(r.stats["caps_ok"], 2)
        self.assertGreaterEqual(r.stats["heart_rounds_completed"], 3)
        self.assertGreaterEqual(r.stats["c49_sent"], 3)
        self.assertGreaterEqual(r.stats["s53_seen"], 3)
        self.assertEqual(r.stats["session_key_bound"], 2)
        self.assertEqual(r.stats["prop0x14_bound"], 2)
        self.assertFalse(r.production_claim)
        actions = [e.action for e in r.events]
        self.assertIn("disconnect", actions)
        self.assertIn("reconnect_begin", actions)
        # phases seen include DISCONNECTED / RECONNECT
        phases = {e.phase for e in r.events}
        self.assertIn("DISCONNECTED", phases)
        self.assertIn("RECONNECT", phases)

    def test_simulate_disconnect_invalid_from_init(self):
        from l3.spice_handshake import SpiceHandshakeSkeleton

        sm = SpiceHandshakeSkeleton()
        with self.assertRaises(RuntimeError):
            sm.simulate_disconnect()

    def test_max_reconnects_exhausted(self):
        from l3.key_provider import DictKeyProvider, SLOT_TICKET
        from l3.spice_handshake import HandshakeConfig, HandshakePhase, SpiceHandshakeSkeleton

        sm = SpiceHandshakeSkeleton(
            DictKeyProvider({SLOT_TICKET: b"t"}),
            HandshakeConfig(max_heart_rounds=1, max_reconnects=1),
        )
        sm.run_handshake_once(heart_rounds=1)
        sm.simulate_disconnect("d1")
        sm.step_reconnect()
        sm.run_handshake_once(heart_rounds=1)
        sm.simulate_disconnect("d2")
        with self.assertRaises(RuntimeError):
            sm.step_reconnect()
        self.assertEqual(sm.phase, HandshakePhase.FAILED)


class TestNoSdkHardDep(unittest.TestCase):
    def test_modules_import_without_sdk(self):
        # Ensure handshake stack imports without uSmartView / spice-client-glib
        mods = [
            "l3.key_provider",
            "l3.spice_handshake",
        ]
        for m in mods:
            if m in sys.modules:
                del sys.modules[m]
            mod = importlib.import_module(m)
            self.assertIsNotNone(mod)
        # no accidental SDK symbols
        import l3.spice_handshake as sh

        with open(sh.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("uSmartView", src)
        self.assertNotIn("spice-client-glib", src)
        self.assertNotIn("ctypes.CDLL", src)


class TestSelftests(unittest.TestCase):
    def test_key_provider_selftest(self):
        from l3 import key_provider

        key_provider.selftest()

    def test_handshake_selftest(self):
        from l3 import spice_handshake

        spice_handshake.selftest()


if __name__ == "__main__":
    unittest.main()
