#!/usr/bin/env python3
"""N6 · PY_CONNECTSTR_K_PIPELINE — guest vs session track separation + vectors.

T51 DEEPEN:
  - residual ticket ≠ -k ≠ prop0x14 ≠ EWK boundary vectors
  - guest/session import isolation hardened
  - T26 SERVER_CONNECTSTR / find-only / MD5-separate pins

PINNED:
  P1 EncryptWithKey@0xa8c80 guest-only
  P2 -k ≠ EncryptWithKey out (ALREADY_IN parse)
  P3 prop0x14 ≠ EncryptWithKey product

production_claim remains false. No LIVE connect.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

from l3.connectstr_k_session import (
    FREEZE_CITE,
    PUBLIC_HEAD_K_DIGITS,
    RESIDUAL_TICKET_FIRST8_CITE,
    RESIDUAL_TICKET_LEN_CITE,
    SOURCE_CLASS,
    assert_ticket_not_session,
    assert_tracks_separated,
    k_to_prop0x14,
    parse_connectstr_k,
    pipeline_from_plain_connectstr,
    refuse_ewk_as_session,
    residual_ticket_boundary,
    session_key_8b,
    session_key_md5_hex,
    session_module_imports_guest,
)
from l3.guest_encrypt_track import (
    ENCRYPT_WITH_KEY_VA,
    LIBRARY,
    NOT_ROLE,
    ROLE,
    TRACK as GUEST_TRACK,
    guest_encrypt,
    never_as_prop0x14,
)
from l3.vdconn_encrypt_with_key import encrypt_with_key
from l3.key_provider import (
    ALL_SLOTS,
    SLOT_PROP0X14,
    SLOT_SESSION_KEY,
    SLOT_TICKET,
)

NEST = Path("/home/demo/ecloud-cloudpc-keepalive-imHansiy")
FIXTURE_PLAIN = NEST / "fixtures/r26/rp001/connectstr_plain.txt"
FIXTURE_TICKET = NEST / "fixtures/r26/rp001/access_ticket_synthetic.txt"
FIXTURE_PROP8 = NEST / "fixtures/r26/rp001/prop8_ascii.txt"


class TrackSeparationTests(unittest.TestCase):
    def test_modules_are_distinct(self):
        import l3.connectstr_k_session as sess
        import l3.guest_encrypt_track as guest
        import l3.vdconn_encrypt_with_key as ewk

        self.assertNotEqual(sess.__file__, guest.__file__)
        self.assertNotEqual(sess.__file__, ewk.__file__)
        self.assertNotEqual(guest.__file__, ewk.__file__)
        self.assertEqual(GUEST_TRACK, "guest")
        self.assertEqual(ENCRYPT_WITH_KEY_VA, "0xa8c80")
        self.assertIn("libvdconn", LIBRARY)
        self.assertEqual(ROLE, "GUEST_CMDLINE_FRAGMENT_ENCRYPT")
        self.assertIn("prop0x14", NOT_ROLE)

    def test_p1_ewk_guest_vectors(self):
        out, ek, _ = guest_encrypt("hello", "testkey", upper_hex=True)
        self.assertEqual(ek, 10)
        self.assertEqual(out, "626F666665")
        out2, ek2, _ = encrypt_with_key("guest", "password", upper_hex=True)
        self.assertEqual(ek2, 11)
        self.assertEqual(out2, "6C7E6E787F")

    def test_p1_never_as_prop0x14(self):
        out, _, _ = guest_encrypt("guest", "password")
        with self.assertRaises(RuntimeError):
            never_as_prop0x14(out)


class ParseKAndSessionTests(unittest.TestCase):
    def test_p2_parse_k_already_in(self):
        plain = f"-h 10.0.0.1 -p 5100 -k {PUBLIC_HEAD_K_DIGITS} --type ice"
        p = parse_connectstr_k(plain)
        self.assertTrue(p.k_present)
        self.assertEqual(p.k_value, PUBLIC_HEAD_K_DIGITS)
        self.assertEqual(p.fields.get("k"), PUBLIC_HEAD_K_DIGITS)

    def test_p2_k_not_equal_ewk_product(self):
        ewk, _, _ = encrypt_with_key("guest", "password")
        self.assertNotEqual(PUBLIC_HEAD_K_DIGITS.upper(), ewk.upper())
        assert_tracks_separated(PUBLIC_HEAD_K_DIGITS, ewk)

    def test_p2_violation_raises(self):
        ewk, _, _ = encrypt_with_key("guest", "password")
        with self.assertRaises(AssertionError):
            assert_tracks_separated(ewk, ewk)

    def test_p3_prop0x14_from_k_public_head(self):
        sk = k_to_prop0x14(PUBLIC_HEAD_K_DIGITS)
        self.assertEqual(sk, b"91723341")
        self.assertEqual(len(sk), 8)

    def test_p3_prop0x14_not_ewk(self):
        ewk, _, _ = encrypt_with_key("guest", "password")
        sk = k_to_prop0x14(PUBLIC_HEAD_K_DIGITS)
        self.assertNotEqual(sk, ewk.encode("ascii")[:8])
        self.assertTrue(refuse_ewk_as_session(ewk, sk))

    def test_session_pad_trunc(self):
        self.assertEqual(session_key_8b("ab"), b"ab\x00\x00\x00\x00\x00\x00")
        self.assertEqual(session_key_8b("123456789"), b"12345678")
        h = session_key_md5_hex(b"91723341")
        self.assertEqual(len(h), 32)

    def test_pipeline_offline(self):
        fixture = f"-h 1.2.3.4 -p 5901 -k {PUBLIC_HEAD_K_DIGITS}"
        r = pipeline_from_plain_connectstr(fixture, production_claim=True)
        self.assertFalse(r["production_claim"])  # forced false
        self.assertEqual(r["track"], "session")
        self.assertEqual(r["session_8b_ascii"], PUBLIC_HEAD_K_DIGITS)
        self.assertEqual(r["freeze_cite"], FREEZE_CITE)
        self.assertFalse(r["live_executed"])
        self.assertTrue(r["md5_is_separate_path"])

    def test_no_k_still_session_track(self):
        r = pipeline_from_plain_connectstr("-h 1.2.3.4 -p 1")
        self.assertFalse(r["k_present"])
        self.assertIsNone(r["session_8b_hex"])


class CrossModuleImportGuard(unittest.TestCase):
    def test_session_module_doc_forbids_ewk(self):
        import l3.connectstr_k_session as m

        self.assertIn("SEPARATE", m.__doc__)
        self.assertIn("EncryptWithKey", m.__doc__)

    def test_session_source_does_not_import_guest(self):
        self.assertFalse(session_module_imports_guest())

    def test_guest_module_points_away_from_session(self):
        import l3.guest_encrypt_track as g

        self.assertIn("prop0x14", g.NOT_ROLE)
        self.assertIn("session_key_8b", g.NOT_ROLE)
        self.assertIn("connectstr_-k_mint", g.NOT_ROLE)


class ResidualTicketBoundaryTests(unittest.TestCase):
    """T51 DEEPEN: residual ticket/session boundary vectors (offline)."""

    def _synthetic_ticket(self) -> str:
        if FIXTURE_TICKET.is_file():
            return FIXTURE_TICKET.read_text(encoding="utf-8").strip()
        # fall back to cite-shaped synthetic
        return RESIDUAL_TICKET_FIRST8_CITE + ("0" * (RESIDUAL_TICKET_LEN_CITE - 8))

    def test_ticket_first8_cite_shape(self):
        t = self._synthetic_ticket()
        self.assertEqual(t[:8], RESIDUAL_TICKET_FIRST8_CITE)
        self.assertEqual(len(t), RESIDUAL_TICKET_LEN_CITE)

    def test_ticket_ne_k_ne_prop0x14(self):
        t = self._synthetic_ticket()
        ewk, _, _ = encrypt_with_key("guest", "password")
        v = residual_ticket_boundary(
            t, PUBLIC_HEAD_K_DIGITS, encrypt_product_hex=ewk
        )
        self.assertTrue(v["ok"], v)
        self.assertFalse(v["mint_from_ticket"])
        self.assertEqual(v["ticket_first8_ascii"], RESIDUAL_TICKET_FIRST8_CITE)
        self.assertNotEqual(v["ticket_first8_ascii"], PUBLIC_HEAD_K_DIGITS)
        self.assertEqual(v["session_8b_ascii"], PUBLIC_HEAD_K_DIGITS)
        assert_ticket_not_session(t, PUBLIC_HEAD_K_DIGITS, ewk)

    def test_ticket_ne_ewk(self):
        t = self._synthetic_ticket()
        ewk, _, _ = encrypt_with_key("guest", "password")
        self.assertNotEqual(t[:8], ewk[:8])
        v = residual_ticket_boundary(t, None, encrypt_product_hex=ewk)
        self.assertTrue(v["ok"], v)

    def test_collapse_ticket_to_k_raises(self):
        # adversarial: ticket body equal to -k digits
        with self.assertRaises(AssertionError):
            assert_ticket_not_session(PUBLIC_HEAD_K_DIGITS, PUBLIC_HEAD_K_DIGITS)

    def test_pipeline_with_ticket_boundary(self):
        plain = FIXTURE_PLAIN.read_text(encoding="utf-8").strip() if FIXTURE_PLAIN.is_file() else (
            f"-h 10.0.0.1 -p 5100 -k {PUBLIC_HEAD_K_DIGITS}"
        )
        t = self._synthetic_ticket()
        ewk, _, _ = encrypt_with_key("guest", "password")
        r = pipeline_from_plain_connectstr(
            plain, access_ticket=t, encrypt_product_hex=ewk
        )
        self.assertTrue(r["k_present"])
        self.assertIsNotNone(r["ticket_boundary"])
        self.assertTrue(r["ticket_boundary"]["ok"], r["ticket_boundary"])
        self.assertFalse(r["production_claim"])
        self.assertIn("no_mint_from_ticket", r["notes"])

    def test_prop8_fixture_matches_k(self):
        if FIXTURE_PROP8.is_file():
            prop8 = FIXTURE_PROP8.read_text(encoding="utf-8").strip()
            self.assertEqual(prop8, PUBLIC_HEAD_K_DIGITS)
            self.assertEqual(k_to_prop0x14(prop8), prop8.encode("ascii"))


class T26AlignmentTests(unittest.TestCase):
    def test_source_class_server_connectstr(self):
        self.assertEqual(SOURCE_CLASS, "SERVER_CONNECTSTR")
        r = pipeline_from_plain_connectstr(
            f"-k {PUBLIC_HEAD_K_DIGITS}"
        )
        self.assertIn("SERVER_CONNECTSTR", r["source_class"])
        self.assertIn("ALREADY_IN", r["source_class"])

    def test_md5_separate_from_raw8(self):
        sk = k_to_prop0x14(PUBLIC_HEAD_K_DIGITS)
        md5h = session_key_md5_hex(sk)
        self.assertEqual(len(md5h), 32)
        self.assertNotEqual(md5h, PUBLIC_HEAD_K_DIGITS)
        self.assertNotEqual(md5h, sk.hex())
        # EWK product also not equal
        ewk, _, _ = encrypt_with_key("guest", "password")
        self.assertNotEqual(md5h.upper(), ewk.upper())

    def test_freeze_cite_held(self):
        self.assertEqual(FREEZE_CITE, "a46d55cd523da9fd")

    def test_find_only_no_append_ewk(self):
        # parse must not invent -k from guest material
        plain = "-h 1.2.3.4 -p 1 --guest-usr demo"
        p = parse_connectstr_k(plain)
        self.assertFalse(p.k_present)
        self.assertIsNone(p.k_value)


class KeyProviderSlotAlignmentTests(unittest.TestCase):
    """N5 key_provider slots coexist but must not collapse tracks."""

    def test_slots_include_ticket_and_prop0x14(self):
        self.assertIn(SLOT_TICKET, ALL_SLOTS)
        self.assertIn(SLOT_PROP0X14, ALL_SLOTS)
        self.assertIn(SLOT_SESSION_KEY, ALL_SLOTS)
        self.assertNotEqual(SLOT_TICKET, SLOT_PROP0X14)
        self.assertNotEqual(SLOT_TICKET, SLOT_SESSION_KEY)

    def test_prop0x14_slot_fed_from_session_not_ewk(self):
        sk = k_to_prop0x14(PUBLIC_HEAD_K_DIGITS)
        ewk, _, _ = encrypt_with_key("guest", "password")
        # slot values must remain distinct materials
        self.assertNotEqual(sk, ewk.encode("ascii")[:8])
        # ticket slot material (synthetic) ≠ prop0x14
        ticket = RESIDUAL_TICKET_FIRST8_CITE.encode("ascii")
        self.assertNotEqual(ticket, sk)


if __name__ == "__main__":
    unittest.main()
