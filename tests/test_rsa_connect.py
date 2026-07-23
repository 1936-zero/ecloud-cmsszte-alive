"""Unit tests for l3.rsa_connect — TEMP PEM only, never committed."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA

from l3.rsa_connect import (
    DRY_STUB_PREFIX,
    ENV_CMSS_PUBKEY_PEM,
    RSA_ENCRYPT_CHUNK,
    RsaConnectError,
    encrypt_connect_params,
    encrypt_plain,
    resolve_pubkey_path,
    resolve_pubkey_slot,
    rsa_encrypt_with_pem,
)
from l3.vendor_resolver import resolve


class TestResolvePubkeySlot(unittest.TestCase):
    def test_from_vendor_profile_cmsszte(self):
        profile = resolve("CMSSZTE", require_binaries=False)
        slot = resolve_pubkey_slot(profile)
        self.assertEqual(slot, "privateSetting.SDKSecretKey.publicKey.CMSSZTE")
        self.assertNotIn("BEGIN", slot)
        self.assertNotIn("KEY-----", slot)

    def test_from_mapping(self):
        slot = resolve_pubkey_slot(
            {"pubkey_slot": "privateSetting.SDKSecretKey.publicKey.CMSSZTE"}
        )
        self.assertTrue(slot.endswith("CMSSZTE"))

    def test_empty_raises(self):
        with self.assertRaises(RsaConnectError):
            resolve_pubkey_slot({})
        with self.assertRaises(RsaConnectError):
            resolve_pubkey_slot(None)


class TestResolvePubkeyPath(unittest.TestCase):
    """P10-A: env ECLOUD_CMSS_PUBKEY_PEM + explicit path; no PEM body."""

    def test_none_when_unset(self):
        self.assertIsNone(
            resolve_pubkey_path(None, env={}, must_exist=True)
        )

    def test_env_path_must_exist_false_returns_string(self):
        fake = "/tmp/does-not-exist-ecloud-cmss-pubkey.pem"
        got = resolve_pubkey_path(
            None, env={ENV_CMSS_PUBKEY_PEM: fake}, must_exist=False
        )
        self.assertIsNotNone(got)
        self.assertIn("does-not-exist-ecloud-cmss-pubkey.pem", got)

    def test_env_missing_file_returns_none_when_must_exist(self):
        got = resolve_pubkey_path(
            None,
            env={ENV_CMSS_PUBKEY_PEM: "/no/such/cmss_pubkey.pem"},
            must_exist=True,
        )
        self.assertIsNone(got)

    def test_explicit_wins_over_env(self):
        with tempfile.TemporaryDirectory() as td:
            p_explicit = Path(td) / "explicit.pem"
            p_env = Path(td) / "env.pem"
            # minimal PEM markers only (not a real key; resolve only checks isfile)
            p_explicit.write_text(
                "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
                encoding="utf-8",
            )
            p_env.write_text(
                "-----BEGIN PUBLIC KEY-----\nZZZZ\n-----END PUBLIC KEY-----\n",
                encoding="utf-8",
            )
            got = resolve_pubkey_path(
                str(p_explicit),
                env={ENV_CMSS_PUBKEY_PEM: str(p_env)},
                must_exist=True,
            )
            self.assertIsNotNone(got)
            self.assertTrue(got.endswith("explicit.pem") or "explicit.pem" in got)

    def test_env_file_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            p_env = Path(td) / "from_env.pem"
            p_env.write_text(
                "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
                encoding="utf-8",
            )
            got = resolve_pubkey_path(
                None, env={ENV_CMSS_PUBKEY_PEM: str(p_env)}, must_exist=True
            )
            self.assertIsNotNone(got)
            self.assertTrue(os.path.isfile(got))
            # never return PEM body
            self.assertNotIn("BEGIN", got)

    def test_no_opt_zte_fallback(self):
        # Even if /opt/ZTE exists on host, resolver must not invent it.
        got = resolve_pubkey_path(None, env={}, must_exist=True)
        self.assertIsNone(got)
        if got:
            self.assertNotIn("/opt/ZTE", got)


class TestEncryptPlainDryRun(unittest.TestCase):
    def test_dry_run_stub_non_empty(self):
        plain = json.dumps({"vmid": "m1", "socketPort": 15900})
        cipher = encrypt_plain(plain, pubkey_path=None, dry_run=True)
        self.assertTrue(cipher.startswith(DRY_STUB_PREFIX))
        self.assertGreater(len(cipher), len(DRY_STUB_PREFIX))

    def test_missing_path_returns_stub(self):
        cipher = encrypt_plain(b'{"a":1}', pubkey_path="/no/such/pubkey.pem")
        self.assertTrue(cipher.startswith(DRY_STUB_PREFIX))

    def test_empty_path_returns_stub(self):
        cipher = encrypt_plain("{}", pubkey_path="")
        self.assertTrue(cipher.startswith(DRY_STUB_PREFIX))

    def test_dry_stub_deterministic_for_same_plain(self):
        a = encrypt_plain("same", dry_run=True)
        b = encrypt_plain("same", dry_run=True)
        self.assertEqual(a, b)
        self.assertNotEqual(encrypt_plain("other", dry_run=True), a)


class TestEncryptWithTempPem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate ephemeral RSA-1024 for tests only (not written to repo).
        cls._key = RSA.generate(1024)
        cls._pem = cls._key.publickey().export_key().decode("ascii")

    def test_rsa_encrypt_with_pem_non_empty_base64(self):
        plain = json.dumps({"socketPort": 15900, "vmid": "test-vm"})
        cipher = rsa_encrypt_with_pem(plain, self._pem)
        self.assertTrue(len(cipher) > 0)
        # Valid base64 and longer than plaintext for multi-block safety.
        raw = base64.b64decode(cipher)
        self.assertGreaterEqual(len(raw), 128)
        self.assertNotEqual(cipher, plain)

    def test_encrypt_plain_from_temp_file(self):
        plain = "x" * (RSA_ENCRYPT_CHUNK + 20)  # force multi-chunk
        with tempfile.TemporaryDirectory() as td:
            pem_path = Path(td) / "test_pub.pem"
            pem_path.write_text(self._pem, encoding="utf-8")
            cipher = encrypt_plain(plain, str(pem_path), dry_run=False)
        self.assertFalse(cipher.startswith(DRY_STUB_PREFIX))
        raw = base64.b64decode(cipher)
        # 2 chunks * 128 bytes for 1024-bit modulus.
        self.assertGreaterEqual(len(raw), 256)

    def test_encrypt_connect_params_with_profile_dry(self):
        profile = resolve("CMSSZTE", require_binaries=False)
        cipher = encrypt_connect_params(
            '{"vmid":"m"}', profile, dry_run=True
        )
        self.assertTrue(cipher.startswith(DRY_STUB_PREFIX))

    def test_interface_stable_bytes_and_str(self):
        with tempfile.TemporaryDirectory() as td:
            pem_path = Path(td) / "p.pem"
            pem_path.write_text(self._pem, encoding="utf-8")
            c1 = encrypt_plain("abc", str(pem_path))
            c2 = encrypt_plain(b"abc", str(pem_path))
        # PKCS1 v1.5 is randomized → different ciphertexts; both valid base64.
        base64.b64decode(c1)
        base64.b64decode(c2)
        self.assertNotEqual(c1, "abc")

    def test_encrypt_plain_via_env_path(self):
        plain = json.dumps({"socketPort": 15900})
        with tempfile.TemporaryDirectory() as td:
            pem_path = Path(td) / "env_pub.pem"
            pem_path.write_text(self._pem, encoding="utf-8")
            cipher = encrypt_plain(
                plain,
                pubkey_path=None,
                dry_run=False,
                env={ENV_CMSS_PUBKEY_PEM: str(pem_path)},
            )
        self.assertFalse(cipher.startswith(DRY_STUB_PREFIX))
        base64.b64decode(cipher)

    def test_encrypt_connect_params_via_env(self):
        profile = resolve("CMSSZTE", require_binaries=False)
        with tempfile.TemporaryDirectory() as td:
            pem_path = Path(td) / "env_pub.pem"
            pem_path.write_text(self._pem, encoding="utf-8")
            cipher = encrypt_connect_params(
                '{"vmid":"m"}',
                profile,
                dry_run=False,
                env={ENV_CMSS_PUBKEY_PEM: str(pem_path)},
            )
        self.assertFalse(cipher.startswith(DRY_STUB_PREFIX))
        base64.b64decode(cipher)


if __name__ == "__main__":
    unittest.main()
