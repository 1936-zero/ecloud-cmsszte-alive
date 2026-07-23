"""#75fixam-fix: delete card must rmtree backend dir."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class AccountDeleteTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        # build minimal index + account dir
        acc_id = "u-test-del1"
        self.acc_id = acc_id
        d = self.root / acc_id
        d.mkdir()
        (d / "config.json").write_text(json.dumps({
            "username": "u",
            "password": "p",
            "label": "u",
            "created_at": "2026-01-01T00:00:00",
        }), encoding="utf-8")
        (self.root / "index.json").write_text(json.dumps({
            "accounts": [{"id": acc_id, "label": "u", "username": "u", "created_at": "2026-01-01T00:00:00"}],
            "updated_at": "2026-01-01T00:00:00",
        }), encoding="utf-8")

    def tearDown(self):
        self._td.cleanup()

    def test_delete_rmtree(self):
        from web.account_runtime import AccountRegistry
        reg = AccountRegistry(root=self.root)
        self.assertTrue((self.root / self.acc_id).is_dir())
        out = reg.delete(self.acc_id)
        self.assertTrue(out.get("ok"), out)
        self.assertFalse((self.root / self.acc_id).exists(), "backend dir must be gone")
        # index empty
        idx = json.loads((self.root / "index.json").read_text())
        self.assertEqual(idx.get("accounts"), [])

    def test_delete_missing(self):
        from web.account_runtime import AccountRegistry
        reg = AccountRegistry(root=self.root)
        out = reg.delete("no-such-id")
        self.assertFalse(out.get("ok"))


if __name__ == "__main__":
    unittest.main()
