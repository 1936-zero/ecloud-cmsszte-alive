"""#75fixao: bottom 运行日志 whitelist + stick gate regression.

P0-R2: card keepalive/preflight/login noise stays on card ring;
       bottom global only gets WebUI lifecycle + ERROR auto-promote.
P0-R1: frontend must not force scrollTop without stick gate.
"""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class GlobalLogWhitelistTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def _fresh_reg(self):
        from web.account_runtime import AccountRegistry

        return AccountRegistry(root=self.root)

    def test_default_log_stays_on_card_not_global(self):
        reg = self._fresh_reg()
        created = reg.create(label="t1", username="u1", password="p1")
        self.assertTrue(created.get("ok") or created.get("id") or "account" in created, created)
        acc = reg.list_accounts()[0] if hasattr(reg, "list_accounts") else None
        # create may return account dict
        aid = (
            (created.get("account") or {}).get("id")
            or created.get("id")
            or (reg.list()[0]["id"] if hasattr(reg, "list") else None)
        )
        if not aid:
            # fallback: pick first loaded account
            with reg._lock:
                aid = next(iter(reg._accounts))
        acc = reg.get(aid)
        self.assertIsNotNone(acc)

        # baseline global after create (create itself may append one lifecycle line)
        before = {e.get("gseq") for e in reg.get_global_logs(0)}

        # noisy keepalive / preflight / pathb ticks — must NOT enter global
        noisy = [
            ("INFO", "preflight ok instance=CCA-x uptime=1"),
            ("INFO", "[1] Path B 成功 heart=True uptime=- status=-"),
            ("INFO", "[账号保活] [1] 账号保活成功"),
            ("INFO", "登录中: user=u1"),
            ("INFO", "登录成功"),
            ("INFO", "会话凭证已就绪"),
        ]
        for lvl, msg in noisy:
            acc.log(lvl, msg)  # default to_global=False

        card = acc.get_logs(0)
        card_msgs = [e["msg"] for e in card]
        for _, msg in noisy:
            self.assertIn(msg, card_msgs, f"card must keep: {msg}")

        after = reg.get_global_logs(0)
        new_global = [e for e in after if e.get("gseq") not in before]
        new_msgs = [e.get("msg") for e in new_global]
        for _, msg in noisy:
            self.assertNotIn(msg, new_msgs, f"global must NOT contain: {msg}")

    def test_error_auto_promotes_to_global(self):
        reg = self._fresh_reg()
        out = reg.create(label="t-err", username="ue", password="pe")
        with reg._lock:
            aid = next(iter(reg._accounts))
        acc = reg.get(aid)
        before = {e.get("gseq") for e in reg.get_global_logs(0)}
        acc.log("ERROR", "Path B 致命失败 boom")  # no to_global kw
        after = reg.get_global_logs(0)
        new_msgs = [e.get("msg") for e in after if e.get("gseq") not in before]
        self.assertIn("Path B 致命失败 boom", new_msgs)

    def test_explicit_lifecycle_whitelist_enters_global(self):
        reg = self._fresh_reg()
        out = reg.create(label="life", username="ul", password="pl")
        # create card itself should append global lifecycle
        g_msgs = [e.get("msg", "") for e in reg.get_global_logs(0)]
        self.assertTrue(
            any("账号卡片已创建" in m for m in g_msgs),
            f"create must append global lifecycle, got: {g_msgs[-5:]}",
        )
        with reg._lock:
            aid = next(iter(reg._accounts))
        acc = reg.get(aid)
        before = {e.get("gseq") for e in reg.get_global_logs(0)}
        acc.log("INFO", "已启动账号登录态保活 interval=60s", to_global=True)
        acc.log("INFO", "已停止 Path B 保活", to_global=True)
        after = reg.get_global_logs(0)
        new_msgs = [e.get("msg") for e in after if e.get("gseq") not in before]
        self.assertIn("已启动账号登录态保活 interval=60s", new_msgs)
        self.assertIn("已停止 Path B 保活", new_msgs)

    def test_km_bridge_info_stays_card_warn_goes_global(self):
        reg = self._fresh_reg()
        reg.create(label="br", username="ub", password="pb")
        with reg._lock:
            aid = next(iter(reg._accounts))
        acc = reg.get(aid)
        before = {e.get("gseq") for e in reg.get_global_logs(0)}
        # invoke installed bridge if present
        self.assertTrue(hasattr(acc.km, "_log"))
        acc.km._log("INFO", "[9] Path B 成功 heart=True uptime=- status=-")
        acc.km._log("WARN", "Path B 连续失败 fail=3")
        card_msgs = [e["msg"] for e in acc.get_logs(0)]
        self.assertTrue(any("Path B 成功" in m for m in card_msgs))
        self.assertTrue(any("连续失败" in m for m in card_msgs))
        g_msgs = [e.get("msg", "") for e in reg.get_global_logs(0) if e.get("gseq") not in before]
        self.assertFalse(any("Path B 成功" in m for m in g_msgs), g_msgs)
        self.assertTrue(any("连续失败" in m for m in g_msgs), g_msgs)

    def test_delete_appends_global_lifecycle(self):
        reg = self._fresh_reg()
        reg.create(label="delme", username="ud", password="pd")
        with reg._lock:
            aid = next(iter(reg._accounts))
        before = {e.get("gseq") for e in reg.get_global_logs(0)}
        out = reg.delete(aid)
        self.assertTrue(out.get("ok"), out)
        g_msgs = [e.get("msg", "") for e in reg.get_global_logs(0) if e.get("gseq") not in before]
        self.assertTrue(
            any("删" in m or "移除" in m or "已删除" in m for m in g_msgs),
            f"delete must global-log lifecycle, got: {g_msgs}",
        )


class FrontendStickGateTest(unittest.TestCase):
    """Static source checks for #75fixao stick-to-bottom gate."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")

    def test_stick_state_and_helpers_present(self):
        for needle in (
            "globalStickBottom",
            "logFullStickBottom",
            "isNearBottom",
            "scrollLogIfStuck",
            "LOG_STICK_THRESHOLD_PX",
        ):
            self.assertIn(needle, self.js, f"missing stick helper: {needle}")

    def test_pull_global_logs_respects_stick(self):
        # pullGlobalLogs must not force unconditional scrollTop
        m = re.search(
            r"function pullGlobalLogs\(force\)\s*\{(?P<body>.*?)\n  \}",
            self.js,
            re.S,
        )
        self.assertIsNotNone(m, "pullGlobalLogs not found")
        body = m.group("body")
        self.assertIn("scrollLogIfStuck", body)
        self.assertIn("globalStickBottom", body)
        # raw force-to-bottom without stick is banned inside pull
        self.assertNotRegex(
            body,
            r"box\.scrollTop\s*=\s*box\.scrollHeight",
            "pullGlobalLogs must not force box.scrollTop",
        )

    def test_sync_modal_respects_stick(self):
        self.assertIn("scrollLogIfStuck(fullBody, state.logFullStickBottom)", self.js)
        self.assertIn("scrollLogIfStuck(body, state.logFullStickBottom)", self.js)

    def test_scroll_listeners_detach_stick(self):
        self.assertIn("state.globalStickBottom = isNearBottom", self.js)
        self.assertIn("state.logFullStickBottom = isNearBottom", self.js)


class LogSignatureContractTest(unittest.TestCase):
    def test_log_default_to_global_false(self):
        src = Path("web/account_runtime.py").read_text(encoding="utf-8")
        self.assertIn("def log(self, level: str, msg: str, *, to_global: bool = False)", src)
        self.assertIn('lvl_u in ("ERROR",)', src)


if __name__ == "__main__":
    unittest.main()
