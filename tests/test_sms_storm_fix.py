"""Regression: a lone /user/getLoginUserInfo 401 must NOT trigger password relogin.

真网故障复盘：/user/getLoginUserInfo 对仍然有效的 token 间歇性返回「[401] token失效」，
而同一 token 的 /user/getDeviceInfo、SPICE heart 仍成功。旧逻辑据单端 401 就密码重登，
每 ~30 分钟一次 /login/verify → 服务端风控 → 手机设备信任/验证码短信轰炸。
修复后：只有【所有会话端点都失效】才判 token 死去重登；任一端点成功即视为会话存活。
"""
import os
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import keepalive
from ecloud_client import EcloudError
from l3 import spice_oracle_keepalive_loop as sok


def _token_401(msg="token失效"):
    return EcloudError({"errorCode": "401", "errorMessage": msg})


def _http_by_endpoint(mapping):
    """mapping: endpoint -> value or Exception (raised). Missing -> {'ok':True}."""
    http = Mock()

    def _post(ep, *a, **k):
        v = mapping.get(ep, {"ok": True})
        if isinstance(v, Exception):
            raise v
        return v

    http.post.side_effect = _post
    return http


class TestKeepaliveProbeNoFalseRelogin(unittest.TestCase):
    def test_lone_getinfo_401_but_deviceinfo_ok_is_alive(self):
        """getLoginUserInfo 401，但 getDeviceInfo 成功 → ok=True，绝不重登。"""
        http = _http_by_endpoint({config.Endpoint.USER_GET_INFO: _token_401()})
        out = keepalive.keepalive_probe(http)
        self.assertIs(out.ok, True)  # NOT False → no password relogin → no SMS

    def test_all_endpoints_token_dead_still_false(self):
        """所有端点都 token 失效 → 真失效 → ok=False（合法单次重登）。"""
        http = Mock()
        http.post.side_effect = lambda ep, *a, **k: (_ for _ in ()).throw(_token_401())
        out = keepalive.keepalive_probe(http)
        self.assertIs(out.ok, False)
        self.assertIn("401", out.error)


class TestAccountPingNoFalseRelogin(unittest.TestCase):
    def test_lone_getinfo_401_but_deviceinfo_ok_not_expired(self):
        http = _http_by_endpoint({config.Endpoint.USER_GET_INFO: _token_401()})
        ap = sok._account_ping(http)
        self.assertFalse(ap["token_expired"])  # no relogin
        self.assertTrue(ap["ok"])

    def test_both_endpoints_token_dead_is_expired(self):
        http = _http_by_endpoint({
            config.Endpoint.USER_GET_INFO: _token_401(),
            config.Endpoint.USER_GET_DEVICE_INFO: _token_401("登录失效"),
        })
        ap = sok._account_ping(http)
        self.assertTrue(ap["token_expired"])  # real expiry → allowed to relogin

    def test_transient_non_token_error_not_expired(self):
        http = _http_by_endpoint({
            config.Endpoint.USER_GET_INFO: EcloudError(
                {"errorCode": "502", "errorMessage": "bad gateway"}
            ),
        })
        ap = sok._account_ping(http)
        self.assertFalse(ap["token_expired"])  # 5xx is not token death


class TestOracleAliveClearsTokenExpired(unittest.TestCase):
    def test_status_ok_uptime_token_err_not_expired(self):
        """状态面成功证明会话存活 → 即便 uptime 报 token 错也不重登。"""
        import desktop_list
        import desktop_session

        orig_status = desktop_list.get_desktop_status
        orig_session = desktop_session.DesktopSession
        try:
            desktop_list.get_desktop_status = lambda http, ds: {"CCA-x": "available"}

            class _Sess:
                last_uptime = ""

                def __init__(self, *a, **k):
                    pass

                def report_uptime(self):
                    raise _token_401()

            desktop_session.DesktopSession = _Sess
            out = sok._oracle_once(Mock(), instance_id="CCA-x", machine_id="m")
            self.assertFalse(out["token_expired"])  # session alive → no relogin
            self.assertTrue(out["oracle_ok"])
        finally:
            desktop_list.get_desktop_status = orig_status
            desktop_session.DesktopSession = orig_session


class TestUptimeTokenExpiryNotOverbroad(unittest.TestCase):
    """desktopUptime 失败：只有真 token 错误才触发重登；非 token 错误绝不重登。"""

    def test_real_token_error_flags_expired(self):
        import desktop_session
        for msg in ("token失效", "token验证失败", "登录失效", "请重新登录", "授权过期"):
            self.assertTrue(
                desktop_session._is_token_expired(
                    EcloudError({"errorCode": "401", "errorMessage": msg})
                ),
                msg,
            )

    def test_non_token_errors_do_not_relogin(self):
        import desktop_session
        # 关机 / accessKey / access denied / instanceId 无效 → 不是 token 失效
        for msg in (
            "desktopUptime 未返回运行时长，桌面可能已关机",
            "accessKey invalid",
            "no access to desktop",
            "instanceId 无效",
        ):
            self.assertFalse(
                desktop_session._is_token_expired(
                    EcloudError({"errorCode": "500", "errorMessage": msg})
                ),
                msg,
            )


class TestOracleUptimeDoesNotOwnTokenLiveness(unittest.TestCase):
    """拿不到状态/在线时长不应据此重登：account ping 开着时 oracle 一律不重登。

    token 死活是账号保活(getLoginUserInfo+getDeviceInfo)的职责，不是 desktopUptime
    的职责。account ping 关闭(独立桌面保活)时才保留一次兜底重登。
    """

    def _run_one_round(self, do_account_ping):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock, patch

        relogin = Mock(return_value="new-token")
        http = Mock()
        http.set_token = Mock()
        out = Path(tempfile.mkdtemp(prefix="ora_"))
        plain = out / "connectstr.plain"
        plain.write_text("dummy-connectstr-for-test\n")  # 存在即可(heart 已 patch)
        # account ping 永远健康(token 没死)；oracle 却报 token_expired
        with patch.object(sok, "_account_ping",
                          return_value={"ok": True, "token_expired": False}), \
             patch.object(sok, "_oracle_once",
                          return_value={"token_expired": True, "oracle_ok": False,
                                        "resource_status": "", "uptime": ""}), \
             patch.object(sok, "run_path_b_keepalive",
                          return_value={"heart_count": 1, "error": None}):
            sok.run_spice_oracle_keepalive_loop(
                http=http, instance_id="CCA-1", machine_id="m",
                plain=plain, pre=out, post=out,
                heart_listen=0.0, interval=0, max_rounds=1, out_dir=out,
                relogin_fn=relogin, do_account_ping=do_account_ping,
                auto_remint=False, mid_session_reconnect=False,
            )
        return relogin

    def test_account_ping_on_oracle_never_relogins(self):
        relogin = self._run_one_round(do_account_ping=True)
        relogin.assert_not_called()  # oracle 的 uptime/status 错误不再触发重登

    def test_account_ping_off_oracle_relogins_as_fallback(self):
        relogin = self._run_one_round(do_account_ping=False)
        relogin.assert_called()  # 独立桌面保活时 oracle 是唯一 token 触点，兜底重登


class TestHeadlessLoginNeverSendsSms(unittest.TestCase):
    """systemd/headless relogin 命中 NEED_*_SMS 时：不发短信、抛 ManualAuthRequired。

    这是设备信任短信轰炸的直接根因守卫：旧代码在 systemd 服务里每次重启都会
    login.send_sms 发一条设备信任验证码，永远无人输入 → 退出 → 重启 → 再发。
    """

    def _run(self, status):
        import main
        from unittest.mock import MagicMock, patch

        res = {"status": status, "mobile": "18701080357", "login_code": None}
        cfg = {"username": "u", "password": "p"}
        with patch.object(main.login, "login_with_password", return_value=res), \
             patch.object(main.login, "send_sms") as send_sms, \
             patch.object(main.login, "send_two_factor_sms") as send_2fa, \
             patch.object(main, "_stdin_is_interactive", return_value=False), \
             patch.object(main, "build_client", return_value=MagicMock()), \
             patch.object(main, "save_config"):
            with self.assertRaises(main.ManualAuthRequired):
                main.do_login(cfg)
            self.assertEqual(send_sms.call_count, 0)
            self.assertEqual(send_2fa.call_count, 0)

    def test_device_trust_headless_no_sms(self):
        import login
        self._run(login.LoginResult.NEED_DEVICE_TRUST)

    def test_two_factor_headless_no_sms(self):
        import login
        self._run(login.LoginResult.NEED_TWO_FACTOR)

    def test_enhanced_headless_no_sms(self):
        import login
        self._run(login.LoginResult.NEED_ENHANCED_SMS)


if __name__ == "__main__":
    unittest.main()
