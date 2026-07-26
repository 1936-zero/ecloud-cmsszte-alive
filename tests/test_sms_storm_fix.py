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


if __name__ == "__main__":
    unittest.main()
