"""SMS / device-trust login path tests (aligned with official loginTrustDevice)."""
import unittest
from unittest.mock import Mock, call, patch

import config
import login
from ecloud_client import EcloudError


class SendSmsCodeTypeTests(unittest.TestCase):
    def test_send_sms_default_login(self):
        http = Mock()
        http.post.return_value = {"ok": True}
        login.send_sms(http, "13800000000")
        http.post.assert_called_once_with(
            config.Endpoint.LOGIN_SEND_SMS,
            {"mobile": "13800000000", "codeType": "login"},
        )

    def test_send_sms_trust_for_device_certificaty(self):
        """对齐官方 certificaty: codeType=trust（非 login）。"""
        http = Mock()
        http.post.return_value = {"ok": True}
        login.send_sms(http, "13800000000", code_type="trust")
        http.post.assert_called_once_with(
            config.Endpoint.LOGIN_SEND_SMS,
            {"mobile": "13800000000", "codeType": "trust"},
        )


class NormalizeSmsCodeTests(unittest.TestCase):
    def test_fullwidth_digits_to_halfwidth(self):
        self.assertEqual(login.normalize_sms_code("３６５３３６"), "365336")

    def test_strips_spaces(self):
        self.assertEqual(login.normalize_sms_code(" 12 34 56 "), "123456")

    def test_none_and_empty(self):
        self.assertEqual(login.normalize_sms_code(None), "")
        self.assertEqual(login.normalize_sms_code(""), "")


class CompleteDeviceTrustTests(unittest.TestCase):
    def test_fullwidth_code_normalized_in_payload(self):
        http = Mock()
        http.post.side_effect = [
            {"accessTicket": "ticket-1"},
            {"ok": True},
            {"accessToken": "token-1"},
        ]
        result = login.complete_device_trust(
            http,
            mobile="13800000000",
            verification_code="３６５３３６",
            login_username="user",
            code=None,
        )
        self.assertEqual(result["status"], login.LoginResult.SUCCESS)
        payload = http.post.call_args_list[0][0][1]
        self.assertEqual(payload["verificationCode"], "365336")

    def test_null_login_code_still_posts_trust_device(self):
        """真网 30002009 body.code 常为 null；官方仍带 code 字段调用 trustDevice。"""
        http = Mock()
        http.post.side_effect = [
            {"accessTicket": "ticket-null-code"},
            {"ok": True},
            {"accessToken": "token-null"},
        ]
        result = login.complete_device_trust(
            http, "13800000000", "123456", "user", code=None,
        )
        self.assertEqual(result["status"], login.LoginResult.SUCCESS)
        first = http.post.call_args_list[0]
        self.assertEqual(first.args[0], config.Endpoint.LOGIN_TRUST_DEVICE)
        self.assertIsNone(first.args[1]["code"])
        self.assertEqual(first.args[1]["mobile"], "13800000000")
        self.assertEqual(first.args[1]["verificationCode"], "123456")
        self.assertTrue(first.args[1]["isNeedTemporaryDeviceSelection"])

    def test_trust_device_posts_official_payload_and_finishes_ticket(self):
        http = Mock()
        http.post.side_effect = [
            {"accessTicket": "ticket-1"},  # trustDevice
            {"ok": True},                   # temporaryDeviceSelection
            {"accessToken": "token-1"},     # getToken
        ]

        result = login.complete_device_trust(
            http,
            mobile="13800000000",
            verification_code="654321",
            login_username="user@tenant",
            is_temporary=False,
            code="login-session-code",
        )

        self.assertEqual(result["status"], login.LoginResult.SUCCESS)
        self.assertEqual(result["access_token"], "token-1")
        self.assertEqual(result["access_ticket"], "ticket-1")

        first = http.post.call_args_list[0]
        self.assertEqual(first.args[0], config.Endpoint.LOGIN_TRUST_DEVICE)
        payload = first.args[1]
        self.assertEqual(payload["mobile"], "13800000000")
        self.assertEqual(payload["verificationCode"], "654321")
        self.assertEqual(payload["code"], "login-session-code")
        self.assertTrue(payload["isNeedTemporaryDeviceSelection"])
        self.assertEqual(payload["loginUserName"], "user@tenant")
        # must never call generic verifySms on trust path
        called_eps = [c.args[0] for c in http.post.call_args_list]
        self.assertNotIn(config.Endpoint.LOGIN_VERIFY_SMS, called_eps)
        self.assertEqual(
            called_eps,
            [
                config.Endpoint.LOGIN_TRUST_DEVICE,
                config.Endpoint.LOGIN_TEMPORARY_DEVICE,
                config.Endpoint.LOGIN_GET_TOKEN,
            ],
        )
        temp_payload = http.post.call_args_list[1].args[1]
        self.assertEqual(temp_payload, {"accessTicket": "ticket-1", "isTemporary": 0})

    def test_trust_device_temporary_flag(self):
        http = Mock()
        http.post.side_effect = [
            {"accessTicket": "t2"},
            {"ok": True},
            {"accessToken": "tok2"},
        ]
        result = login.complete_device_trust(
            http, "139", "111111", code="c", is_temporary=True,
        )
        self.assertEqual(result["status"], login.LoginResult.SUCCESS)
        temp_payload = http.post.call_args_list[1].args[1]
        self.assertEqual(temp_payload["isTemporary"], 1)


class CompleteTwoFactorTests(unittest.TestCase):
    def test_two_factor_includes_login_code(self):
        http = Mock()
        http.post.side_effect = [
            {"accessTicket": "tf-ticket"},
            {"accessToken": "tf-token"},
        ]
        result = login.complete_two_factor(
            http, "138", "user", "pwd", "sms", code="session-code",
        )
        self.assertEqual(result["status"], login.LoginResult.SUCCESS)
        payload = http.post.call_args_list[0].args[1]
        self.assertEqual(payload["code"], "session-code")
        self.assertEqual(payload["verificationCode"], "sms")
        self.assertEqual(payload["password"], "pwd")


class ClassifyLoginErrorTests(unittest.TestCase):
    def test_untrusted_device_extracts_login_code(self):
        err = EcloudError({
            "errorCode": config.LoginError.UNTRUSTED_DEVICE,
            "errorMessage": "untrusted",
            "body": {"mobile": "13800000000", "code": "sess-abc"},
        })
        result = login._classify_login_error(err, "user")
        self.assertEqual(result["status"], login.LoginResult.NEED_DEVICE_TRUST)
        self.assertEqual(result["login_code"], "sess-abc")
        self.assertEqual(result["mobile"], "13800000000")


class WebSmsApiTests(unittest.TestCase):
    def setUp(self):
        try:
            from web import server
        except Exception as e:
            self.skipTest(f"web deps unavailable: {e}")
        self.server = server
        server._app_state.update({
            "http": None,
            "cfg": {},
            "username": "",
            "password": "",
            "mobile": "",
            "login_type": "",
            "login_code": None,
        })
        # Local data/webui_access_token or ECLOUD_WEBUI_TOKEN must not block /api/* in unit tests.
        self._access_token_patcher = patch.object(server, "_read_access_token", return_value="")
        self._access_token_patcher.start()
        try:
            import login_rate_limit as _lrl
            _lrl.reset_for_tests()
        except Exception:
            pass

    def tearDown(self):
        patcher = getattr(self, "_access_token_patcher", None)
        if patcher is not None:
            patcher.stop()

    def test_send_sms_does_not_overwrite_login_code(self):
        server = self.server
        app = server.create_app()
        fake_http = Mock()
        server._app_state.update({
            "http": fake_http,
            "mobile": "13800000000",
            "login_type": "device_trust",
            "login_code": "keep-me",
            "username": "user",
        })

        with patch("web.server.login.send_sms", return_value={"code": "should-not-use"}) as send_sms:
            data = app.test_client().post(
                "/api/send-sms",
                json={"mobile": "13800000000"},
            ).get_json()

        self.assertTrue(data["ok"])
        # device_trust 必须 codeType=trust（官方 certificaty）
        send_sms.assert_called_once_with(fake_http, "13800000000", code_type="trust")
        self.assertEqual(server._app_state["login_code"], "keep-me")

    def test_verify_sms_device_trust_allows_null_login_code(self):
        """login_code 为 null 时仍应调用 complete_device_trust（对齐官方）。"""
        server = self.server
        app = server.create_app()
        fake_http = Mock()
        server._app_state.update({
            "http": fake_http,
            "mobile": "13800000000",
            "login_type": "device_trust",
            "login_code": None,
            "username": "user",
            "password": "pwd",
            "cfg": {},
        })
        with patch("web.server.login.complete_device_trust", return_value={
            "status": login.LoginResult.SUCCESS,
            "access_token": "new-token-abcdefghijklmnopqrstuvwxyz",
        }) as complete, patch("web.server._save_cfg"):
            data = app.test_client().post(
                "/api/verify-sms",
                json={"code": "123456", "login_type": "device_trust"},
            ).get_json()
        self.assertEqual(data["status"], "success")
        complete.assert_called_once_with(
            fake_http, "13800000000", "123456", "user", code=None,
        )

    def test_verify_sms_device_trust_passes_login_code(self):
        server = self.server
        app = server.create_app()
        fake_http = Mock()
        server._app_state.update({
            "http": fake_http,
            "mobile": "13800000000",
            "login_type": "device_trust",
            "login_code": "sess-xyz",
            "username": "user",
            "password": "pwd",
            "cfg": {},
        })
        with patch("web.server.login.complete_device_trust", return_value={
            "status": login.LoginResult.SUCCESS,
            "access_token": "new-token-abcdefghijklmnopqrstuvwxyz",
        }) as complete, patch("web.server._save_cfg"):
            data = app.test_client().post(
                "/api/verify-sms",
                json={"code": "654321", "login_type": "device_trust"},
            ).get_json()

        self.assertEqual(data["status"], "success")
        complete.assert_called_once_with(
            fake_http, "13800000000", "654321", "user", code="sess-xyz",
        )
        self.assertIsNone(server._app_state["login_code"])


if __name__ == "__main__":
    unittest.main()
