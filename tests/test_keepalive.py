import unittest
from unittest.mock import Mock

import config
import keepalive
from ecloud_client import EcloudError


class AccountKeepaliveTests(unittest.TestCase):
    def test_non_token_probe_failure_does_not_hide_device_list_success(self):
        http = Mock()

        def post(endpoint, payload=None):
            # 非 token 失效错误：USER_GET_INFO 失败不应掩盖后续 device list 成功
            if endpoint == config.Endpoint.USER_GET_INFO:
                raise EcloudError({
                    "errorCode": "9999100",
                    "errorMessage": "temporary upstream error",
                })
            if endpoint == config.Endpoint.USER_GET_DEVICE_INFO:
                return {"deviceInfos": []}
            if endpoint == config.Endpoint.PROBE_QKK_BATCHPUSH:
                raise EcloudError({
                    "errorCode": "PROBE_FAIL",
                    "errorMessage": "probe unavailable",
                })
            raise AssertionError(endpoint)

        http.post.side_effect = post

        self.assertTrue(keepalive.keepalive_once(http))

    def test_token_error_still_requests_relogin(self):
        http = Mock()
        http.post.side_effect = EcloudError({
            "errorCode": "401",
            "errorMessage": "token expired",
        })

        # 所有会话端点都 token 失效 → 真失效 → keepalive_once() 返回 False（需重登）。
        self.assertFalse(keepalive.keepalive_once(http))
        # 修复后不再在首个端点 401 就早退：会先复核 getDeviceInfo，确认整条会话确实
        # 死了才判失效。单端 getLoginUserInfo 401 而 getDeviceInfo 仍活 → 不重登
        # （见 test_sms_storm_fix.py），这是根除设备信任短信风暴的关键。
        called = [c.args[0] for c in http.post.call_args_list]
        self.assertIn(config.Endpoint.USER_GET_INFO, called)
        self.assertIn(config.Endpoint.USER_GET_DEVICE_INFO, called)


if __name__ == "__main__":
    unittest.main()
