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

        self.assertFalse(keepalive.keepalive_once(http))
        http.post.assert_called_once_with(config.Endpoint.USER_GET_INFO)


if __name__ == "__main__":
    unittest.main()
