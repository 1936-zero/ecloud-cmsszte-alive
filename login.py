"""
登录流程 —— 复刻 service/user.js。

密码登录链路 (loginWithPassword line 277-356):
  POST /login/verify {username, password, timestamp, clientNeedTwoFactor:true}
    ├ 成功 → body.accessTicket → verifyAccessTicket
    ├ errorCode 30002009 (未授信设备) → 需短信 + trustDevice
    ├ errorCode 30002060 (二次验证) → 需短信 + verifyTwoFactorAuthSms
    ├ errorCode 30002063 (增强策略) → 需短信 + verifyLoginEnhanceSms
    └ userId 字段 → 4A MFA 流程

verifyAccessTicket (line 448-480):
  POST /login/verifyAccessTicket {accessTicket} → accessToken
"""
import time
import json

import config
from ecloud_client import EcloudHttpUtil, EcloudError


class LoginResult:
    SUCCESS = "success"
    NEED_DEVICE_TRUST = "need_device_trust"      # 30002009
    NEED_TWO_FACTOR = "need_two_factor"          # 30002060
    NEED_ENHANCED_SMS = "need_enhanced_sms"      # 30002063
    NEED_4A = "need_4a"
    FAILED = "failed"


def _extract_error(resp: dict) -> str:
    """Extract a useful server-side failure message from a decoded response."""
    if not isinstance(resp, dict):
        return str(resp)
    for key in (
        "errorMessage", "message", "msg", "resultMsg", "resultMessage",
        "returnMessage", "desc", "description",
    ):
        if resp.get(key):
            return str(resp[key])
    body = resp.get("body")
    if isinstance(body, dict):
        nested = _extract_error(body)
        if nested and nested != "{}":
            return nested
    return json.dumps(resp, ensure_ascii=False)[:500]


# 全角数字 ０-９ → 半角 0-9（中文输入法/IME 常见坑）
_FULLWIDTH_DIGIT_TRANS = str.maketrans("０１２３４５６７８９", "0123456789")


def normalize_sms_code(code: str | None) -> str:
    """
    归一化短信验证码：去空白 + 全角数字转半角。
    真网实测输入 ３６５３３６（U+FF1x）会被服务端判 30002004 验证码失败。
    """
    if code is None:
        return ""
    s = str(code).strip().translate(_FULLWIDTH_DIGIT_TRANS)
    # 去掉中间空白/不可见字符，只保留数字与字母（验证码通常纯数字）
    s = "".join(ch for ch in s if not ch.isspace())
    return s


def login_with_password(http: EcloudHttpUtil, username: str, password: str) -> dict:
    """
    密码登录。返回 {"status": ..., "access_ticket": ..., "access_token": ..., ...}。

    若服务端要求短信验证/设备信任，返回 status=NEED_* 并带 mobile 字段，
    由调用方拿到短信后调 complete_login_with_sms() 继续流程。
    """
    try:
        resp = http.post(config.Endpoint.LOGIN_CHECK_USER_PASSWORD, {
            "username": username,
            "password": password,
            "timestamp": int(time.time() * 1000),
            "clientNeedTwoFactor": True,
        })
    except EcloudError as e:
        # 业务错误（未授信设备/二次验证等）—— errorCode 在异常里，需要解析分支
        return _classify_login_error(e, username)

    # 直接拿到 accessTicket（已授信设备 + 无需二次验证）
    ticket = resp.get("accessTicket") if isinstance(resp, dict) else None
    if ticket:
        token = _exchange_ticket(http, ticket)
        return {"status": LoginResult.SUCCESS, "access_ticket": ticket,
                "access_token": token, "user_info": resp}

    # 响应里没 ticket 也没异常，按错误分类处理
    if isinstance(resp, dict) and resp.get("errorCode"):
        return _classify_dict_error(resp, username)
    return {"status": LoginResult.SUCCESS, "access_token": None, "user_info": resp}


def _classify_login_error(e: EcloudError, username: str) -> dict:
    """把 EcloudError 转成分支状态。错误对象 resp 含 errorCode/errorMessage/body。"""
    resp = e.resp if isinstance(e.resp, dict) else {}
    code = str(resp.get("errorCode", "") or e.code or "")
    body = resp.get("body", {}) if isinstance(resp, dict) else {}
    if isinstance(body, str):
        try:
            import json
            body = json.loads(body)
        except Exception:
            body = {}
    mobile = body.get("mobile", "") if isinstance(body, dict) else ""
    login_code = body.get("code") if isinstance(body, dict) else None
    common = {
        "mobile": mobile,
        "login_code": login_code,
        "raw": resp,
        "error": e.message,
        "error_code": code,
    }

    if code == config.LoginError.UNTRUSTED_DEVICE:
        return {"status": LoginResult.NEED_DEVICE_TRUST, **common}
    if code == config.LoginError.TWO_FACTOR_AUTH:
        return {"status": LoginResult.NEED_TWO_FACTOR, **common}
    if code == config.LoginError.ENHANCED_STRATEGY:
        return {"status": LoginResult.NEED_ENHANCED_SMS, **common}
    if resp.get("userId"):
        return {"status": LoginResult.NEED_4A, "user_id": resp.get("userId"),
                "login_type": resp.get("loginType"), **common}
    return {"status": LoginResult.FAILED, **common}


def _classify_dict_error(resp: dict, username: str) -> dict:
    code = str(resp.get("errorCode", ""))
    body = resp.get("body", {}) if isinstance(resp.get("body"), dict) else {}
    mobile = body.get("mobile", "")
    common = {
        "mobile": mobile,
        "login_code": body.get("code"),
        "raw": resp,
        "error_code": code,
    }
    if code == config.LoginError.UNTRUSTED_DEVICE:
        return {"status": LoginResult.NEED_DEVICE_TRUST, **common}
    if code == config.LoginError.TWO_FACTOR_AUTH:
        return {"status": LoginResult.NEED_TWO_FACTOR, **common}
    if code == config.LoginError.ENHANCED_STRATEGY:
        return {"status": LoginResult.NEED_ENHANCED_SMS, **common}
    if resp.get("userId"):
        return {"status": LoginResult.NEED_4A, "user_id": resp.get("userId"),
                "login_type": resp.get("loginType"), **common}
    return {"status": LoginResult.FAILED, "error": resp.get("errorMessage"), **common}


def _exchange_ticket(http: EcloudHttpUtil, access_ticket: str) -> str | None:
    """
    accessTicket 换 accessToken (verifyAccessTicket line 448-480)。
    EcloudHttpUtil 内部会在 LOGIN_GET_TOKEN 分支自动 set_token。
    """
    body = http.post(config.Endpoint.LOGIN_GET_TOKEN, {"accessTicket": access_ticket})
    return body.get("accessToken") if isinstance(body, dict) else None


def send_sms(http: EcloudHttpUtil, mobile: str, code_type: str = "login") -> dict:
    """
    发送短信验证码 (sendSMSCode / certificaty 页面)。

    code_type 必须与后续校验场景一致，否则真网返回 30002004 验证码验证失败：
      - "login"  : 普通短信登录 / 部分 enhanced 分支
      - "forget" : 忘记密码
      - "trust"  : 未授信设备信任 (official certificaty: codeType:"trust")
    官方 electron service 只 POST {mobile, codeType}；前端多传的 type:"5" 不进后端。
    """
    return http.post(config.Endpoint.LOGIN_SEND_SMS, {
        "mobile": mobile,
        "codeType": code_type,
    })


def verify_sms(http: EcloudHttpUtil, mobile: str, verification_code: str,
               code_type: str = "login") -> dict:
    """验证通用短信验证码，部分登录分支会返回后续接口需要的 code。"""
    verification_code = normalize_sms_code(verification_code)
    return http.post(config.Endpoint.LOGIN_VERIFY_SMS, {
        "mobile": mobile,
        "verificationCode": verification_code,
        "codeType": code_type,
    })


def send_two_factor_sms(http: EcloudHttpUtil, mobile: str, username: str) -> dict:
    """发送二次验证短信。"""
    return http.post(config.Endpoint.LOGIN_AUTH_TWOFACTOR_GET, {
        "mobile": mobile,
        "userName": username,
    })


def complete_device_trust(http: EcloudHttpUtil, mobile: str,
                          verification_code: str, login_username: str = "",
                          is_temporary: bool = False, code: str | None = None) -> dict:
    """
    未授信设备 → 短信验证后信任/临时设备 (user.js loginTrustDevice)。

    官方 payload:
      {mobile, verificationCode, isNeedTemporaryDeviceSelection:true,
       code: this.code, loginUserName?}
    其中 code 来自密码登录 /login/verify 的 body.code，不是短信验证码。
    真网实测 30002009 时 body.code 常为 null；官方仍会传 code:this.code（可为 null），
    不可在客户端硬失败。成功后若返回 accessTicket，再走 temporaryDeviceSelection → verifyAccessTicket。
    """
    verification_code = normalize_sms_code(verification_code)
    # 官方始终带上 code 字段（可为 null/undefined）；勿因缺失直接拒绝
    payload = {
        "mobile": mobile,
        "verificationCode": verification_code,
        "isNeedTemporaryDeviceSelection": True,
        "code": code,
    }
    if login_username:
        payload["loginUserName"] = login_username
    resp = http.post(config.Endpoint.LOGIN_TRUST_DEVICE, payload)

    # 官方: accessTicket 后先让用户选永久/临时设备，再 verifyAccessTicket
    ticket = resp.get("accessTicket") if isinstance(resp, dict) else None
    if ticket:
        return _finish_after_ticket(http, ticket, is_temporary=is_temporary)

    if isinstance(resp, dict) and resp.get("userId"):
        return {
            "status": LoginResult.NEED_4A,
            "user_id": resp.get("userId"),
            "login_type": resp.get("loginType"),
            "raw": resp,
        }

    return {
        "status": LoginResult.FAILED,
        "raw": resp,
        "error": _extract_error(resp) or "信任设备后未返回 accessTicket",
    }


def _finish_after_ticket(http: EcloudHttpUtil, ticket: str,
                         is_temporary: bool = False) -> dict:
    """trust/twoFactor 拿到 accessTicket 后: temporaryDevice → exchange token。"""
    is_temp_val = 1 if is_temporary else 0
    http.post(config.Endpoint.LOGIN_TEMPORARY_DEVICE, {
        "accessTicket": ticket, "isTemporary": is_temp_val,
    })
    token = _exchange_ticket(http, ticket)
    return {
        "status": LoginResult.SUCCESS,
        "access_ticket": ticket,
        "access_token": token,
    }


def complete_two_factor(http: EcloudHttpUtil, mobile: str, username: str,
                        password: str, verification_code: str,
                        code: str | None = None) -> dict:
    """
    二次验证短信验证 (user.js loginTwoFactor)。
    官方 payload 含 code:this.code（密码登录 body.code）。
    短信发送由调用方先调用 send_two_factor_sms 完成。
    """
    verification_code = normalize_sms_code(verification_code)
    payload = {
        "mobile": mobile,
        "userName": username,
        "verificationCode": verification_code,
        "password": password,
    }
    if code:
        payload["code"] = code
    resp = http.post(config.Endpoint.LOGIN_AUTH_TWOFACTOR, payload)
    ticket = resp.get("accessTicket") if isinstance(resp, dict) else None
    if ticket:
        token = _exchange_ticket(http, ticket)
        return {"status": LoginResult.SUCCESS, "access_ticket": ticket,
                "access_token": token}
    if isinstance(resp, dict) and resp.get("userId"):
        return {
            "status": LoginResult.NEED_4A,
            "user_id": resp.get("userId"),
            "login_type": resp.get("loginType"),
            "raw": resp,
        }
    return {"status": LoginResult.FAILED, "raw": resp, "error": _extract_error(resp)}


def complete_enhanced_sms(http: EcloudHttpUtil, mobile: str, username: str,
                          verification_code: str,
                          code: str | None = None) -> dict:
    """
    增强策略短信 (user.js verifyLoginEnhanceSms)。
    """
    verification_code = normalize_sms_code(verification_code)
    payload = {
        "mobile": mobile,
        "verificationCode": verification_code,
        "userName": username,
    }
    if code:
        payload["code"] = code
    resp = http.post(config.Endpoint.LOGIN_ENHANCE_SMS, payload)
    ticket = resp.get("accessTicket") if isinstance(resp, dict) else None
    if ticket:
        token = _exchange_ticket(http, ticket)
        return {"status": LoginResult.SUCCESS, "access_ticket": ticket,
                "access_token": token}
    return {"status": LoginResult.FAILED, "raw": resp, "error": _extract_error(resp)}


def logout(http: EcloudHttpUtil) -> None:
    """登出 (user.js:235 logout)。"""
    try:
        http.post(config.Endpoint.LOGOUT)
    except EcloudError:
        pass
    finally:
        http.clear_token()


def get_user_info(http: EcloudHttpUtil) -> dict:
    """登录后拉取用户信息。

    官方：POST /user/getLoginUserInfo params={accessToken, deviceUid}
    （deviceUid / accessToken 由 EcloudHttpUtil.post 从 common_params + token 合并）
    勿调 /client/getSysConfig：该接口强制 type，会 9999100 type不能为空。
    """
    return http.post(config.Endpoint.USER_GET_INFO)


def get_device_list(http: EcloudHttpUtil) -> dict:
    """
    获取云桌面列表 (USER_GET_DEVICE_INFO)。
    用于保活前确认有可用桌面，也用于阶段2拿到连接信息。
    """
    return http.post(config.Endpoint.USER_GET_DEVICE_INFO)
