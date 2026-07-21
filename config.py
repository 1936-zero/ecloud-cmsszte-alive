"""
移动云电脑 V3.8.2 协议常量与密钥。

所有值均从已安装客户端的 app.asar 反混淆源码 + AES 解密的 settingValue.js 中提取并验证。
源码出处:
  - util/ecloudHttpUtil.js:189-204  (getFullurl 签名算法)
  - util/cryptoUtil.js              (RSA/AES/hash/hmac)
  - config/settingValue.js          (AES-256-CBC 加密的密钥 blob)
  - config/decryptSetting.js        (key = SHA256("Ecloud-Computer-"+platform))
  - util/deviceUtil.js:48-71        (commonParams 字段)
"""

# ---------------------------------------------------------------------------
# 服务端地址 (从 EcloudServerSecretKey.prod 解出)
# ---------------------------------------------------------------------------
BASE_URL = "https://cloudpc.ecloud.10086.cn"
API_PATH = "/api/cem/gateway/outer/cem-webapi"
BACKUP_DOMAINS = [
    "https://cloudpc1.ecloud.10086.cn",
    "https://cloudpc2.ecloud.10086.cn",
]
ACCESS_KEY = "53bb79015a3f47c4be166d9371f68f14"
SECRET_KEY = "6b0d3b93f3aa4c7ea076c841bead1ddd"

# ---------------------------------------------------------------------------
# RSA 密钥 (1024-bit, PKCS1 padding)
#   - 公钥: 加密每个请求的 JSON body -> {"params": base64}
#   - 私钥: 解密响应 body 的 RSA 密文
# ---------------------------------------------------------------------------
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G+t6
J0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6Ev1/UNX
E74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVXtV6phNkor
NyIahyfy46+iNB+FSQIDAQAB
-----END PUBLIC KEY-----"""

# 私钥 (PKCS#8, 从 settingValue.js 经 AES-256-CBC(kk/vv) 解密得到)。
# 仅用于解密服务端响应；不会泄露给服务端。
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKqKwkvti908L+Ak
Dt8uuvUb63onRqsmvSxV+J5UlNdNyWb/Zp8/9+M1hj8IVyDUxTHwo+Y8LYKqxQdE
xmroS/X9Q1cTvgjVN8kL/Zvxp7Fx1n4uiSPsDDOsz3I/Lap9Xq9e3HJGtOz4lwUd
Ve1XqmE2Sis3IhqHJ/Ljr6I0H4VJAgMBAAECgYBD6lx0BlajtRtPxKxTfvWfNQ4y
qD+BWz0M0fPfgcmAcI7bQKyqkLv0NNWQdo7UGUeqmq16u85X8g/i1CW8X2QYHOSY
NBUWsK3k5gFT1wdk+bwuIMZqgjEc48TXzM4pidcplJLyD1tnNiubzcXIsZCIIuQ/
GmWcuxn7ULHnXDsQMQJBANMl4V97be6fkd1beGqYZWIx3XNnL96AQsapBrEbbORT
u/JnwTCRbsRWRBHU11FZuK85dBDXrH8reoAsgepmsF0CQQDOxL99OFjozj8g1weF
GwI/otMKcPhkaslU2tj3QF44zT1TZiOZ710I8GQLPlKeu1yGWvVUwgH4bCY0M8M1
/gndAkB9sU4RTeOqKjllwT7UjbXEl5SRTzrSxB18L0B5i67t2N7INXVumRSMMiJB
TyeCGNv1C0mJgSoBZft9c4E+7TRNAkB+7Azza7Q/6+KaYQRPs32U3HkZbrE6ysYd
XV1ToOJ1kZ60Y/00j9cXFqECudXzc+Ve39S6m4CkIpbs8l1A9ljNAkBy6Rp19R5w
WMr/3feIMZ18akWXT5mgRvZpkT5MgmrjVu1lRv8bHsEsAzRYvdPSjzp0nCkUbOWU
ITxWp7d//Fwc
-----END PRIVATE KEY-----"""

# RSA 分块大小 (RSA-1024: 加密块 117 字节，解密块 128 字节)
RSA_ENCRYPT_CHUNK = 117   # modulusLength/8 - 11  (cryptoUtil.js:43)
RSA_DECRYPT_CHUNK = 128   # modulusLength/8       (cryptoUtil.js:19)

# ---------------------------------------------------------------------------
# 签名常量 (ecloudHttpUtil.js:203-204)
# ---------------------------------------------------------------------------
SIGN_METHOD = "HmacSHA1"
SIGN_VERSION = "V2.0"
HMAC_KEY_PREFIX = "BC_SIGNATURE&"   # 拼在 secretKey 前作为 HMAC key

# ---------------------------------------------------------------------------
# HTTP 客户端常量
# ---------------------------------------------------------------------------
API_TIMEOUT = 30          # ecloudHttpUtil.js API_TIMEOUT = 0x7530 (30s)
LOGIN_TIMEOUT = 10        # 登录类接口 0x2710 (10s)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "EcloudCloudComputer/3.8.2"
)

# ---------------------------------------------------------------------------
# API 端点 (EcloudServerUrl 常量 -> 真实路径，见 service/user.js 调用上下文)
# ---------------------------------------------------------------------------
class Endpoint:
    # 登录
    LOGIN_CHECK_USER_PASSWORD = "/login/verify"              # 密码登录 -> accessTicket
    LOGIN_GET_TOKEN           = "/login/verifyAccessTicket"  # ticket -> accessToken
    LOGIN_CHECK_MOBILE        = "/login/checkMobile"
    LOGIN_SEND_SMS            = "/login/sendVerifySms"
    LOGIN_VERIFY_SMS          = "/login/verifySms"
    LOGIN_QR_CODE             = "/login/getQRCode"
    LOGIN_QR_LOGIN_RESULT     = "/login/getQRLoginResult"
    LOGIN_TRUST_DEVICE        = "/login/trustDevice"
    LOGIN_TEMPORARY_DEVICE    = "/login/trustOrTemporaryDevice"
    LOGIN_AUTH_TWOFACTOR_GET  = "/login/special/getSecondauthSms"
    LOGIN_AUTH_TWOFACTOR      = "/login/verifyTwoFactorAuthSms"
    LOGIN_AUTH_4A_SMS         = "/user/getUserNameBySmsAuth"
    LOGIN_AUTH_4A             = "/login/special/secondauthBy4a"
    LOGIN_ENHANCE_SMS         = "/login/verifyLoginEnhanceSms"
    LOGIN_AD_LOGIN            = "/login/adUserLogin"
    LOGIN_AD_RESULT           = "/login/getAdLoginResult"
    LOGIN_SIM_CODE            = "/login/simVerify"
    LOGIN_SIM_LOGIN_RESULT    = "/login/getSimLoginResult"
    LOGIN_NEW_BY_CODE         = "/login/loginByCode"
    LOGOUT                    = "/login/logout"

    # 用户/设备
    # 官方 electron USER_GET_INFO = /user/getLoginUserInfo（body: accessToken+deviceUid）
    # 历史误写成 /client/getSysConfig → 服务端 9999100 type不能为空（该接口必填 type）
    USER_GET_INFO             = "/user/getLoginUserInfo"
    # 系统配置（需 type，如 DEVICE_PERFORMANCE_BATCH_PERIOD）；勿当用户信息接口
    GET_SYS_CONFIG            = "/client/getSysConfig"
    USER_GET_DEVICE_INFO      = "/user/getDeviceInfo"
    GET_SYS_TIME              = "/user/getSysTime"
    SET_NEW_PWD               = "/user/setNewPwd"

    # 探针上报 (登录态保活)
    PROBE_QKK_BATCHPUSH       = "/login/batchPushLoginQkk"

    # 桌面会话保活（抓包逆向，见 desktop_session.py）
    DESKTOP_UPTIME            = "/resource/desktopUptime"          # 桌面运行时长查询/刷新 ⭐保活核心
    SESSION_MACHINE_CONNECT   = "/session/machineConnect"          # 桌面会话登记/保活
    PUSH_CONNECT_EVENT        = "/machine/pushConnectEventData"    # 连接事件上报(CloudEvents)
    GET_DESKTOP_LIST          = "/resource/getDesktopList"         # 桌面列表(推测路径)

    # 桌面列表与操作（渲染层 bundle 逆向，index-53f3f1a5.js）
    GET_DEVICE_INFO           = "/user/getDeviceInfo"              # 桌面列表 → body.machineList[]
    GET_DESKTOP_STATUS        = "/user/getDesktopStatus"           # 桌面状态 → body.machineStatusList[]
    RESOURCE_OPERATE          = "/resource/operate"                # 桌面开关机 {operate:startup|shutdown|restart}
    UPDATE_SESSION_STATUS     = "/session/updateSessionStatus"     # 会话状态更新

# 登录类端点 (10s 超时 + 备用域名重试，ecloudHttpUtil.js:28 LOGIN_PATHS)
LOGIN_PATHS = {
    Endpoint.LOGIN_CHECK_USER_PASSWORD,
    Endpoint.LOGIN_QR_CODE,
    Endpoint.LOGIN_CHECK_MOBILE,
    Endpoint.LOGIN_AD_LOGIN,
}

# ---------------------------------------------------------------------------
# 业务常量
# ---------------------------------------------------------------------------
COMPANY_CODE   = "ECloud"
CLIENT_VERSION = "3.8.2"
CHANNEL_VERSION = "23"

# 登录错误码 (service/user.js:67-74 LoginRespError)
class LoginError:
    UNTRUSTED_DEVICE   = "30002009"   # 未授信设备 -> 需短信信任
    TWO_FACTOR_AUTH    = "30002060"   # 二次验证
    ENHANCED_STRATEGY  = "30002063"   # 增强策略短信
    FEISHU_BIND        = "10002039"
    REFRESH_FS_QRCODE  = "30002026"

# 登录方式 (service/user.js:22-31 LoginType)
class LoginType:
    PASSWORD     = 0
    SMS          = 1
    QRCODE       = 2
    SIM          = 3
    FORGET_PWD   = 4
    AD_CONNECTOR = 5
    FEISHU_QR    = 6
    MULTI_ACCT   = 7
