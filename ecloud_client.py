"""
移动云电脑 HTTP 客户端 —— 1:1 复刻 util/ecloudHttpUtil.js。

每个请求两层加密:
  1. URL 查询串带 HmacSHA1 签名 (getFullurl, line 189-204)
  2. JSON body 整体 RSA-1024 加密 -> {"params": base64} (line 127-152)

响应也是 RSA 加密的 {"params": base64}，用私钥分块解密 (line 159-163)。
"""
import hashlib
import hmac
import json
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import config


def _load_rsa_pub() -> RSA.RsaKey:
    return RSA.import_key(config.PUBLIC_KEY_PEM)


def _load_rsa_priv() -> RSA.RsaKey:
    return RSA.import_key(config.PRIVATE_KEY_PEM)


# 模块级单例（避免每个请求重新解析 PEM）
_PUB = None
_PRIV = None


def _get_pub():
    global _PUB
    if _PUB is None:
        _PUB = _load_rsa_pub()
    return _PUB


def _get_priv():
    global _PRIV
    if _PRIV is None:
        _PRIV = _load_rsa_priv()
    return _PRIV


def rsa_encrypt(plaintext: str) -> str:
    """
    RSA-1024 PKCS1 分块加密，返回 base64。
    复刻 cryptoUtil.js rsaEncrypt (line 39-66)。
    """
    key = _get_pub()
    cipher = PKCS1_v1_5.new(key)
    data = plaintext.encode("utf-8")
    chunk_size = config.RSA_ENCRYPT_CHUNK  # 117
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        out += cipher.encrypt(data[i:i + chunk_size])
    import base64
    return base64.b64encode(bytes(out)).decode("ascii")


def rsa_decrypt(ciphertext_b64: str) -> str:
    """
    RSA-1024 PKCS1 分块解密 base64 密文，返回 UTF-8 字符串。
    复刻 cryptoUtil.js rsaDecrypt (line 5-38)。
    """
    import base64
    key = _get_priv()
    cipher = PKCS1_v1_5.new(key)
    ct = base64.b64decode(ciphertext_b64)
    chunk_size = config.RSA_DECRYPT_CHUNK  # 128
    out = bytearray()
    for i in range(0, len(ct), chunk_size):
        block = ct[i:i + chunk_size]
        # PKCS1_v1_5.decrypt 需要一个 sentinel 用于解密失败时返回
        out += cipher.decrypt(block, b"")
    return out.decode("utf-8", errors="replace")


def _sha256_hex(s: str) -> str:
    """cryptoUtil.js hashStr (line 104-107)。"""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hmac_sha1_hex(data: str, key: str) -> str:
    """cryptoUtil.js shaMacStr (line 108-111)。"""
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha1).hexdigest()


def _build_signed_url(endpoint: str) -> str:
    """
    构造带 HmacSHA1 签名的完整 URL。
    严格复刻 ecloudHttpUtil.js getFullurl (line 189-204)。
    """
    # 时间戳：UTC+8，格式 YYYY-MM-DDTHH:MM:SSZ
    # 源码: now + 8h 偏移后取 ISO 字符串前 19 位 + 'Z'
    now_utc8 = datetime.now(timezone.utc) + timedelta(hours=8)
    timestamp = now_utc8.strftime("%Y-%m-%dT%H:%M:%SZ")

    # JS 用 querystring.stringify，保持插入顺序（Python dict 自 3.7 保序）
    query = {
        "AccessKey": config.ACCESS_KEY,
        "SignatureMethod": config.SIGN_METHOD,
        "SignatureNonce": uuid.uuid4().hex,  # uuidv4 去掉 '-'
        "SignatureVersion": config.SIGN_VERSION,
        "Timestamp": timestamp,
    }
    canonical = urllib.parse.urlencode(query)  # 对应 querystring.stringify

    # stringToSign = "POST\n" + encodeURIComponent(apiPath + endpoint) + "\n" + sha256(canonical)
    # 注意：JS encodeURIComponent 把 '/' 编码成 %2F；Python quote(safe='') 等价
    full_api_path = config.API_PATH + endpoint
    encoded_path = urllib.parse.quote(full_api_path, safe="")
    hash_step = _sha256_hex(canonical)
    string_to_sign = f"POST\n{encoded_path}\n{hash_step}"

    signing_key = config.HMAC_KEY_PREFIX + config.SECRET_KEY
    signature = _hmac_sha1_hex(string_to_sign, signing_key)
    query["Signature"] = signature

    return f"{config.BASE_URL}{config.API_PATH}{endpoint}?{urllib.parse.urlencode(query)}"


class EcloudError(Exception):
    """服务端返回 state != OK 或带 errorMessage。"""
    def __init__(self, resp: dict):
        self.code = resp.get("errorCode", "")
        self.message = resp.get("errorMessage", str(resp))
        self.resp = resp
        super().__init__(f"[{self.code}] {self.message}")


class EcloudHttpUtil:
    """
    单例式 HTTP 客户端，对应 ecloudHttpUtil.js 的 EcloudHttpUtil 类。
    """

    def __init__(self, common_params: dict):
        self.common_params = common_params
        self.access_token: str | None = None
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": config.USER_AGENT,
        })

    def set_token(self, token: str | None) -> None:
        self.access_token = token

    def clear_token(self) -> None:
        self.access_token = None

    def post(self, endpoint: str, payload: dict | None = None,
             base_url: str | None = None) -> dict:
        """
        发起一个已签名的 POST 请求并返回解密后的 body。
        :param endpoint: Endpoint.XXX 常量
        :param payload: 业务参数（会与 commonParams、accessToken 合并后 RSA 加密）
        :param base_url: 备用域名重试时传入；默认 config.BASE_URL
        :raises EcloudError: 服务端返回错误
        """
        payload = payload or {}
        # 合并 body (ecloudHttpUtil.js:127-133)
        merged = {**payload, **self.common_params}
        if self.access_token:
            merged["accessToken"] = self.access_token

        encrypted = rsa_encrypt(json.dumps(merged, ensure_ascii=False))
        http_body = {"params": encrypted}

        url = self._url_for(endpoint, base_url)
        timeout = config.LOGIN_TIMEOUT if endpoint in config.LOGIN_PATHS else config.API_TIMEOUT

        resp = self._session.post(url, data=json.dumps(http_body), timeout=timeout)
        return self._handle_response(resp, endpoint)

    def _url_for(self, endpoint: str, base_url: str | None) -> str:
        """构造签名 URL；支持备用域名（base_url 替换）。"""
        full = _build_signed_url(endpoint)
        if base_url and base_url != config.BASE_URL:
            full = full.replace(config.BASE_URL, base_url, 1)
        return full

    def post_with_failover(self, endpoint: str, payload: dict | None = None) -> dict:
        """
        登录类接口：主域名失败则按 BACKUP_DOMAINS 重试。
        复刻 ecloudHttpUtil.js post() 的 catch 分支 (line 167-168)。
        """
        try:
            return self.post(endpoint, payload, config.BASE_URL)
        except (requests.RequestException, EcloudError) as e:
            # 仅登录类接口走备用域名
            if endpoint not in config.LOGIN_PATHS:
                raise
            last_err = e
            for backup in config.BACKUP_DOMAINS:
                try:
                    return self.post(endpoint, payload, backup)
                except (requests.RequestException, EcloudError) as e2:
                    last_err = e2
                    continue
            raise last_err

    def _handle_response(self, resp: requests.Response, endpoint: str) -> dict:
        """复刻 handleHttpOrOpError + handleServerError (line 225-236)。"""
        if resp.status_code != 200 or not resp.text:
            raise EcloudError({
                "errorCode": str(resp.status_code),
                "errorMessage": f"HTTP {resp.status_code}: {resp.text[:200]}",
            })
        try:
            envelope = resp.json()
        except ValueError:
            raise EcloudError({
                "errorCode": "PARSE_ERROR",
                "errorMessage": f"非 JSON 响应: {resp.text[:200]}",
            })
        if "params" not in envelope:
            raise EcloudError(envelope)

        plain = rsa_decrypt(envelope["params"])
        try:
            obj = json.loads(plain)
        except ValueError:
            raise EcloudError({"errorMessage": f"解密后非 JSON: {plain[:200]}"})

        # state 校验 (ecloudHttpUtil.js:233)
        if obj.get("state") and obj["state"] != "OK":
            raise EcloudError(obj)
        if obj.get("errorMessage"):
            raise EcloudError(obj)

        body = obj.get("body", obj)
        # 登录换 token 接口：自动保存 accessToken (ecloudHttpUtil.js:163)
        if endpoint == config.Endpoint.LOGIN_GET_TOKEN:
            token = body.get("accessToken") if isinstance(body, dict) else None
            if token:
                self.set_token(token)
        return body
