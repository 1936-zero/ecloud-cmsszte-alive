"""
保活循环 —— 维持账号在线态。

⚠️ 重要说明（来自对源码的完整分析）：
移动云电脑 Electron 主进程没有任何"会话心跳"接口。真正的桌面会话保活
（SPICE 协议层）封装在 uSmartView_VDI_Client.exe 二进制内，Python 层无法触及。
本模块实现的是【账号登录态保活】：周期性调用业务接口让服务端认为账号活跃，
延缓 accessToken 过期。它不能阻止"已连接桌面"因 SPICE 会话闲置而被释放。

保活策略（按强度从高到低，每个周期依次尝试）：
  1. 拉取用户信息 (USER_GET_INFO)        —— 证明 token 有效
  2. 拉取桌面列表 (USER_GET_DEVICE_INFO) —— 触发服务端会话刷新
  3. 上报探针数据 (PROBE_QKK_BATCHPUSH)   —— 模拟客户端正常上报

若任何接口返回 token 失效错误，自动重新登录。
"""
import logging
import time
from dataclasses import dataclass
from typing import Optional

import config
from ecloud_client import EcloudHttpUtil, EcloudError

log = logging.getLogger("keepalive")


@dataclass
class KeepaliveOutcome:
    """一轮保活的结果 + 真实服务端错误（供 CLI/WebUI 打可诊断日志）。

    ok:  True  = 至少一个接口成功（健康）
         False = 检测到 token 失效，需要重新登录
         None  = 本轮全部失败但均为非 token 错误（服务端瞬时/5xx），不应重登
    error: 触发 False/None 的真实服务端报错 "[code] message"（成功为空）；
           来自服务端返回，不含 token/密码，可安全展示到日志/界面。
    """

    ok: Optional[bool]
    error: str = ""


def keepalive_probe(http: EcloudHttpUtil) -> KeepaliveOutcome:
    """执行一次保活并返回结果 + 真实错误（供 CLI/WebUI 打可诊断日志）。

    ⚠️ 关键：单个接口返回 401/token失效【不能】直接判定 token 死了。真网实测
    /user/getLoginUserInfo 会对同一个仍然有效的 token 间歇性返回「[401] token失效」
    （端点级风控/单会话态），而同一 token 的 /user/getDeviceInfo、SPICE 会话在
    同一秒内仍然成功。若据单点 401 就密码重登，会每 10~20 分钟打一次 /login/verify，
    触发服务端风控 → 手机短信轰炸。
    因此：只要【任一】接口成功 → 会话有效 → ok=True，绝不重登；只有【全部】接口
    失败且其中至少一个是 token 失效错误时，才判 ok=False 触发重登。
    """
    success = False
    token_err = ""   # token 失效样错误：仅当【全部接口失败】时才据此重登
    last_err = ""    # 最近一个非 token 错误（用于 None 分支的诊断日志）
    # 1. 用户信息
    try:
        info = http.post(config.Endpoint.USER_GET_INFO)
        log.debug("USER_GET_INFO ok: %s", _brief(info))
        success = True
    except EcloudError as e:
        detail = f"[{e.code}] {e.message}"
        log.warning("USER_GET_INFO failed: %s", detail)
        if _is_token_expired(e):
            token_err = token_err or detail
        else:
            last_err = detail

    # 2. 桌面列表
    try:
        devs = http.post(config.Endpoint.USER_GET_DEVICE_INFO)
        log.debug("USER_GET_DEVICE_INFO ok: %s", _brief(devs))
        success = True
    except EcloudError as e:
        detail = f"[{e.code}] {e.message}"
        log.warning("USER_GET_DEVICE_INFO failed: %s", detail)
        if _is_token_expired(e):
            token_err = token_err or detail
        else:
            last_err = detail

    # 3. 探针上报（模拟一条登录探针事件；失败不影响保活判定）
    try:
        _push_probe(http)
        success = True
    except EcloudError as e:
        detail = f"[{e.code}] {e.message}"
        log.warning("PROBE_QKK_BATCHPUSH failed: %s", detail)
        if _is_token_expired(e):
            token_err = token_err or detail
        elif not last_err:
            last_err = detail

    if success:
        # 任一接口成功 → 会话仍有效。若同时看到过某接口的 token 失效样报错，
        # 那是端点级风控/单点抖动，记为 debug 但【绝不】重登（否则密码重登风暴）。
        if token_err:
            log.debug(
                "token-like error on one endpoint but session is alive "
                "(another probe succeeded) → NOT relogin: %s", token_err,
            )
        return KeepaliveOutcome(ok=True)
    if token_err:
        # 全部接口失败，且至少一个是 token 失效 → 真失效，需重登刷新 token。
        return KeepaliveOutcome(ok=False, error=token_err)
    # 全部失败但均为非 token 错误（瞬时/服务端故障）→ None，避免误触发密码重登。
    return KeepaliveOutcome(ok=None, error=last_err)


def keepalive_once(http: EcloudHttpUtil):
    """三态兼容包装（True/False/None）。新代码请用 keepalive_probe 拿真实错误。"""
    return keepalive_probe(http).ok


def _push_probe(http: EcloudHttpUtil) -> None:
    """
    上报一条探针事件 (reportDataUtil.js:283-291 PROBE_QKK_BATCHPUSH)。
    模拟客户端正常的心跳式上报，让服务端看到账号活跃。
    """
    event = {
        "eventSeq": str(int(time.time() * 1000)),
        "eventCode": str(config.LoginType.PASSWORD),  # 探针事件类型
        "eventName": "keepalive",
        "eventType": "1",
        "eventValue": "1",
        "eventStatus": "0",
        "apiTime": str(int(time.time())),
        "appVersion": config.CLIENT_VERSION,
    }
    http.post(config.Endpoint.PROBE_QKK_BATCHPUSH, {"list": [event]})


def _is_token_expired(err: EcloudError) -> bool:
    """判断错误是否表示 token 失效需要重新登录。"""
    # Keep hints token-specific. "access" / "超时" over-matched transient errors
    # (accessKey mentions, gateway timeouts) → wrongly forced password relogin.
    token_expired_hints = [
        "token", "登录失效", "未登录", "请重新登录",
        "授权", "过期",
    ]
    msg = (err.message or "").lower()
    return any(h.lower() in msg for h in token_expired_hints)


def _brief(obj, limit=120) -> str:
    s = str(obj)
    return s if len(s) <= limit else s[:limit] + "..."


def run_keepalive_loop(http: EcloudHttpUtil,
                       relogin_fn,
                       interval: int = 300,
                       max_rounds: int | None = None) -> None:
    """
    保活主循环。
    :param http: EcloudHttpUtil 实例
    :param relogin_fn: 无参回调，token 失效时调用以重新登录并刷新 http 的 token
    :param interval: 保活间隔（秒），默认 5 分钟
    :param max_rounds: 最多执行多少轮（None=无限）
    """
    log.info("启动保活循环，间隔 %ds", interval)
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        rounds += 1
        try:
            outcome = keepalive_probe(http)
            if outcome.ok is True:
                log.info("[%d] 保活成功 ✓", rounds)
            elif outcome.ok is False:
                # 打出服务端真实报错，便于判断是真失效还是被误判
                log.warning(
                    "[%d] token 失效（服务端返回: %s），重新登录...",
                    rounds, outcome.error or "无详情",
                )
                token = relogin_fn()
                if token:
                    http.set_token(token)
                    log.info("[%d] 重新登录成功，token 已刷新", rounds)
                else:
                    log.error("[%d] 重新登录失败", rounds)
            else:
                # None: 本轮全部为非 token 错误（服务端瞬时/5xx）——不重登，下轮重试
                log.warning(
                    "[%d] 本轮请求失败（非 token 错误: %s），跳过重登，下轮重试",
                    rounds, outcome.error or "无详情",
                )
        except Exception as e:
            log.exception("[%d] 保活异常: %s", rounds, e)
        if max_rounds is None or rounds < max_rounds:
            time.sleep(interval)
