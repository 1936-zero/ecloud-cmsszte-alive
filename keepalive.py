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

import config
from ecloud_client import EcloudHttpUtil, EcloudError

log = logging.getLogger("keepalive")


def keepalive_once(http: EcloudHttpUtil) -> bool:
    """
    执行一次保活。成功返回 True，token 失效返回 False（需重新登录）。
    """
    success = False
    # 1. 用户信息
    try:
        info = http.post(config.Endpoint.USER_GET_INFO)
        log.debug("USER_GET_INFO ok: %s", _brief(info))
        success = True
    except EcloudError as e:
        log.warning("USER_GET_INFO failed: %s", e)
        if _is_token_expired(e):
            return False

    # 2. 桌面列表
    try:
        devs = http.post(config.Endpoint.USER_GET_DEVICE_INFO)
        log.debug("USER_GET_DEVICE_INFO ok: %s", _brief(devs))
        success = True
    except EcloudError as e:
        log.warning("USER_GET_DEVICE_INFO failed: %s", e)
        if _is_token_expired(e):
            return False

    # 3. 探针上报（模拟一条登录探针事件）
    try:
        _push_probe(http)
        success = True
    except EcloudError as e:
        log.warning("PROBE_QKK_BATCHPUSH failed: %s", e)
        # 探针失败不影响保活判定
    return success


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
    token_expired_hints = [
        "token", "登录失效", "未登录", "请重新登录",
        "access", "授权", "超时", "过期",
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
            alive = keepalive_once(http)
            if alive:
                log.info("[%d] 保活成功 ✓", rounds)
            else:
                log.warning("[%d] token 可能失效，尝试重新登录...", rounds)
                token = relogin_fn()
                if token:
                    http.set_token(token)
                    log.info("[%d] 重新登录成功，token 已刷新", rounds)
                else:
                    log.error("[%d] 重新登录失败", rounds)
        except Exception as e:
            log.exception("[%d] 保活异常: %s", rounds, e)
        if max_rounds is None or rounds < max_rounds:
            time.sleep(interval)
