"""
桌面会话保活（L2 资源登记层）—— 基于抓包逆向的 HTTP 保活。

分层说明（详见 docs/protocol-layers.md）：
  L1 账号 HTTP / L2 desktopUptime·machineConnect / L3 SPICE(VDI 心跳)
  本模块只做 **L2**：
    1. POST /resource/desktopUptime  {accessToken, instanceId}
       -> 返回 "X小时X分X秒"
    2. POST /session/machineConnect  {ticket, accessToken, machineId, ...}
       -> 返回 {connectId}

【已纠偏 2026-07】旧注释「不需要 SPICE / 无 VDI 可维持桌面在线」仅对 L2 登记成立。
用户实测：仅 L2 时桌面仍会不可用/被回收 → **真保活需要 L3 SPICE**（厂商 VDI）。
本模块可与 L3 并存，不能替代 L3。

凭证链：
  accessToken  ← 登录获得（token:<id>:<hex>accountPwd）
  instanceId   ← 桌面列表 API 返回（CCA-<32hex>）
  ticket       ← 会话票据（ticket:<id>:<hex>accountPwd）
  machineId    ← 桌面列表 API 返回（UUID）

本模块支持：
  (a) 从 cloud_pc.json 读取已保存的桌面凭证（用户从抓包/客户端提取）
  (b) 登录后自动尝试拉取桌面列表获取 instanceId/machineId
"""
import logging
import time
import uuid

import config
from ecloud_client import EcloudHttpUtil, EcloudError

log = logging.getLogger("desktop")


class DesktopSession:
    """一个云电脑桌面的会话保活器。"""

    def __init__(self, http: EcloudHttpUtil, instance_id: str,
                 machine_id: str = "", machine_name: str = "",
                 ticket: str = ""):
        self.http = http
        self.instance_id = instance_id
        self.machine_id = machine_id
        self.machine_name = machine_name
        self.ticket = ticket
        self.last_uptime = ""
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_token_expired = False
        # 会话标识（UUID，连接时生成，保活期间保持不变）
        self.connect_id = str(uuid.uuid4())
        self.login_uid = str(uuid.uuid4())

    def report_uptime(self) -> str:
        """
        查询/刷新桌面运行时长（保活核心）。
        已通过真实抓包验证：返回 "X小时X分X秒"。

        POST /resource/desktopUptime {accessToken, instanceId}
        """
        resp = self.http.post(config.Endpoint.DESKTOP_UPTIME, {
            "instanceId": self.instance_id,
        })
        if resp is None:
            raise EcloudError({
                "errorCode": "NO_UPTIME",
                "errorMessage": "desktopUptime 未返回运行时长，桌面可能已关机",
            })
        if isinstance(resp, dict):
            uptime = (
                resp.get("uptime")
                or resp.get("upTime")
                or resp.get("runningTime")
                or resp.get("duration")
            )
            if not uptime:
                raise EcloudError({
                    "errorCode": "NO_UPTIME",
                    "errorMessage": f"desktopUptime 未返回运行时长: {resp}",
                })
        else:
            uptime = str(resp)
        if not uptime or uptime == "None":
            raise EcloudError({
                "errorCode": "NO_UPTIME",
                "errorMessage": "desktopUptime 未返回运行时长，桌面可能已关机",
            })
        self.last_uptime = uptime
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_token_expired = False
        log.info("桌面 %s 运行时长: %s", self.instance_id[:16], uptime)
        return uptime

    def register_session(self) -> str:
        """
        登记桌面会话（让服务端知道这个会话存在）。
        抓包显示连接成功时调用一次。

        POST /session/machineConnect
        {ticket, accessToken, machineId, machineName, status:success, flag:true,
         clientConnectId, clientLoginUid}

        返回 {connectId}。
        """
        if not self.ticket:
            log.warning("无 ticket，跳过 session 登记")
            return ""
        resp = self.http.post(config.Endpoint.SESSION_MACHINE_CONNECT, {
            "ticket": self.ticket,
            "machineId": self.machine_id,
            "machineName": self.machine_name,
            "status": "success",
            "flag": True,
            "clientConnectId": self.connect_id,
            "clientLoginUid": self.login_uid,
        })
        if isinstance(resp, dict) and "connectId" in resp:
            self.connect_id = resp["connectId"]
            log.info("会话已登记: connectId=%s", self.connect_id)
        return self.connect_id

    def keepalive_once(self) -> bool:
        """
        执行一次桌面保活。
        策略：report_uptime 为主（已验证有效），register_session 为辅。
        """
        try:
            self.report_uptime()
            return True
        except EcloudError as e:
            self.last_error = f"[{e.code}] {e.message}"
            self.last_error_code = e.code
            self.last_error_token_expired = _is_token_expired(e)
            log.warning("desktopUptime 失败: %s", e)
            if self.last_error_token_expired:
                return False
            # uptime 失败可能是桌面关机或 instanceId 无效
            return False


def _is_token_expired(err: EcloudError) -> bool:
    msg = (err.message or "").lower()
    hints = ["token", "登录失效", "未登录", "请重新登录", "access", "授权", "过期"]
    return any(h.lower() in msg for h in hints)


def run_desktop_keepalive(http: EcloudHttpUtil, instance_id: str,
                          machine_id: str = "", ticket: str = "",
                          interval: int = 300, max_rounds: int | None = None,
                          relogin_fn=None) -> None:
    """
    桌面会话保活主循环。

    :param http: 已登录的 EcloudHttpUtil
    :param instance_id: 云电脑实例 ID（CCA-开头）
    :param machine_id: 桌面机 ID（UUID，可选，session 登记用）
    :param ticket: 会话票据（可选，session 登记用）
    :param interval: 保活间隔秒数（默认 5 分钟）
    :param max_rounds: 最大轮数（None=无限）
    :param relogin_fn: token 失效时的重新登录回调
    """
    session = DesktopSession(http, instance_id, machine_id, ticket=ticket)

    # 首次：尝试登记会话（可选）
    if ticket:
        try:
            session.register_session()
        except EcloudError as e:
            log.warning("初次 session 登记失败（忽略）: %s", e)

    log.info("启动桌面保活: instance=%s, 间隔=%ds", instance_id[:20], interval)
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        rounds += 1
        try:
            alive = session.keepalive_once()
            if alive:
                log.info("[%d] 桌面保活成功", rounds)
            else:
                detail = session.last_error or "桌面保活失败"
                log.warning("[%d] 桌面保活失败: %s", rounds, detail)
                if relogin_fn and session.last_error_token_expired:
                    token = relogin_fn()
                    if token:
                        http.set_token(token)
                        log.info("[%d] 已重新登录，继续保活", rounds)
                    else:
                        log.error("[%d] 重新登录失败，退出", rounds)
                        break
        except Exception as e:
            log.exception("[%d] 保活异常: %s", rounds, e)
        if max_rounds is None or rounds < max_rounds:
            time.sleep(interval)
