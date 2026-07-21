"""
设备指纹采集 —— 复刻 deviceUtil.js 的 getCommonParams() (line 48-71)。

实测结论（通过逐字段删除测试验证）：
  服务端对已认证请求（带 accessToken）的 commonParams 字段【不做校验】。
  连空 commonParams 都能成功调用 desktopUptime。
  这些字段纯粹是客户端上报的统计信息。

因此本模块的策略：
  - deviceUid：唯一需要稳定的字段（服务端用它识别设备，变化会触发"未授信设备"），
    优先从配置读取，否则从 /etc/machine-id 派生。
  - 其余字段：给合理默认值即可，无需真实采集（服务端不校验）。
"""
import os
import platform
import socket
import uuid as uuidlib
from dataclasses import dataclass, field

import config


def _read_machine_id() -> str:
    """读 /etc/machine-id（systemd），返回 32 位 hex；失败回退。"""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as f:
                mid = f.read().strip()
            if mid:
                return mid
        except OSError:
            continue
    return ""


def _get_client_type() -> str:
    """复刻 deviceUtil.js:188-211 的 Linux 分支（Windows 回退为 windows 类型）。"""
    os_name = platform.system()
    if os_name == "Windows":
        return "pc_windows_64_yt"
    if os_name == "Darwin":
        return "pc_mac"
    arch = platform.machine()
    if arch in ("aarch64", "arm64"):
        return "linux_arm64"
    return "linux_x86-64"


@dataclass
class DeviceInfo:
    """设备指纹。只有 deviceUid 是关键，其余字段服务端不校验。"""
    device_uid: str
    device_name: str = ""
    client_type: str = ""
    client_version: str = config.CLIENT_VERSION
    device_company: str = ""
    device_model: str = ""
    operating_system: str = ""
    device_system: str = ""
    operating_version: str = ""
    cores: int = 4
    processor: str = ""
    system_architecture: str = ""
    disk_total: float = 500.0
    disk_used: float = 250.0
    ram: int = 8
    ip_address: str = "127.0.0.1"
    mac_address: str = "00:00:00:00:00:00"

    def to_common_params(self) -> dict:
        """生成 ecloudHttpUtil.js 合并到每个请求 body 的公共参数。"""
        return {
            "companyCode": config.COMPANY_CODE,
            "clientType": self.client_type or _get_client_type(),
            "clientVersion": self.client_version,
            "deviceUid": self.device_uid,
            "deviceName": self.device_name or socket.gethostname() or "keepalive",
            "deviceType": "pc",
            "operatingSystem": self.operating_system or platform.system() or "Linux",
            "cores": self.cores,
            "ram": self.ram,
            "systemArchitecture": self.system_architecture or platform.machine() or "x86_64",
            # 以下字段服务端不校验，给默认值即可
            "deviceCompany": self.device_company or "Unknown",
            "deviceModel": self.device_model or "Server",
            "deviceSystem": self.device_system or "Unknown",
            "operatingVersion": self.operating_version or "unknown",
            "processor": self.processor or "Unknown",
            "diskTotal": self.disk_total,
            "diskUsed": self.disk_used,
            "ipAddress": self.ip_address,
            "macAddress": self.mac_address,
        }


def detect(device_uid: str | None = None,
           client_version: str = config.CLIENT_VERSION) -> DeviceInfo:
    """
    构造设备指纹。
    :param device_uid: 必须跨运行稳定（从配置读取）。不传则从 machine-id 派生。
    """
    if not device_uid:
        mid = _read_machine_id()
        if mid:
            device_uid = f"{mid[:8]}-{mid[8:12]}-{mid[12:16]}-{mid[16:20]}-{mid[20:32]}"
        else:
            device_uid = str(uuidlib.uuid4())

    return DeviceInfo(
        device_uid=device_uid,
        client_version=client_version,
        client_type=_get_client_type(),
    )
