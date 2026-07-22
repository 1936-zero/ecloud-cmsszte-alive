"""
保活后台线程管理器。

用 threading.Event 实现可控启停，用 collections.deque 缓存最近日志供前端轮询。

桌面保活默认走 **公众 ecloud Path B**（SPICE HEART + status/uptime oracle），
与 CLI `main.py desktop-keepalive` 同源；不再依赖已失效的纯 HTTP desktopUptime。
账号登录态保活（AccountKeepaliveManager）仍走 L1 account HTTP。
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import json

import keepalive as account_keepalive
from ecloud_client import EcloudError, EcloudHttpUtil

log = logging.getLogger(__name__)

# Path B defaults (aligned with l3/product_setup.py / path_b package)
# NOTE: container often has HOME=/ (uid 1000, no passwd home) → never default to ~/.cache only.
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve_default_plain() -> str:
    """Prefer env → existing files → first writable candidate (Docker-safe)."""
    for env_key in ("SHORT_CONNECT_PLAIN_FILE", "PLAIN", "ECLOUD_PLAIN"):
        v = (os.environ.get(env_key) or "").strip()
        if v:
            return v
    candidates = [
        Path("/tmp/r26_t29_plain"),
        Path("/tmp/ecloud-pathb/connectstr.plain"),
        _REPO_ROOT / "data" / "connectstr.plain",
        Path.home() / ".cache/ecloud-pathb/connectstr.plain",
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return str(c)
        except OSError:
            pass
    for c in candidates:
        try:
            c.parent.mkdir(parents=True, exist_ok=True)
            if os.access(str(c.parent), os.W_OK):
                return str(c)
        except OSError:
            continue
    return "/tmp/ecloud-pathb/connectstr.plain"


_DEFAULT_PLAIN = _resolve_default_plain()
_DEFAULT_PRE = str(_REPO_ROOT / "assets/templates/pre")
_DEFAULT_POST = str(_REPO_ROOT / "assets/templates/post")
_DEFAULT_HEART_LISTEN_S = float(os.environ.get("SPICE_HEART_LISTEN_S", "30") or 30)
_DEFAULT_CAG_HOST = "36.212.224.105"
_CONFIG_FILE = Path(
    os.environ.get(
        "CLOUD_PC_CONFIG_FILE",
        str(_REPO_ROOT / "cloud_pc.json"),
    )
)


def _resolve_out_dir() -> Path:
    """Docker-safe soak/report dir (repo reports/ often not writable as uid 1000)."""
    for env_key in ("OUT_DIR", "SPICE_ORACLE_OUT_DIR", "PATH_B_OUT_DIR"):
        v = (os.environ.get(env_key) or "").strip()
        if not v:
            continue
        p = Path(v)
        try:
            p.mkdir(parents=True, exist_ok=True)
            if os.access(str(p), os.W_OK):
                return p
        except OSError:
            continue
    candidates = [
        _REPO_ROOT / "reports" / "r26_live" / "spice_oracle_webui",
        Path("/tmp/ecloud-pathb/reports/spice_oracle_webui"),
        Path("/tmp/spice_oracle_webui"),
    ]
    for c in candidates:
        try:
            c.mkdir(parents=True, exist_ok=True)
            if os.access(str(c), os.W_OK):
                return c
        except OSError:
            continue
    return Path("/tmp/spice_oracle_webui")


def _load_cfg() -> dict:
    try:
        if _CONFIG_FILE.is_file():
            with open(_CONFIG_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        log.warning("load cloud_pc.json failed: %s", e)
    return {}


def _save_cfg(cfg: dict) -> None:
    """Atomic-ish write; never logs secrets."""
    try:
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CONFIG_FILE.with_suffix(_CONFIG_FILE.suffix + f".{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _CONFIG_FILE)
    except Exception as e:
        log.warning("save cloud_pc.json failed: %s", e)
        try:
            if tmp.is_file():  # type: ignore[name-defined]
                tmp.unlink()
        except Exception:
            pass


def _make_log_entry(previous_seq: int, level: str, msg: str) -> tuple[int, dict]:
    now = datetime.now()
    seq = max(previous_seq + 1, int(time.time() * 1000))
    return seq, {
        "seq": seq,
        "time": now.strftime("%H:%M:%S"),
        "created_at": now.isoformat(timespec="milliseconds"),
        "level": level,
        "msg": msg,
    }


def _safe_public_err(msg: str) -> str:
    """Strip potential secrets from error strings before UI log.

    #75fixv: do NOT whole-string redact when only the *word* connectStr/no_connectStr
    appears (CAG 501 status). Keep result_code / http status so UI is actionable.
    """
    if not msg:
        return ""
    import re

    s = str(msg)
    # redact key=value secret forms (keep key name)
    s = re.sub(
        r"(?i)\b(connectstr|password|access_token|refresh_token|plain)\s*[=:]\s*[^\s,;|]+",
        r"\1=(redacted)",
        s,
    )
    # long base64/hex blobs (≥48 continuous)
    s = re.sub(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{48,}(?![A-Za-z0-9+/=_-])", "(blob)", s)
    # known public mint failure — map to friendly Chinese (no secrets)
    low = s.lower()
    if "no_connectstr" in low or ("result=501" in low and "connect" in low):
        return (
            "mint失败: CAG result=501 no_connectStr "
            "(桌面可能关机/未就绪或 vmid 无效，请先开机后重试)"
        )
    if "result=501" in low:
        return "mint失败: CAG result=501 (桌面会话不可用，请先开机后重试)"
    if len(s) > 400:
        return s[:200] + "…(truncated)"
    return s


class AccountKeepaliveManager:
    """管理账号登录态保活线程，对应 `python main.py keepalive`。"""

    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._interval = 300
        self._rounds = 0
        self._last_error = ""
        self._started_at: datetime | None = None
        self._last_success_at: datetime | None = None
        self._consecutive_errors = 0
        self._log_seq = 0
        self._logs: deque[dict] = deque(maxlen=200)

    def is_running(self) -> bool:
        return self._running

    @property
    def running(self) -> bool:
        """Alias for is_running(); account_runtime autostart reads `.running`."""
        return self._running

    def get_status(self) -> dict:
        with self._lock:
            if not self._running:
                health = "stopped"
            elif self._last_error:
                health = "error"
            elif self._last_success_at:
                health = "ok"
            else:
                health = "starting"
            return {
                "running": self._running,
                "health": health,
                "interval": self._interval,
                "rounds": self._rounds,
                "last_error": self._last_error,
                "consecutive_errors": self._consecutive_errors,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "last_success_at": (
                    self._last_success_at.isoformat() if self._last_success_at else None
                ),
            }

    def get_logs(self, since: int = 0) -> list[dict]:
        with self._lock:
            return [log for log in self._logs if log["seq"] > since]

    def _log(self, level: str, msg: str):
        with self._lock:
            self._log_seq, entry = _make_log_entry(self._log_seq, level, msg)
            self._logs.append(entry)

    def _record_success(self):
        with self._lock:
            self._last_error = ""
            self._last_success_at = datetime.now()
            self._consecutive_errors = 0

    def _record_error(self, msg: str):
        with self._lock:
            self._last_error = msg
            self._consecutive_errors += 1

    def start(self, http: EcloudHttpUtil, interval: int = 300, relogin_fn=None) -> bool:
        """启动账号登录态保活线程。已在运行则返回 False。"""
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._interval = interval
            self._rounds = 0
            self._last_error = ""
            self._last_success_at = None
            self._consecutive_errors = 0
            self._started_at = datetime.now()
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run,
            args=(http, interval, relogin_fn),
            daemon=True,
            name="account-keepalive",
        )
        self._thread.start()
        self._log("INFO", f"账号保活已启动: interval={interval}s")
        return True

    def stop(self) -> bool:
        # #75fixag: non-blocking stop — UI must not wait join
        with self._lock:
            if not self._running and not (self._thread and self._thread.is_alive()):
                return False
            was = self._running
            self._running = False
        self._stop_event.set()
        self._log("INFO", "正在停止账号保活...")
        th = self._thread

        def _join_bg(t: threading.Thread | None) -> None:
            if t and t.is_alive():
                t.join(timeout=3.0)
            self._log("INFO", "账号保活已停止" if not (t and t.is_alive()) else "账号保活已标记停止（线程收尾中）")

        threading.Thread(
            target=_join_bg, args=(th,), daemon=True, name="account-keepalive-stop"
        ).start()
        return True

    def _run(self, http: EcloudHttpUtil, interval: int, relogin_fn):
        while not self._stop_event.is_set():
            with self._lock:
                self._rounds += 1
                current_round = self._rounds
            try:
                account_keepalive.keepalive_once(http)
                self._record_success()
                self._log("INFO", f"[{current_round}] 账号保活成功")
            except EcloudError as e:
                detail = _safe_public_err(f"[{e.code}] {e.message}")
                self._record_error(detail)
                self._log("WARN", f"[{current_round}] 账号保活失败: {detail}")
                if relogin_fn and _token_maybe_expired(e):
                    try:
                        token = relogin_fn()
                        if token:
                            http.set_token(token)
                            self._log("INFO", "重新登录成功，立即重试账号保活")
                            try:
                                account_keepalive.keepalive_once(http)
                                self._record_success()
                                self._log("INFO", f"[{current_round}] 重登后账号保活成功")
                            except Exception as retry_ex:
                                msg = _safe_public_err(str(retry_ex))
                                self._record_error(msg)
                                self._log("WARN", f"[{current_round}] 重登后仍失败: {msg}")
                        else:
                            self._log("ERROR", "重新登录失败")
                    except Exception as ex:
                        self._log("ERROR", f"重新登录异常: {_safe_public_err(str(ex))}")
            except Exception as e:
                msg = _safe_public_err(str(e))
                self._record_error(msg)
                self._log("ERROR", f"[{current_round}] 账号保活异常: {msg}")

            for _ in range(max(1, int(interval))):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        with self._lock:
            self._running = False


class KeepaliveManager:
    """管理一个桌面会话 Path B (SPICE) 保活后台线程。

    可多实例：每个 Web 账号注入独立 config_path / plain_path，
    避免多账号共用全局 cloud_pc.json / connectstr.plain。
    无注入时行为与历史单档案模式一致（读全局 env / CLOUD_PC_CONFIG_FILE）。
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        plain_path: str | Path | None = None,
        label: str = "",
        out_dir: str | Path | None = None,
    ):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        # 状态
        self._running = False
        self._instance_id = ""
        self._interval = 300
        self._rounds = 0
        self._last_uptime = ""
        self._last_error = ""
        self._started_at: datetime | None = None
        self._last_success_at: datetime | None = None
        self._consecutive_errors = 0
        self._log_seq = 0
        self._logs: deque[dict] = deque(maxlen=200)
        self._mode = "path_b"  # public surface: SPICE Path B
        self._last_heart_ok: Optional[bool] = None
        self._heart_listen = _DEFAULT_HEART_LISTEN_S
        self._label = (label or "").strip()
        self._config_path: Path | None = (
            Path(config_path).expanduser() if config_path else None
        )
        self._plain_path_override: Path | None = (
            Path(plain_path).expanduser() if plain_path else None
        )
        self._out_dir_override: Path | None = (
            Path(out_dir).expanduser() if out_dir else None
        )

    def _load_cfg_local(self) -> dict:
        """Load cfg from injected path, else global _load_cfg()."""
        if self._config_path is not None:
            try:
                if self._config_path.is_file():
                    with open(self._config_path, encoding="utf-8") as f:
                        data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except Exception as e:
                log.warning("load cfg %s failed: %s", self._config_path, e)
            return {}
        return _load_cfg()

    def _save_cfg_local(self, cfg: dict) -> None:
        """Save cfg to injected path, else global _save_cfg()."""
        if self._config_path is not None:
            try:
                self._config_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._config_path.with_suffix(
                    self._config_path.suffix + f".{os.getpid()}.tmp"
                )
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self._config_path)
            except Exception as e:
                log.warning("save cfg %s failed: %s", self._config_path, e)
                try:
                    if tmp.is_file():  # type: ignore[name-defined]
                        tmp.unlink()
                except Exception:
                    pass
            return
        _save_cfg(cfg)

    def is_running(self) -> bool:
        return self._running

    @property
    def running(self) -> bool:
        """Alias for is_running(); keep attribute-style checks consistent."""
        return self._running

    def get_status(self) -> dict:
        with self._lock:
            if not self._running:
                health = "stopped"
            elif self._last_error:
                health = "error"
            elif self._last_success_at or self._last_uptime:
                health = "ok"
            else:
                health = "starting"
            return {
                "running": self._running,
                "health": health,
                "mode": self._mode,
                "instance_id": self._instance_id,
                "interval": self._interval,
                "rounds": self._rounds,
                "last_uptime": self._last_uptime,
                "last_error": self._last_error,
                "last_heart_ok": self._last_heart_ok,
                "consecutive_errors": self._consecutive_errors,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "last_success_at": (
                    self._last_success_at.isoformat() if self._last_success_at else None
                ),
                "production_claim": False,
                "dual_evidence_ok": False,
            }

    def get_logs(self, since: int = 0) -> list[dict]:
        """返回序号 > since 的日志。"""
        with self._lock:
            return [entry for entry in self._logs if entry["seq"] > since]

    def _log(self, level: str, msg: str):
        with self._lock:
            self._log_seq, entry = _make_log_entry(self._log_seq, level, msg)
            self._logs.append(entry)

    def _record_success(self, uptime: str, heart_ok: Optional[bool] = None):
        with self._lock:
            self._last_uptime = uptime or self._last_uptime
            self._last_error = ""
            self._last_success_at = datetime.now()
            self._consecutive_errors = 0
            if heart_ok is not None:
                self._last_heart_ok = heart_ok

    def _record_error(self, msg: str, heart_ok: Optional[bool] = None):
        with self._lock:
            self._last_error = msg
            self._consecutive_errors += 1
            if heart_ok is not None:
                self._last_heart_ok = heart_ok

    def start(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str = "",
        ticket: str = "",
        interval: int = 300,
        relogin_fn=None,
    ) -> bool:
        """启动 Path B 桌面保活线程。已在运行则返回 False。

        ticket 参数保留兼容 WebUI/API 旧签名，Path B 不使用 ticket 明文。
        """
        # #75fixag: previous soft-stop may still have a dying worker
        old = self._thread
        if old is not None and old.is_alive():
            self._stop_event.set()
            old.join(timeout=5.0)
            if old.is_alive():
                self._log("WARN", "上一轮 Path B 线程尚未退出，拒绝重复启动")
                return False

        with self._lock:
            if self._running:
                return False
            self._running = True
            self._instance_id = instance_id
            self._interval = interval
            self._rounds = 0
            self._last_uptime = ""
            self._last_error = ""
            self._last_success_at = None
            self._consecutive_errors = 0
            self._last_heart_ok = None
            self._started_at = datetime.now()
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run,
            args=(http, instance_id, machine_id, ticket, interval, relogin_fn),
            daemon=True,
            name="keepalive-pathb",
        )
        self._thread.start()
        self._log(
            "INFO",
            f"Path B 保活已启动: instance={str(instance_id)[:20]}, interval={interval}s",
        )
        return True

    def stop(self) -> bool:
        """停止保活线程。未运行则返回 False。

        #75fixag: 不在请求线程里 join 长达 heart_listen+30s，否则 Flask 单 worker
        会卡死 stop API / 前端像「点了没反应」。先置 stop + 立即 running=False，
        后台短 join；若轮询中线程仍在收尾，start() 会再拦一层。
        """
        with self._lock:
            if not self._running and not (self._thread and self._thread.is_alive()):
                return False
            was = self._running
            self._running = False
        self._stop_event.set()
        self._log("INFO", "正在停止 Path B 保活...")
        th = self._thread

        def _join_bg(t: threading.Thread | None) -> None:
            if not t or not t.is_alive():
                self._log("INFO", "Path B 保活已停止")
                return
            # 给当前 sleep(1) 循环一点时间退出；heart 中可能仍卡一会
            t.join(timeout=3.0)
            if t.is_alive():
                self._log(
                    "WARN",
                    "Path B 线程仍在收尾（可能在 heart_listen），已标记停止，稍后自然退出",
                )
            else:
                self._log("INFO", "Path B 保活已停止")

        threading.Thread(
            target=_join_bg, args=(th,), daemon=True, name="keepalive-pathb-stop"
        ).start()
        return True

    # ------------------------------------------------------------------ path B helpers

    def _plain_path(self) -> Path:
        # Priority: instance override → env → cloud_pc.json plain_path → Docker-safe default
        if self._plain_path_override is not None:
            return self._plain_path_override
        for env_key in ("SHORT_CONNECT_PLAIN_FILE", "PLAIN", "ECLOUD_PLAIN"):
            v = (os.environ.get(env_key) or "").strip()
            if v:
                return Path(v).expanduser()
        cfg = self._load_cfg_local()
        cfg_plain = str(cfg.get("plain_path") or "").strip()
        if cfg_plain:
            return Path(cfg_plain).expanduser()
        return Path(_resolve_default_plain())

    def _template_dirs(self) -> tuple[Path, Path]:
        pre = Path(os.environ.get("SPICE_PRE_DIR", _DEFAULT_PRE))
        post = Path(os.environ.get("SPICE_POST_DIR", _DEFAULT_POST))
        if not pre.is_dir():
            nest = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/pre"
            if nest.is_dir():
                pre = nest
        if not post.is_dir():
            nest = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/post"
            if nest.is_dir():
                post = nest
        return pre, post

    def _resolve_cag_host(self, cfg: dict) -> str:
        host = (
            os.environ.get("CAG_HOST")
            or os.environ.get("ECLOUD_CAG_HOST")
            or str(cfg.get("cag_host") or "")
            or _DEFAULT_CAG_HOST
        )
        return str(host).strip() or _DEFAULT_CAG_HOST

    def _gateway_source_weak(self, cfg: dict) -> bool:
        """#75fixy: plain may exist while cag_host is still GZ4 default."""
        src = str(cfg.get("gateway_source") or "").strip().lower()
        host = str(cfg.get("cag_host") or "").strip()
        if not host:
            return True
        if not src or src in {"default", "account_weak", "fallback", "env"}:
            return True
        if "device" in src or "customlogin" in src.replace("_", "").lower():
            return False
        return src not in {"cli", "manual", "user"}

    def _refresh_gateway_from_desktop(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str,
        cfg: dict,
    ) -> dict:
        """Re-list desktop and force-write customLoginParams → region CAG (#75fixy)."""
        try:
            from desktop_list import get_desktop_list
            from l3.gateway_config import (
                gateway_from_custom_login_params,
                merge_gateway_into_cloud_pc,
            )
        except Exception as e:
            self._log("INFO", f"gateway refresh import skip: {_safe_public_err(str(e))}")
            return cfg
        try:
            desktops = get_desktop_list(http)
        except Exception as e:
            self._log("INFO", f"gateway refresh list skip: {_safe_public_err(str(e))}")
            return cfg
        matched = None
        for d in desktops or []:
            if instance_id and d.instance_id == instance_id:
                matched = d
                break
            if machine_id and d.machine_id == machine_id:
                matched = d
                break
        if matched is None:
            self._log("INFO", "gateway refresh: desktop not found in list")
            return cfg
        clp = getattr(matched, "custom_login_params", None)
        if not clp:
            self._log("INFO", "gateway refresh: no customLoginParams on desktop")
            return cfg
        try:
            gw = gateway_from_custom_login_params(clp)
        except Exception as e:
            self._log("INFO", f"gateway refresh parse skip: {_safe_public_err(str(e))}")
            return cfg
        if gw is None:
            return cfg
        before = (cfg.get("cag_host"), cfg.get("cag_port"), cfg.get("gateway_source"))
        cfg = merge_gateway_into_cloud_pc(cfg, gw, only_missing=False)
        try:
            self._save_cfg_local(cfg)
        except Exception:
            pass
        after = (cfg.get("cag_host"), cfg.get("cag_port"), cfg.get("gateway_source"))
        if before != after:
            self._log(
                "INFO",
                f"gateway_device={cfg.get('cag_host')}:{cfg.get('cag_port')} "
                f"src={cfg.get('gateway_source')}",
            )
        return cfg

    @staticmethod
    def _plain_stale_after_power(plain: Path, cfg: dict) -> bool:
        """#75fixae: plain mtime older than power_on_at → must remint after boot.

        Preflight may power the desktop then start Path B with an existing plain.
        ensure_powered_once then returns already_running / power_on_done and the
        old path skipped mint — connectStr from the previous power cycle is dead.
        """
        try:
            if not plain.is_file() or plain.stat().st_size <= 0:
                return True
        except OSError:
            return True
        poa = str((cfg or {}).get("power_on_at") or "").strip()
        if not poa:
            # no marker → not "stale after power"; first-mint path handles missing plain
            return False
        try:
            # power_on_at written as "%Y-%m-%dT%H:%M:%S" (local, no tz)
            poa_ts = time.mktime(time.strptime(poa[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            return False
        try:
            plain_mtime = float(plain.stat().st_mtime)
        except OSError:
            return True
        # 2s skew tolerance (fs vs wall clock)
        return plain_mtime < (poa_ts - 2.0)

    def _ensure_plain(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str,
        plain: Path,
    ) -> bool:
        """Ensure plain exists; #75fixy also refresh weak gateway even if plain present."""
        cfg = self._load_cfg_local()
        plain_ok = False
        try:
            plain_ok = plain.is_file() and plain.stat().st_size > 0
        except OSError:
            plain_ok = False

        # Always correct weak/default CAG before Path B (plain alone is not enough).
        if self._gateway_source_weak(cfg):
            self._log("INFO", "gateway 源偏弱/默认，从桌面 customLoginParams 刷新区域 CAG…")
            cfg = self._refresh_gateway_from_desktop(
                http,
                instance_id or str(cfg.get("instance_id") or ""),
                machine_id or str(cfg.get("machine_id") or ""),
                cfg,
            )
            # reload after save
            cfg = self._load_cfg_local() or cfg

        # #75fixac: plain 存在时也要检查是否关机；关机则 operate=available + remint
        # #75fixae: preflight/本处已开机但 plain 早于 power_on_at → 强制 remint
        #           （旧 connectStr 在电源周期后失效；already_running 不得跳过 mint）
        need_remint_after_power = False
        power_wait = float(os.environ.get("CLOUD_PC_POWER_WAIT", "60") or 60)
        if plain_ok:
            try:
                from l3.desktop_power_once import ensure_powered_once

                pr = ensure_powered_once(
                    http,
                    cfg,
                    machine_id=machine_id or str(cfg.get("machine_id") or ""),
                    machine_name=str(cfg.get("machine_name") or ""),
                    instance_id=instance_id or str(cfg.get("instance_id") or ""),
                    save_cfg_fn=self._save_cfg_local,
                    wait_s=power_wait,
                    force=False,
                )
                cfg = self._load_cfg_local() or cfg
                if pr.acted:
                    need_remint_after_power = True
                    self._log(
                        "INFO",
                        "检测到桌面已关机，已调用开机(operate=available)，将重签发凭证…",
                    )
                elif self._plain_stale_after_power(plain, cfg):
                    # already_running / power_on_done，但凭证早于最近开机
                    need_remint_after_power = True
                    self._log(
                        "INFO",
                        "会话凭证早于最近开机(power_on_at)，等待 CAG 就绪后重签发… "
                        f"power_skip={pr.skipped_reason or '-'} wait={power_wait:.0f}s",
                    )
                    # ensure_powered_once 未 wait（未 operate）；冷启动 CAG 需缓冲
                    try:
                        time.sleep(max(0.0, float(power_wait)))
                    except Exception:
                        pass
                else:
                    host = self._resolve_cag_host(cfg)
                    self._log(
                        "INFO",
                        f"会话凭证已存在，跳过 mint；Path B host={host} "
                        f"src={cfg.get('gateway_source') or ''} "
                        f"power_skip={pr.skipped_reason or '-'}",
                    )
                    return True
            except Exception as e:
                # power check failed: keep old plain path (do not block keepalive start)
                host = self._resolve_cag_host(cfg)
                self._log(
                    "INFO",
                    f"会话凭证已存在，跳过 mint；Path B host={host} "
                    f"src={cfg.get('gateway_source') or ''} "
                    f"(power_check_err={_safe_public_err(str(e))})",
                )
                return True

        if not plain_ok:
            self._log("INFO", "未找到会话凭证文件，正在准备（开机 + 签发）…")
        elif need_remint_after_power:
            self._log("INFO", "电源周期后凭证失效，正在重签发会话凭证…")
        try:
            plain.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self._log(
                "ERROR",
                f"凭证目录不可写 ({plain.parent}): {_safe_public_err(str(e))}；"
                "请设置 SHORT_CONNECT_PLAIN_FILE=/tmp/... 或 cloud_pc.json plain_path",
            )
            return False
        try:
            from l3.product_setup import run_product_setup
        except Exception as e:
            self._log("ERROR", f"加载 product_setup 失败: {_safe_public_err(str(e))}")
            return False

        try:
            # #75fixr: WebUI 默认 25s 对慢链路 mint 不够；CLI 侧常能过。
            # 与 product_setup 调用对齐拉长读超时，避免 Read timed out. (read timeout=25.0)
            # #75fixw: mint 501/no_connectStr → force power + wait + remint
            # （默认 mint_power_retry=True / power_wait=DEFAULT_POWER_WAIT_S，与 CLI 共用）
            # #75fixac: remint after power-on when plain already existed
            # #75fixae: power_wait 默认 60；do_power=False 时 mint501 仍可 wait+remint
            result = run_product_setup(
                cfg=cfg,
                client=http,
                save_config=self._save_cfg_local,
                plain_path=plain,
                do_power=not need_remint_after_power,  # already powered above
                force_power=False,
                do_mint=True,
                do_path_b=False,
                instance_id=instance_id or str(cfg.get("instance_id") or ""),
                machine_id=machine_id or str(cfg.get("machine_id") or ""),
                mint_timeout=float(os.environ.get("CLOUD_PC_MINT_TIMEOUT", "90") or 90),
                power_wait_s=float(os.environ.get("CLOUD_PC_POWER_WAIT", "60") or 60),
                mint_power_retry=True,
            )
        except Exception as e:
            self._log("ERROR", f"准备失败: {_safe_public_err(str(e))}")
            return False

        ok = bool(getattr(result, "ok", False))
        stage = getattr(result, "stage", "")
        err = _safe_public_err(str(getattr(result, "error", "") or ""))
        if ok and plain.is_file() and plain.stat().st_size > 0:
            self._log("INFO", f"会话凭证已签发 (stage={stage})")
            return True
        # partial: mint may have written plain even if later stage failed
        try:
            if plain.is_file() and plain.stat().st_size > 0:
                self._log("INFO", f"会话凭证已存在 (stage={stage})")
                return True
        except OSError:
            pass
        self._log("ERROR", f"准备未完成 stage={stage} err={err or 'unknown'}")
        return False

    def _run_one_path_b_round(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str,
        interval: int,
        relogin_fn,
        plain: Path,
        pre: Path,
        post: Path,
        host: str,
    ) -> dict[str, Any]:
        from l3.spice_oracle_keepalive_loop import run_spice_oracle_keepalive_loop

        if self._out_dir_override is not None:
            try:
                self._out_dir_override.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            out_dir = self._out_dir_override
        else:
            out_dir = _resolve_out_dir()
        return run_spice_oracle_keepalive_loop(
            http=http,
            instance_id=instance_id,
            machine_id=machine_id,
            host=host,
            plain=plain,
            pre=pre,
            post=post,
            heart_listen=self._heart_listen,
            interval=int(interval),
            max_rounds=1,
            relogin_fn=relogin_fn,
            do_account_ping=True,
            stop_on_fatal=False,
            auto_remint=True,
            mid_session_reconnect=True,
            out_dir=out_dir,
            # #75fixah: abort heart_listen early when WebUI stop requested
            should_stop=self._stop_event.is_set,
        )

    def _run(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str,
        ticket: str,
        interval: int,
        relogin_fn,
    ):
        """Path B 保活主循环：每轮 oracle max_rounds=1，然后 sleep interval。"""
        _ = ticket  # API 兼容；Path B 不消费 ticket
        plain = self._plain_path()
        pre, post = self._template_dirs()

        cfg = self._load_cfg_local()

        # prefer cfg machine_id if caller omitted
        mid = machine_id or str(cfg.get("machine_id") or "")
        iid = instance_id or str(cfg.get("instance_id") or "")
        host = self._resolve_cag_host(cfg)

        if not self._ensure_plain(http, iid, mid, plain):
            self._record_error("会话凭证准备失败（请先 setup / 检查桌面是否可开机）")
            with self._lock:
                self._running = False
            return

        self._log(
            "INFO",
            f"Path B 就绪: host={host}, plain={plain.name}, "
            f"pre={pre.name if pre else '?'}, heart_listen={self._heart_listen}s",
        )

        while not self._stop_event.is_set():
            with self._lock:
                self._rounds += 1
                current_round = self._rounds

            try:
                # refresh host/mid from latest cfg each round (gateway may update)
                cfg = self._load_cfg_local() or (cfg if isinstance(cfg, dict) else {})
                if isinstance(cfg, dict):
                    mid = mid or str(cfg.get("machine_id") or "")
                    iid = iid or str(cfg.get("instance_id") or "")
                    host = self._resolve_cag_host(cfg)

                if not plain.is_file() or plain.stat().st_size <= 0:
                    if not self._ensure_plain(http, iid, mid, plain):
                        self._record_error("会话凭证缺失且重签失败")
                        self._log("ERROR", f"[{current_round}] 会话凭证缺失且重签失败")
                        # still wait interval before next try
                        for _ in range(max(1, int(interval))):
                            if self._stop_event.is_set():
                                break
                            time.sleep(1)
                        continue

                finished = self._run_one_path_b_round(
                    http=http,
                    instance_id=iid,
                    machine_id=mid,
                    interval=interval,
                    relogin_fn=relogin_fn,
                    plain=plain,
                    pre=pre,
                    post=post,
                    host=host,
                )
                ok_heart = int(finished.get("ok_heart_rounds") or 0)
                ok_redq = int(finished.get("ok_redq_rounds") or 0)
                fail_rounds = int(finished.get("fail_rounds") or 0)
                uptime = str(finished.get("last_uptime") or "")
                last_status = str(finished.get("last_resource_status") or "")
                heart_ok = ok_heart > 0

                if heart_ok:
                    self._record_success(uptime or last_status or "heart_ok", heart_ok=True)
                    self._log(
                        "INFO",
                        f"[{current_round}] Path B 成功 heart=True "
                        f"uptime={uptime or '-'} status={last_status or '-'}",
                    )
                elif ok_redq > 0:
                    # partial channel; not full heart
                    self._record_error(
                        f"仅 redq 无 heart (status={last_status or '-'})",
                        heart_ok=False,
                    )
                    self._log(
                        "WARN",
                        f"[{current_round}] Path B 部分成功 redq=True heart=False "
                        f"status={last_status or '-'}",
                    )
                else:
                    err = _safe_public_err(
                        str(finished.get("last_error") or finished.get("error") or "")
                    )
                    self._record_error(
                        err or f"Path B 失败 fail={fail_rounds}",
                        heart_ok=False,
                    )
                    self._log(
                        "WARN",
                        f"[{current_round}] Path B 失败 fail={fail_rounds} "
                        f"err={err or 'unknown'}",
                    )
            except Exception as e:
                msg = _safe_public_err(str(e))
                self._record_error(msg, heart_ok=False)
                self._log("ERROR", f"[{current_round}] Path B 异常: {msg}")

            for _ in range(max(1, int(interval))):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        with self._lock:
            self._running = False


def _token_maybe_expired(err: EcloudError) -> bool:
    msg = (err.message or "").lower()
    return any(h in msg for h in ["token", "失效", "未登录", "expire", "401", "授权"])
