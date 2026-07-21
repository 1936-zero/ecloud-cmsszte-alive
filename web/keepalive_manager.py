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
    """Strip potential secrets from error strings before UI log."""
    if not msg:
        return ""
    low = msg.lower()
    for ban in ("connectstr", "password", "access_token", "refresh_token", "plain="):
        if ban in low:
            return "error(redacted)"
    # never echo long base64-looking blobs
    if len(msg) > 400:
        return msg[:200] + "…(truncated)"
    return msg


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
        if not self._running:
            return False
        self._stop_event.set()
        self._log("INFO", "正在停止账号保活...")
        if self._thread:
            self._thread.join(timeout=10)
        with self._lock:
            self._running = False
        self._log("INFO", "账号保活已停止")
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
        """停止保活线程。未运行则返回 False。"""
        if not self._running:
            return False
        self._stop_event.set()
        self._log("INFO", "正在停止 Path B 保活...")
        # allow in-flight heart listen + remint slack
        join_timeout = max(60.0, float(self._heart_listen) + 30.0)
        if self._thread:
            self._thread.join(timeout=join_timeout)
        with self._lock:
            self._running = False
        self._log("INFO", "Path B 保活已停止")
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

    def _ensure_plain(
        self,
        http: EcloudHttpUtil,
        instance_id: str,
        machine_id: str,
        plain: Path,
    ) -> bool:
        """If connectStr plain missing/empty, run product_setup mint (power once + mint)."""
        try:
            if plain.is_file() and plain.stat().st_size > 0:
                return True
        except OSError:
            pass

        self._log("INFO", "未找到会话凭证文件，正在准备（仅首次开机 + 签发）…")
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

        cfg = self._load_cfg_local()

        try:
            result = run_product_setup(
                cfg=cfg,
                client=http,
                save_config=self._save_cfg_local,
                plain_path=plain,
                do_power=True,
                force_power=False,
                do_mint=True,
                do_path_b=False,
                instance_id=instance_id or str(cfg.get("instance_id") or ""),
                machine_id=machine_id or str(cfg.get("machine_id") or ""),
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
