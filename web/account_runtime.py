"""
Multi-account WebUI runtime for public ecloud Path B.

Each account has isolated:
  - cloud_pc.json
  - connectstr.plain
  - logs.jsonl
  - KeepaliveManager instance
  - EcloudHttpUtil session

Registry index: data/web_accounts/index.json
Global log:     data/web_accounts/global_logs.jsonl

No concurrency orchestration. claim/dual never touched.
Secrets stay path-only / redacted in public log views.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import device
import desktop_list
import desktop_session
import login
from ecloud_client import EcloudError, EcloudHttpUtil
from l3.gateway_config import (
    gateway_from_custom_login_params,
    merge_gateway_into_cloud_pc,
)
from web.keepalive_manager import AccountKeepaliveManager, KeepaliveManager

log = logging.getLogger("web.account_runtime")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROOT = Path(
    os.environ.get(
        "ECLOUD_WEB_ACCOUNTS_DIR",
        str(_PROJECT_ROOT / "data" / "web_accounts"),
    )
)

_SENSITIVE_KEYS = {
    "password",
    "accessToken",
    "access_token",
    "accessTicket",
    "access_ticket",
    "verificationCode",
    "token",
    "ticket",
    "plain",
    "connect_str",
    "connectStr",
}


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_log_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: ("[redacted]" if k in _SENSITIVE_KEYS else _safe_log_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_safe_log_obj(v) for v in obj]
    return obj


def _token_maybe_expired(err: EcloudError) -> bool:
    msg = (err.message or "").lower()
    return any(h in msg for h in ["token", "失效", "未登录", "expire", "401", "授权"])


def _preflight_uptime(http: EcloudHttpUtil, instance_id: str) -> str:
    if not instance_id:
        raise EcloudError({
            "errorCode": "NO_INSTANCE",
            "errorMessage": "缺少桌面实例 ID",
        })
    return desktop_session.DesktopSession(http, instance_id).report_uptime()


def _slug(s: str, fallback: str = "acct") -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = s.strip("-._")[:48]
    return s or fallback


class AccountRuntime:
    """One public-ecloud account card + Path B keepalive worker."""

    def __init__(self, registry: "AccountRegistry", meta: dict):
        self.registry = registry
        self.id = str(meta["id"])
        self.label = str(meta.get("label") or self.id)
        self.dir = registry.root / self.id
        self.dir.mkdir(parents=True, exist_ok=True)

        self.config_path = self.dir / "cloud_pc.json"
        self.plain_path = self.dir / "connectstr.plain"
        self.logs_path = self.dir / "logs.jsonl"
        self.out_dir = self.dir / "oracle_out"
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._http: EcloudHttpUtil | None = None
        self._cfg: dict = self._load_cfg()
        # login intermediate state (sms flow)
        self._username = str(self._cfg.get("username") or meta.get("username") or "")
        self._password = str(self._cfg.get("password") or "")
        self._mobile = ""
        self._login_type = ""
        self._login_code = None
        self._log_seq = 0
        self._logs: deque[dict] = deque(maxlen=500)
        self._load_logs_tail()

        self.km = KeepaliveManager(
            config_path=self.config_path,
            plain_path=self.plain_path,
            out_dir=self.out_dir,
            label=self.label or self.id,
        )
        # L1 账号登录态保活（对应 CLI `python main.py keepalive`），与 Path B 桌面保活独立
        self.aka = AccountKeepaliveManager()
        # bridge KM / AKA logs into account + global backend logs
        self._install_km_log_bridge()
        self._install_aka_log_bridge()

        # ensure per-account device fingerprint (must NOT share host machine-id
        # across multi-account cards — SMS trust is bound to device_uid)
        if not self._cfg.get("device_uid"):
            try:
                # unique uid first, then detect() fills other device fields if needed
                uid = str(uuid.uuid4())
                dev = device.detect(device_uid=uid)
                self._cfg["device_uid"] = dev.device_uid or uid
                self._save_cfg()
            except Exception as e:
                self._cfg["device_uid"] = str(uuid.uuid4())
                try:
                    self._save_cfg()
                except Exception:
                    pass
                log.warning("device detect failed for %s: %s", self.id, e)

    # ------------------------------------------------------------------ paths
    def _load_cfg(self) -> dict:
        try:
            if self.config_path.is_file():
                with open(self.config_path, encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception as e:
            log.warning("load %s failed: %s", self.config_path, e)
        return {}

    def _save_cfg(self) -> None:
        tmp = self.config_path.with_suffix(
            f".{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._cfg, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.config_path)
        except Exception as e:
            log.warning("save %s failed: %s", self.config_path, e)
            try:
                if tmp.is_file():
                    tmp.unlink()
            except Exception:
                pass

    def _gateway_needs_refresh(self) -> bool:
        """#75fixy: weak/missing gateway must re-read customLoginParams."""
        src = str(self._cfg.get("gateway_source") or "").strip().lower()
        host = str(self._cfg.get("cag_host") or "").strip()
        if not host:
            return True
        # default / account_weak / empty source = not device-region CAG
        if not src or src in {"default", "account_weak", "fallback", "env"}:
            return True
        if "device" in src or "customlogin" in src.replace("_", "").lower():
            return False
        # any non-device source is treated as weak for region CAG
        return src not in {"cli", "manual", "user"}

    def _apply_desktop_gateway_locked(self, desktop) -> bool:
        """Write region CAG from desktop.custom_login_params into self._cfg (lock held).

        Returns True if cfg was updated. Caller saves.
        """
        clp = getattr(desktop, "custom_login_params", None)
        if not clp:
            return False
        try:
            gw = gateway_from_custom_login_params(clp)
        except Exception as e:
            self.log("INFO", f"parse customLoginParams skip: {type(e).__name__}")
            return False
        if gw is None:
            return False
        before = (
            str(self._cfg.get("cag_host") or ""),
            str(self._cfg.get("cag_port") or ""),
            str(self._cfg.get("csapip") or ""),
            str(self._cfg.get("gateway_source") or ""),
        )
        # force overwrite weak/default; device clp is authoritative for this desktop
        self._cfg = merge_gateway_into_cloud_pc(self._cfg, gw, only_missing=False)
        after = (
            str(self._cfg.get("cag_host") or ""),
            str(self._cfg.get("cag_port") or ""),
            str(self._cfg.get("csapip") or ""),
            str(self._cfg.get("gateway_source") or ""),
        )
        if before != after:
            self.log(
                "INFO",
                f"gateway_device={after[0]}:{after[1]} src={after[3]}",
            )
            return True
        return False

    def _load_logs_tail(self, max_lines: int = 200) -> None:
        if not self.logs_path.is_file():
            return
        try:
            lines = self.logs_path.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-max_lines:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                seq = int(entry.get("seq") or 0)
                if seq > self._log_seq:
                    self._log_seq = seq
                self._logs.append(entry)
        except Exception as e:
            log.warning("load logs %s failed: %s", self.logs_path, e)

    def _append_log_file(self, entry: dict) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.logs_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            log.warning("append log %s failed: %s", self.logs_path, e)

    def log(self, level: str, msg: str, *, to_global: bool = True) -> dict:
        with self._lock:
            self._log_seq += 1
            entry = {
                "seq": self._log_seq,
                "ts": _now_iso(),
                "level": level,
                "msg": msg,
                "account_id": self.id,
                "label": self.label,
            }
            self._logs.append(entry)
            self._append_log_file(entry)
        if to_global:
            self.registry.append_global_log(entry)
        return entry

    def get_logs(self, since: int = 0) -> list[dict]:
        with self._lock:
            return [e for e in self._logs if int(e.get("seq") or 0) > since]

    def clear_logs(self) -> dict:
        """HARD_GATE#853-style: clear ring buffer + truncate logs.jsonl (backend real clear)."""
        with self._lock:
            self._logs.clear()
            self._log_seq = 0
            try:
                self.logs_path.write_text("", encoding="utf-8")
            except Exception as e:
                log.warning("clear logs file %s failed: %s", self.logs_path, e)
                return {"ok": False, "error": str(e)}
        self.log("info", "日志已清空", to_global=False)
        return {"ok": True, "cleared": True}


    @staticmethod
    def _is_keepalive_round_tick(msg: str) -> bool:
        """Per-round success ticks belong on the card only.

        Align 爱家 bottom「运行日志」: lifecycle / status / failures only,
        NOT every Path B heart or 账号保活 success round.
        """
        s = str(msg or "")
        # [n] Path B 成功 heart=... / status=...
        if re.search(r"\[\d+\]\s*Path B 成功", s):
            return True
        # [n] 账号保活成功 / 重登后账号保活成功
        if re.search(r"\[\d+\]\s*(?:重登后)?账号保活成功", s):
            return True
        return False

    def _install_km_log_bridge(self) -> None:
        """Mirror KeepaliveManager into account logs; global = lifecycle/errors only."""
        orig = self.km._log

        def _bridged(level: str, msg: str, _orig=orig):
            _orig(level, msg)
            # 卡片 ring 始终全量；底部运行日志对齐爱家，不刷每轮 heart
            lvl = str(level or "").upper()
            tick = self._is_keepalive_round_tick(msg)
            to_g = (not tick) or lvl in ("WARN", "WARNING", "ERROR")
            self.log(level, msg, to_global=to_g)

        self.km._log = _bridged  # type: ignore[method-assign]

    def _install_aka_log_bridge(self) -> None:
        """Mirror AccountKeepaliveManager; global = lifecycle/errors only."""
        orig = self.aka._log

        def _bridged(level: str, msg: str, _orig=orig):
            _orig(level, msg)
            full = f"[账号保活] {msg}"
            lvl = str(level or "").upper()
            tick = self._is_keepalive_round_tick(msg)
            to_g = (not tick) or lvl in ("WARN", "WARNING", "ERROR")
            self.log(level, full, to_global=to_g)

        self.aka._log = _bridged  # type: ignore[method-assign]

    # ------------------------------------------------------------------ http
    def get_http(self) -> EcloudHttpUtil:
        """Per-account HTTP client; same construction as web/server._get_or_create_http."""
        with self._lock:
            if self._http is None:
                uid = (self._cfg.get("device_uid") or "").strip() or str(uuid.uuid4())
                dev = device.detect(device_uid=uid)
                self._cfg["device_uid"] = dev.device_uid or uid
                try:
                    self._save_cfg()
                except Exception:
                    pass
                self._http = EcloudHttpUtil(dev.to_common_params())
            token = str(self._cfg.get("access_token") or "").strip()
            if token:
                try:
                    self._http.set_token(token)
                except Exception:
                    try:
                        self._http.access_token = token  # type: ignore[attr-defined]
                    except Exception:
                        pass
            return self._http

    def set_token(self, token: str) -> None:
        with self._lock:
            self._cfg["access_token"] = token
            self._save_cfg()
            http = self.get_http()
            try:
                http.set_token(token)
            except Exception:
                try:
                    http.access_token = token  # type: ignore[attr-defined]
                except Exception:
                    pass

    def clear_http(self) -> None:
        with self._lock:
            self._http = None

    # ------------------------------------------------------------------ public views
    def public_meta(self) -> dict:
        cfg = self._cfg
        ka = self.km.get_status()
        aka = self.aka.get_status()
        logged_in = bool(cfg.get("access_token"))
        try:
            interval_default = int(cfg.get("keepalive_interval") or 300)
        except (TypeError, ValueError):
            interval_default = 300
        try:
            account_interval = int(cfg.get("account_keepalive_interval") or 300)
        except (TypeError, ValueError):
            account_interval = 300
        return {
            "id": self.id,
            "label": self.label,
            "username": self._username or cfg.get("username") or "",
            "logged_in": logged_in,
            "has_password": bool(cfg.get("password")),
            "instance_id": cfg.get("instance_id") or "",
            "machine_id": cfg.get("machine_id") or "",
            "machine_name": cfg.get("machine_name") or "",
            "device_uid": (cfg.get("device_uid") or "")[:12],
            "plain_ready": self.plain_path.is_file() and self.plain_path.stat().st_size > 0,
            "keepalive_interval": interval_default,
            "account_keepalive_interval": account_interval,
            "keepalive": ka,
            "account_keepalive": aka,
            "last_error": ka.get("last_error") or aka.get("last_error") or "",
            "updated_at": cfg.get("updated_at") or "",
        }

    def update_label(self, label: str) -> None:
        label = (label or "").strip() or self.id
        self.label = label
        # also update KM label if present
        try:
            self.km._label = label  # type: ignore[attr-defined]
        except Exception:
            pass

    def update_settings(
        self,
        *,
        label: str | None = None,
        password: str | None = None,
        keepalive_interval: int | None = None,
        account_keepalive_interval: int | None = None,
        instance_id: str | None = None,
        machine_id: str | None = None,
        machine_name: str | None = None,
    ) -> dict:
        """Update display name / password / intervals / bound desktop (no secrets in return)."""
        with self._lock:
            if label is not None:
                new_label = (label or "").strip() or self.id
                self.label = new_label
                try:
                    self.km._label = new_label  # type: ignore[attr-defined]
                except Exception:
                    pass
            if password is not None and str(password) != "":
                self._cfg["password"] = str(password)
            if keepalive_interval is not None:
                try:
                    iv = int(keepalive_interval)
                except (TypeError, ValueError):
                    return {"ok": False, "error": "Path B 间隔必须是数字"}
                if iv < 30 or iv > 3600:
                    return {"ok": False, "error": "Path B 间隔需在 30–3600 秒"}
                self._cfg["keepalive_interval"] = iv
            if account_keepalive_interval is not None:
                try:
                    aiv = int(account_keepalive_interval)
                except (TypeError, ValueError):
                    return {"ok": False, "error": "账号保活间隔必须是数字"}
                if aiv < 30 or aiv > 3600:
                    return {"ok": False, "error": "账号保活间隔需在 30–3600 秒"}
                self._cfg["account_keepalive_interval"] = aiv
            if instance_id is not None:
                self._cfg["instance_id"] = str(instance_id or "").strip()
            if machine_id is not None:
                self._cfg["machine_id"] = str(machine_id or "").strip()
            if machine_name is not None:
                self._cfg["machine_name"] = str(machine_name or "").strip()
            self._cfg["updated_at"] = _now_iso()
            self._save_cfg()
        self.log("INFO", "已更新账号配置（label/密码/间隔/桌面）")
        return {"ok": True, "account": self.public_meta()}

    # ------------------------------------------------------------------ login
    def login(self, username: str, password: str, *, quiet: bool = False) -> dict:
        """密码登录。

        quiet=True：成功路径的「登录中/结果/成功」只写卡内 ring，不上 global
        （Path B / 账号保活 relogin 每轮静默刷新 token 时使用，避免淹没保活行）。
        失败/需短信仍始终上 global，便于用户感知。
        """
        username = (username or "").strip()
        password = password or ""
        if not username or not password:
            return {"status": "failed", "error": "账号和密码不能为空"}

        http = self.get_http()
        try:
            http.clear_token()
        except Exception:
            pass

        with self._lock:
            self._username = username
            self._password = password
            self._cfg["username"] = username
            self._cfg["password"] = password
            self._cfg["updated_at"] = _now_iso()
            self._save_cfg()

        # quiet 成功：卡内 only；失败/非 success：仍 to_global 便于排查
        self.log("INFO", f"登录中: user={username}", to_global=not quiet)
        result = login.login_with_password(http, username, password)
        _ok = result.get("status") == login.LoginResult.SUCCESS
        self.log(
            "INFO",
            f"登录结果: {json.dumps(_safe_log_obj({'status': result.get('status'), 'error': result.get('error'), 'error_code': result.get('error_code')}), ensure_ascii=False)}",
            to_global=(not quiet) or (not _ok),
        )

        if result["status"] == login.LoginResult.SUCCESS:
            token = result["access_token"]
            self.set_token(token)
            self.log("INFO", "登录成功", to_global=not quiet)
            aka = self._autostart_account_keepalive_after_login()
            out = {"status": "success", "token": token[:20] + "..."}
            if aka is not None:
                out["account_keepalive"] = aka
            return out

        if result["status"] == login.LoginResult.NEED_DEVICE_TRUST:
            with self._lock:
                self._mobile = result.get("mobile", "") or ""
                self._login_type = "device_trust"
                self._login_code = result.get("login_code")
            return {
                "status": "need_sms",
                "mobile": self._mobile,
                "login_type": "device_trust",
                "message": "该设备未授信，需要短信验证",
            }

        if result["status"] == login.LoginResult.NEED_TWO_FACTOR:
            with self._lock:
                self._mobile = result.get("mobile", "") or ""
                self._login_type = "two_factor"
                self._login_code = result.get("login_code")
            return {
                "status": "need_sms",
                "mobile": self._mobile,
                "login_type": "two_factor",
                "message": "需要二次短信验证",
            }

        if result["status"] == login.LoginResult.NEED_ENHANCED_SMS:
            with self._lock:
                self._mobile = result.get("mobile", "") or ""
                self._login_type = "enhanced_sms"
                self._login_code = result.get("login_code")
            return {
                "status": "need_sms",
                "mobile": self._mobile,
                "login_type": "enhanced_sms",
                "message": "需要增强策略短信验证",
            }

        if result["status"] == login.LoginResult.NEED_4A:
            return {"status": "failed", "error": "需要 4A MFA 验证，暂不支持"}

        return {"status": "failed", "error": result.get("error", "登录失败")}

    def send_sms(self, mobile: str = "") -> dict:
        with self._lock:
            mobile = (mobile or self._mobile or "").strip()
            login_type = self._login_type
            username = self._username
        if not mobile:
            return {"ok": False, "error": "缺少手机号"}
        http = self.get_http()
        try:
            if login_type == "two_factor":
                login.send_two_factor_sms(http, mobile, username)
            elif login_type == "device_trust":
                login.send_sms(http, mobile, code_type="trust")
            else:
                login.send_sms(http, mobile, code_type="login")
            with self._lock:
                self._mobile = mobile
            self.log("INFO", f"短信已发送 mobile={mobile[-4:].rjust(len(mobile), '*') if mobile else ''}")
            return {"ok": True, "mobile": mobile}
        except EcloudError as e:
            self.log("ERROR", f"发送短信失败: {e.message}")
            return {"ok": False, "error": e.message}
        except Exception as e:
            self.log("ERROR", f"发送短信异常: {e}")
            return {"ok": False, "error": str(e)}

    def verify_sms(self, mobile: str, code: str, login_type: str = "") -> dict:
        # Mirror web/server.py verify-sms: complete_* helpers, not bare verify_sms.
        mobile = (mobile or self._mobile or "").strip()
        code = login.normalize_sms_code(code)
        if not code:
            return {"status": "failed", "error": "验证码不能为空"}

        with self._lock:
            mobile = mobile or self._mobile or ""
            login_type = (login_type or self._login_type or "device_trust").strip()
            username = self._username
            password = self._password
            login_code = self._login_code

        if not mobile:
            return {"status": "failed", "error": "缺少手机号"}

        http = self.get_http()
        self.log(
            "INFO",
            f"verify sms start: login_type={login_type} mobile_present={bool(mobile)} "
            f"username_present={bool(username)} login_code_present={bool(login_code)}",
        )
        try:
            if login_type == "device_trust":
                r = login.complete_device_trust(
                    http, mobile, code, username, code=login_code,
                )
            elif login_type == "two_factor":
                r = login.complete_two_factor(
                    http, mobile, username, password, code, code=login_code,
                )
            elif login_type == "enhanced_sms":
                r = login.complete_enhanced_sms(
                    http, mobile, username, code, code=login_code,
                )
            else:
                return {"status": "failed", "error": f"未知登录类型: {login_type}"}
        except EcloudError as e:
            self.log("ERROR", f"短信验证失败: {e.message}")
            return {
                "status": "failed",
                "error": e.message,
                "error_code": getattr(e, "code", None),
            }

        if r.get("status") == login.LoginResult.SUCCESS:
            token = r["access_token"]
            self.set_token(token)
            with self._lock:
                self._login_code = None
                self._login_type = ""
                self._mobile = mobile
            self.log("INFO", "短信验证成功，已登录")
            aka = self._autostart_account_keepalive_after_login()
            out = {"status": "success", "token": token[:20] + "..."}
            if aka is not None:
                out["account_keepalive"] = aka
            return out

        if r.get("status") == login.LoginResult.NEED_4A:
            return {"status": "failed", "error": "需要 4A MFA 验证，暂不支持"}

        self.log("ERROR", f"短信验证失败: {r.get('error')}")
        return {
            "status": "failed",
            "error": r.get("error", "验证失败"),
            "error_code": r.get("error_code"),
            "raw": _safe_log_obj(r.get("raw")),
        }

    def relogin(self) -> bool:
        with self._lock:
            username = str(self._cfg.get("username") or self._username or "").strip()
            password = str(self._cfg.get("password") or self._password or "")
        if not username or not password:
            self.log("ERROR", "重登失败：缺少已保存账号密码")
            return False
        # Path B / AKA 轮次 relogin：成功明细不刷 global，避免淹没 heart/保活行
        r = self.login(username, password, quiet=True)
        return r.get("status") == "success"

    # ------------------------------------------------------------------ desktops
    def list_desktops(self) -> dict:
        if not self._cfg.get("access_token"):
            return {"error": "未登录", "desktops": []}
        http = self.get_http()
        try:
            desktops = desktop_list.get_desktop_list(http)
            result = []
            for d in desktops:
                result.append({
                    "instance_id": d.instance_id,
                    "machine_id": d.machine_id,
                    "machine_name": d.machine_name,
                    "vendor": getattr(d, "origin_company_code", "") or "",
                    "status": getattr(d, "status", "") or "",
                })
            try:
                statuses = desktop_list.get_desktop_status(http, desktops)
                for r in result:
                    r["status"] = statuses.get(r["instance_id"], r.get("status") or "?")
            except EcloudError:
                pass
            return {"desktops": result}
        except EcloudError as e:
            if _token_maybe_expired(e) and self.relogin():
                return self.list_desktops()
            return {"error": e.message, "desktops": []}

    # ------------------------------------------------------------------ keepalive
    def start_keepalive(
        self,
        instance_id: str = "",
        machine_id: str = "",
        interval: int = 300,
    ) -> dict:
        if not self._cfg.get("access_token"):
            return {"ok": False, "error": "未登录"}
        try:
            interval = int(interval)
        except (TypeError, ValueError):
            return {"ok": False, "error": "保活间隔必须是数字"}
        if interval < 30:
            interval = 30

        http = self.get_http()

        def _relogin():
            return self.relogin()

        def _call_with_relogin(fn):
            try:
                return fn()
            except EcloudError as e:
                if _token_maybe_expired(e) and _relogin():
                    return fn()
                raise

        # auto pick desktop
        if not instance_id:
            try:
                desktops = _call_with_relogin(lambda: desktop_list.get_desktop_list(http))
                if not desktops:
                    return {"ok": False, "error": "账号下没有可用桌面"}
                try:
                    statuses = _call_with_relogin(
                        lambda: desktop_list.get_desktop_status(http, desktops)
                    )
                except EcloudError:
                    statuses = {}

                selected = None
                preflight_errors = []
                for d in desktops:
                    st = statuses.get(d.instance_id, "")
                    try:
                        uptime = _call_with_relogin(
                            lambda d=d: _preflight_uptime(http, d.instance_id)
                        )
                    except EcloudError as e:
                        label = d.machine_name or d.instance_id[:20] or "未知桌面"
                        state = f", status={st}" if st else ""
                        preflight_errors.append(f"{label}{state}: {e.message}")
                    else:
                        self.log(
                            "INFO",
                            f"preflight ok instance={d.instance_id[:20]} status={st or '?'} uptime={uptime}",
                        )
                        selected = d
                        break
                if selected is None:
                    detail = preflight_errors[0] if preflight_errors else "desktopUptime 未返回运行时长"
                    return {"ok": False, "error": f"没有可保活桌面：{detail}"}
                instance_id = selected.instance_id
                machine_id = selected.machine_id
                with self._lock:
                    self._cfg["instance_id"] = instance_id
                    self._cfg["machine_id"] = machine_id
                    self._cfg["machine_name"] = getattr(selected, "machine_name", "") or ""
                    # #75fixy: region CAG from machineList[].customLoginParams
                    self._apply_desktop_gateway_locked(selected)
                    self._cfg["updated_at"] = _now_iso()
                    self._save_cfg()
            except EcloudError as e:
                return {"ok": False, "error": f"拉取桌面列表失败: {e.message}"}
        else:
            if not machine_id and self._cfg.get("instance_id") == instance_id:
                machine_id = str(self._cfg.get("machine_id") or "")
            matched_desktop = None
            if not machine_id or self._gateway_needs_refresh():
                try:
                    desktops = _call_with_relogin(lambda: desktop_list.get_desktop_list(http))
                    for d in desktops:
                        if d.instance_id == instance_id:
                            machine_id = machine_id or d.machine_id
                            matched_desktop = d
                            break
                except EcloudError as e:
                    self.log("INFO", f"machine_id/gateway lookup failed: {e.message}")
            try:
                uptime = _call_with_relogin(lambda: _preflight_uptime(http, instance_id))
                self.log("INFO", f"preflight ok instance={instance_id[:20]} uptime={uptime}")
            except EcloudError as e:
                return {"ok": False, "error": f"桌面不可保活: {e.message}"}
            with self._lock:
                self._cfg["instance_id"] = instance_id
                if machine_id:
                    self._cfg["machine_id"] = machine_id
                if matched_desktop is not None:
                    if getattr(matched_desktop, "machine_name", None):
                        self._cfg["machine_name"] = matched_desktop.machine_name or ""
                    self._apply_desktop_gateway_locked(matched_desktop)
                self._cfg["updated_at"] = _now_iso()
                self._save_cfg()

        ok = self.km.start(
            http,
            instance_id,
            machine_id=machine_id or "",
            ticket="",
            interval=interval,
            relogin_fn=_relogin,
        )
        if not ok:
            return {"ok": False, "error": "该账号保活已在运行"}
        self.log("INFO", f"已启动 Path B 保活 interval={interval}s instance={instance_id[:20]}")
        # Align CLI: starting desktop keepalive also starts account login-state keepalive
        aka_res = self.start_account_keepalive()
        if not aka_res.get("ok"):
            # already running is fine; other errors only warn
            err = str(aka_res.get("error") or "")
            if "已在运行" not in err and "already" not in err.lower():
                self.log("WARN", f"桌面保活已启，账号保活未自动启动: {err or aka_res}")
            else:
                self.log("INFO", "账号登录态保活已在运行")
        else:
            self.log("INFO", "已自动启动账号登录态保活（对齐 CLI）")
        return {"ok": True, "instance_id": instance_id, "interval": interval, "account_keepalive": aka_res}

    def stop_keepalive(self) -> dict:
        ok = self.km.stop()
        self.log("INFO", "已请求停止 Path B 保活" if ok else "保活未在运行")
        # Align CLI: stop desktop keepalive also stops account login-state keepalive
        aka_ok = self.stop_account_keepalive()
        self.log("INFO", f"已同步停止账号登录态保活 ok={aka_ok.get('ok') if isinstance(aka_ok, dict) else aka_ok}")
        return {"ok": ok, "account_keepalive_stopped": aka_ok}

    def _autostart_account_keepalive_after_login(self) -> dict | None:
        """Best-effort: start L1 account keepalive right after login/SMS success.

        Multi-account WebUI previously only exposed manual aka-start/stop; single-account
        path already had autostart. Mirror that behavior so cards become "logged-in + AKA".
        Never raise — login success must still return to the UI.
        """
        try:
            if self.aka.is_running() or getattr(self.aka, "running", False):
                return {"ok": True, "already": True}
            # Prefer persisted interval; fall back to default 300s.
            interval = None
            try:
                interval = int(self._cfg.get("account_keepalive_interval") or 300)
            except (TypeError, ValueError):
                interval = 300
            result = self.start_account_keepalive(interval=interval)
            if result.get("ok"):
                self.log("INFO", f"登录后已自动启动账号保活 interval={result.get('interval', interval)}s")
            else:
                self.log("WARN", f"登录后自动启动账号保活失败: {result.get('error') or result}")
            return result
        except Exception as e:
            self.log("WARN", f"登录后自动启动账号保活异常: {e}")
            return {"ok": False, "error": str(e)}

    def start_account_keepalive(self, interval: int | None = None) -> dict:
        """Start L1 account login-state keepalive (CLI `python main.py keepalive`)."""
        if not self._cfg.get("access_token"):
            return {"ok": False, "error": "未登录，无法启动账号保活"}
        try:
            if interval is None:
                interval = int(self._cfg.get("account_keepalive_interval") or 300)
            else:
                interval = int(interval)
        except (TypeError, ValueError):
            return {"ok": False, "error": "账号保活间隔必须是数字"}
        if interval < 30 or interval > 3600:
            return {"ok": False, "error": "账号保活间隔需在 30–3600 秒"}

        def _relogin():
            username = self._username or self._cfg.get("username") or ""
            password = self._cfg.get("password") or ""
            if not username or not password:
                self.log("WARN", "账号保活重登失败：缺用户名/密码")
                return None
            result = self.login(username=username, password=password)
            if result.get("status") == "success" or result.get("ok") is True:
                return self._cfg.get("access_token")
            self.log("WARN", f"账号保活重登未完成: {result.get('status') or result.get('error')}")
            return None

        http = self.get_http()
        ok = self.aka.start(http, interval=interval, relogin_fn=_relogin)
        if not ok:
            return {"ok": False, "error": "该账号登录态保活已在运行"}
        with self._lock:
            self._cfg["account_keepalive_interval"] = interval
            self._cfg["updated_at"] = _now_iso()
            self._save_cfg()
        self.log("INFO", f"已启动账号登录态保活 interval={interval}s")
        return {"ok": True, "interval": interval}

    def stop_account_keepalive(self) -> dict:
        ok = self.aka.stop()
        self.log("INFO", "已请求停止账号登录态保活" if ok else "账号保活未在运行")
        return {"ok": ok}

    def logout(self) -> dict:
        self.stop_keepalive()
        self.stop_account_keepalive()
        with self._lock:
            self._cfg.pop("access_token", None)
            self._save_cfg()
            self._http = None
            self._login_type = ""
            self._login_code = None
        self.log("INFO", "已登出（本地 token 已清除）")
        return {"ok": True}


class AccountRegistry:
    """In-process multi-account registry with backend-persisted logs."""

    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else _DEFAULT_ROOT
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        self.global_logs_path = self.root / "global_logs.jsonl"
        self._lock = threading.RLock()
        self._accounts: dict[str, AccountRuntime] = {}
        self._global_seq = 0
        self._global_logs: deque[dict] = deque(maxlen=1000)
        self._load_global_tail()
        self._load_index()

    # -------------------------------------------------------------- index
    def _load_index(self) -> None:
        items: list[dict] = []
        if self.index_path.is_file():
            try:
                data = json.loads(self.index_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    items = list(data.get("accounts") or [])
                elif isinstance(data, list):
                    items = data
            except Exception as e:
                log.warning("load index failed: %s", e)
        for meta in items:
            if not isinstance(meta, dict) or not meta.get("id"):
                continue
            aid = str(meta["id"])
            if aid in self._accounts:
                continue
            try:
                self._accounts[aid] = AccountRuntime(self, meta)
            except Exception as e:
                log.warning("init account %s failed: %s", aid, e)

    def _write_index(self) -> None:
        items = []
        for aid, acc in self._accounts.items():
            items.append({
                "id": aid,
                "label": acc.label,
                "username": acc._username or acc._cfg.get("username") or "",
                "created_at": acc._cfg.get("created_at") or "",
            })
        tmp = self.index_path.with_suffix(".tmp")
        payload = {"accounts": items, "updated_at": _now_iso()}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.index_path)

    def _load_global_tail(self, max_lines: int = 400) -> None:
        if not self.global_logs_path.is_file():
            return
        try:
            lines = self.global_logs_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            for line in lines[-max_lines:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                gseq = int(entry.get("gseq") or entry.get("seq") or 0)
                if gseq > self._global_seq:
                    self._global_seq = gseq
                self._global_logs.append(entry)
        except Exception as e:
            log.warning("load global logs failed: %s", e)

    def append_global_log(self, entry: dict) -> dict:
        with self._lock:
            self._global_seq += 1
            gentry = dict(entry)
            gentry["gseq"] = self._global_seq
            if "ts" not in gentry:
                gentry["ts"] = _now_iso()
            self._global_logs.append(gentry)
            try:
                with open(self.global_logs_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(gentry, ensure_ascii=False) + "\n")
            except Exception as e:
                log.warning("append global log failed: %s", e)
            return gentry

    def get_global_logs(self, since: int = 0) -> list[dict]:
        with self._lock:
            return [e for e in self._global_logs if int(e.get("gseq") or 0) > since]

    def clear_global_logs(self) -> dict:
        """Clear bottom 「运行日志」 ring + file (DOM clear alone was cosmetic)."""
        with self._lock:
            self._global_logs.clear()
            try:
                self.global_logs_path.write_text("", encoding="utf-8")
            except Exception as e:
                log.warning("clear global logs file failed: %s", e)
                return {"ok": False, "error": str(e)}
        self.append_global_log(
            {
                "level": "info",
                "msg": "运行日志已清空",
                "account_id": "",
                "account_label": "",
            }
        )
        return {"ok": True, "cleared": True}

    # -------------------------------------------------------------- CRUD
    def list_accounts(self) -> list[dict]:
        with self._lock:
            return [a.public_meta() for a in self._accounts.values()]

    def get(self, account_id: str) -> AccountRuntime | None:
        with self._lock:
            return self._accounts.get(account_id)

    def create(self, label: str = "", username: str = "", password: str = "") -> dict:
        label = (label or username or "账号").strip()
        base = _slug(username or label)
        aid = f"{base}-{uuid.uuid4().hex[:6]}"
        created = _now_iso()
        meta = {
            "id": aid,
            "label": label,
            "username": username,
            "created_at": created,
        }
        with self._lock:
            acc = AccountRuntime(self, meta)
            if username:
                acc._username = username
                acc._cfg["username"] = username
            if password:
                acc._password = password
                acc._cfg["password"] = password
            acc._cfg["created_at"] = created
            acc._cfg["updated_at"] = created
            acc._save_cfg()
            self._accounts[aid] = acc
            self._write_index()
        # Pure card create; login is explicit via /api/accounts/<id>/login
        # (matches composer: create → login → desktops → keepalive).
        acc.log("INFO", f"账号卡片已创建 label={label}")
        return {"account": acc.public_meta()}

    def delete(self, account_id: str) -> dict:
        with self._lock:
            acc = self._accounts.pop(account_id, None)
            if not acc:
                return {"ok": False, "error": "账号不存在"}
            try:
                acc.stop_keepalive()
            except Exception:
                pass
            self._write_index()
        self.append_global_log({
            "ts": _now_iso(),
            "level": "INFO",
            "msg": f"账号卡片已删除 id={account_id}",
            "account_id": account_id,
            "label": acc.label,
        })
        # keep on-disk files for audit; do not wipe secrets aggressively here
        return {"ok": True}

    def rename(self, account_id: str, label: str) -> dict:
        acc = self.get(account_id)
        if not acc:
            return {"ok": False, "error": "账号不存在"}
        acc.update_label(label)
        with self._lock:
            self._write_index()
        return {"ok": True, "account": acc.public_meta()}

    def update_account(self, account_id: str, **kwargs) -> dict:
        acc = self.get(account_id)
        if not acc:
            return {"ok": False, "error": "账号不存在"}
        result = acc.update_settings(**kwargs)
        if result.get("ok"):
            with self._lock:
                self._write_index()
        return result


# process-wide singleton used by Flask server
_REGISTRY: AccountRegistry | None = None
_REGISTRY_LOCK = threading.Lock()


def get_registry() -> AccountRegistry:
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            _REGISTRY = AccountRegistry()
        return _REGISTRY
