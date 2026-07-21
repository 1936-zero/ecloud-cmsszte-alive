"""
Flask Web UI 服务。

提供 JSON API + 单页 HTML 前端，复用现有 login/desktop_session 模块。
登录交互改为 API 驱动（不再用 input()）。
"""
import json
import logging
import os
import secrets
import sys
import threading
import time
from pathlib import Path

from flask import Flask, request, jsonify, render_template, g

# 确保能 import 项目根目录的模块
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import config
import device
import login
import desktop_list
import desktop_session
from ecloud_client import EcloudHttpUtil, EcloudError
from web.keepalive_manager import AccountKeepaliveManager, KeepaliveManager
from web.account_runtime import get_registry

log = logging.getLogger("web")

# ---------------------------------------------------------------------------
# 全局状态（单用户场景，无需 session/DB）
# ---------------------------------------------------------------------------
CONFIG_FILE = os.environ.get(
    "CLOUD_PC_CONFIG_FILE",
    os.path.join(_PROJECT_ROOT, "cloud_pc.json"),
)

_app_state = {
    "http": None,           # EcloudHttpUtil 实例（登录后创建）
    "cfg": {},              # cloud_pc.json 内容
    "username": "",         # 待登录的用户名（短信验证流程中间态）
    "password": "",         # 待登录的密码（同上）
    "mobile": "",           # 短信验证手机号
    "login_type": "",       # 当前登录分支: device_trust / two_factor / enhanced_sms
    "login_code": None,     # 未授信设备信任流程需要的服务端 code
}
_lock = threading.Lock()
_account_ka = AccountKeepaliveManager()
_ka = KeepaliveManager()
_watchdog_lock = threading.Lock()
_watchdog_started = False
_WATCHDOG_INTERVAL = int(os.environ.get("CLOUD_PC_KEEPALIVE_WATCHDOG_INTERVAL", "60"))


def _token_maybe_expired(err: EcloudError) -> bool:
    msg = (err.message or "").lower()
    return any(h in msg for h in ["token", "失效", "未登录", "expire", "401", "授权"])


def _preflight_uptime(http: EcloudHttpUtil, instance_id: str) -> str:
    """Use desktopUptime as the runtime source of truth before starting keepalive."""
    if not instance_id:
        raise EcloudError({
            "errorCode": "NO_INSTANCE",
            "errorMessage": "缺少桌面实例 ID",
        })
    return desktop_session.DesktopSession(http, instance_id).report_uptime()


def _safe_log_obj(obj):
    """Return a JSON-safe copy with sensitive values redacted for diagnostics."""
    sensitive = {
        "password", "accessToken", "access_token", "accessTicket",
        "access_ticket", "verificationCode", "token",
    }
    if isinstance(obj, dict):
        return {
            k: ("[redacted]" if k in sensitive else _safe_log_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_safe_log_obj(v) for v in obj]
    return obj


def _load_cfg() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_cfg(cfg: dict):
    tmp_file = f"{CONFIG_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, CONFIG_FILE)
    finally:
        if os.path.exists(tmp_file):
            os.unlink(tmp_file)


def _persist_keepalive_autostart(enabled: bool, interval: int | None = None):
    with _lock:
        cfg = _app_state["cfg"]
        cfg["keepalive_autostart"] = bool(enabled)
        if interval is not None:
            cfg["keepalive_interval"] = interval
        _save_cfg(cfg)


def _persist_account_keepalive_autostart(enabled: bool, interval: int | None = None):
    with _lock:
        cfg = _app_state["cfg"]
        cfg["account_keepalive_autostart"] = bool(enabled)
        if interval is not None:
            cfg["account_keepalive_interval"] = interval
        _save_cfg(cfg)


def _get_or_create_http() -> EcloudHttpUtil:
    """获取或创建 HTTP 客户端（复用全局实例）。"""
    with _lock:
        if _app_state["http"] is None:
            cfg = _app_state["cfg"]
            dev = device.detect(device_uid=cfg.get("device_uid"))
            cfg["device_uid"] = dev.device_uid
            client = EcloudHttpUtil(dev.to_common_params())
            if cfg.get("access_token"):
                client.set_token(cfg["access_token"])
            _app_state["http"] = client
        return _app_state["http"]


def _set_token(token: str):
    """更新 token 到全局 client 和配置文件。"""
    with _lock:
        _app_state["cfg"]["access_token"] = token
        _save_cfg(_app_state["cfg"])
        if _app_state["http"]:
            _app_state["http"].set_token(token)


def _relogin_with_saved_credentials() -> str | None:
    """Use saved username/password to refresh an expired access token."""
    with _lock:
        cfg_state = _app_state.get("cfg", {})
        username = _app_state.get("username") or cfg_state.get("username", "")
        password = _app_state.get("password") or cfg_state.get("password", "")
    if not username or not password:
        return None

    http = _get_or_create_http()
    http.clear_token()
    result = login.login_with_password(http, username, password)
    log.info("auto relogin result: %s", json.dumps(_safe_log_obj({
        "status": result.get("status"),
        "error_code": result.get("error_code"),
        "error": result.get("error"),
        "mobile_present": bool(result.get("mobile")),
        "login_code_present": bool(result.get("login_code")),
    }), ensure_ascii=False))
    if result.get("status") == login.LoginResult.SUCCESS and result.get("access_token"):
        token = result["access_token"]
        _set_token(token)
        return token
    return None


def _ensure_keepalive_autostart(reason: str = "watchdog") -> bool:
    """Start the in-process keepalive worker if config says it should be running."""
    if _ka.is_running():
        return True

    cfg = _app_state["cfg"]
    if not cfg.get("keepalive_autostart"):
        disk_cfg = _load_cfg()
        if not disk_cfg.get("keepalive_autostart"):
            return False
        with _lock:
            _app_state["cfg"] = disk_cfg
            cfg = disk_cfg

    instance_id = cfg.get("instance_id", "")
    if not instance_id:
        log.warning("keepalive autostart skipped: no instance_id")
        return False
    machine_id = cfg.get("machine_id", "")
    ticket = cfg.get("ticket", "")

    try:
        interval = int(cfg.get("keepalive_interval", 300))
    except (TypeError, ValueError):
        interval = 300
    if interval < 30:
        interval = 30

    http = _get_or_create_http()

    def _relogin():
        return _relogin_with_saved_credentials()

    ok = _ka.start(
        http,
        instance_id,
        machine_id=machine_id,
        ticket=ticket,
        interval=interval,
        relogin_fn=_relogin,
    )
    if ok:
        log.info(
            "keepalive autostart recovered by %s: instance=%s interval=%ds",
            reason, instance_id[:20], interval,
        )
    return ok


def _ensure_account_keepalive_autostart(reason: str = "watchdog") -> bool:
    """Start the account keepalive worker if config says it should be running."""
    if _account_ka.is_running():
        return True

    cfg = _app_state["cfg"]
    if not cfg.get("account_keepalive_autostart"):
        disk_cfg = _load_cfg()
        if not disk_cfg.get("account_keepalive_autostart"):
            return False
        with _lock:
            _app_state["cfg"] = disk_cfg
            cfg = disk_cfg

    if not cfg.get("access_token"):
        log.warning("account keepalive autostart skipped: no access_token")
        return False

    try:
        interval = int(cfg.get("account_keepalive_interval", 300))
    except (TypeError, ValueError):
        interval = 300
    if interval < 30:
        interval = 30

    http = _get_or_create_http()

    def _relogin():
        return _relogin_with_saved_credentials()

    ok = _account_ka.start(http, interval=interval, relogin_fn=_relogin)
    if ok:
        log.info("account keepalive autostart recovered by %s: interval=%ds", reason, interval)
    return ok


def _keepalive_autostart_watchdog(interval: int):
    while True:
        try:
            _ensure_account_keepalive_autostart()
            _ensure_keepalive_autostart()
        except Exception:
            log.exception("keepalive autostart watchdog failed")
        time.sleep(interval)


def _start_keepalive_autostart_watchdog(interval: int | None = None):
    """Run one watchdog per process. It restores keepalive after process restart."""
    global _watchdog_started
    with _watchdog_lock:
        if _watchdog_started:
            return
        _watchdog_started = True
    seconds = interval if interval is not None else _WATCHDOG_INTERVAL
    threading.Thread(
        target=_keepalive_autostart_watchdog,
        args=(seconds,),
        daemon=True,
        name="keepalive-autostart-watchdog",
    ).start()



# ---------------------------------------------------------------------------
# WebUI access-token gate (对标爱家 gate6：无 token = 开放；file > env)
# 文件: data/webui_access_token；环境: ECLOUD_WEBUI_TOKEN
# 请求头: Authorization Bearer / x-api-token / ?token=
# ---------------------------------------------------------------------------
_WEBUI_VERSION = "0.3.8-webui-access-gate"
_ACCESS_TOKEN_ENV = "ECLOUD_WEBUI_TOKEN"


def _webui_data_dir() -> Path:
    """Durable data root shared with multi-account registry."""
    override = (os.environ.get("ECLOUD_DATA_DIR") or "").strip()
    if override:
        return Path(override)
    # Prefer same parent as web_accounts when ECLOUD_WEB_ACCOUNTS_DIR is set
    acc = (os.environ.get("ECLOUD_WEB_ACCOUNTS_DIR") or "").strip()
    if acc:
        p = Path(acc)
        # if .../data/web_accounts → use .../data
        if p.name == "web_accounts":
            return p.parent
        return p
    return Path(_PROJECT_ROOT) / "data"


def _access_token_path() -> Path:
    return _webui_data_dir() / "webui_access_token"


def _read_access_token() -> str:
    """Resolve expected WebUI access token. Priority: file > ECLOUD_WEBUI_TOKEN env."""
    try:
        p = _access_token_path()
        if p.is_file():
            raw = p.read_text(encoding="utf-8", errors="replace").strip()
            for line in raw.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                return s
    except OSError:
        pass
    return (os.environ.get(_ACCESS_TOKEN_ENV) or "").strip()


def _write_access_token(token: str) -> Path:
    token = (token or "").strip()
    if not token:
        raise ValueError("empty token")
    if len(token) < 4:
        raise ValueError("token too short (min 4)")
    if len(token) > 256:
        raise ValueError("token too long (max 256)")
    if any(c.isspace() for c in token):
        raise ValueError("token must not contain whitespace")
    root = _webui_data_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = _access_token_path()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _clear_access_token_file() -> bool:
    path = _access_token_path()
    try:
        if path.is_file():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def _extract_request_token() -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (
        request.headers.get("x-api-token")
        or request.args.get("token")
        or ""
    ).strip()


def _token_ok(provided: str, expected: str) -> bool:
    if not expected:
        return True
    if not provided:
        return False
    # constant-time compare
    try:
        import hmac as _hmac
        return _hmac.compare_digest(provided, expected)
    except Exception:
        return provided == expected


def _auth_error(code: str, message: str, status: int = 401, next_step: str = ""):
    body = {"ok": False, "error": code, "message": message}
    if next_step:
        body["next_step"] = next_step
    return jsonify(body), status


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                static_folder=os.path.join(os.path.dirname(__file__), "static"))

    # 启动时加载配置
    _app_state["cfg"] = _load_cfg()

    # #75fixr: 穿透/内嵌浏览器常缓存旧 HTML/CSS；对页面与静态资源禁缓存
    @app.after_request
    def _no_cache_ui(resp):
        try:
            path = request.path or "/"
            if path in ("/", "/dashboard", "/index.html") or path.startswith("/static/"):
                resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Expires"] = "0"
        except Exception:
            pass
        return resp

    # -----------------------------------------------------------------------
    # 页面
    # -----------------------------------------------------------------------
    @app.route("/")
    @app.route("/dashboard")
    def index():
        return render_template("index.html")


    # -----------------------------------------------------------------------
    # Access-token gate (before_request) + auth/health open endpoints
    # -----------------------------------------------------------------------
    @app.before_request
    def _webui_access_gate():
        path = request.path or "/"
        open_exact = {
            "/",
            "/dashboard",
            "/index.html",
            "/health",
            "/api/health",
            "/api/system/health",
            "/api/system/info",
            "/api/info",
            "/api/auth/status",
            "/api/auth/setup",
            "/api/auth/login",
        }
        open_prefixes = ("/static/", "/favicon")
        if path in open_exact or path.startswith(open_prefixes):
            return None
        expected = _read_access_token()
        if not expected:
            return None  # auth disabled
        token = _extract_request_token()
        if not _token_ok(token, expected):
            return _auth_error(
                "TOKEN_INVALID",
                "访问密钥无效或缺失",
                401,
                next_step="请在登录门输入正确访问密钥，或在请求头携带 Bearer / x-api-token",
            )
        return None

    @app.route("/health")
    @app.route("/api/health")
    @app.route("/api/system/health")
    def api_health():
        return jsonify({"ok": True, "service": "ecloud-cloudpc-keepalive", "version": _WEBUI_VERSION})

    @app.route("/api/system/info")
    @app.route("/api/info")
    def api_system_info():
        expected = _read_access_token()
        has_file = False
        try:
            has_file = _access_token_path().is_file() and bool(
                _access_token_path().read_text(encoding="utf-8", errors="replace").strip()
            )
        except OSError:
            has_file = False
        has_env = bool((os.environ.get(_ACCESS_TOKEN_ENV) or "").strip())
        return jsonify({
            "ok": True,
            "service": "ecloud-cloudpc-keepalive",
            "version": _WEBUI_VERSION,
            "dataDir": str(_webui_data_dir()),
            "authEnabled": bool(expected),
            "authSource": ("file" if has_file else ("env" if has_env else "none")),
            "production_claim": False,
            "dual_evidence": False,
            "path_b": True,
        })

    @app.route("/api/auth/status", methods=["GET"])
    def api_auth_status():
        expected = _read_access_token()
        provided = _extract_request_token()
        authed = (not expected) or _token_ok(provided, expected)
        return jsonify({
            "ok": True,
            "setupRequired": False,  # gate6: empty token = auth off, no forced first-run
            "tokenRequired": bool(expected),
            "authEnabled": bool(expected),
            "authenticated": authed,
            "version": _WEBUI_VERSION,
        })

    @app.route("/api/auth/setup", methods=["POST"])
    def api_auth_setup():
        if _read_access_token():
            return _auth_error(
                "ALREADY_CONFIGURED",
                "访问密钥已存在，请使用登录或「设置令牌」修改",
                409,
                next_step="在登录页输入现有密钥；修改请用 /api/auth/change",
            )
        data = request.get_json(force=True, silent=True) or {}
        generate = bool(data.get("generate"))
        token = str(data.get("token") or data.get("accessToken") or "").strip()
        if generate or not token:
            token = secrets.token_urlsafe(18)
        try:
            path = _write_access_token(token)
        except ValueError as e:
            return _auth_error("VALIDATION", str(e), 400, next_step="请提供 4–256 位无空格密钥，或使用 generate")
        except OSError as e:
            return _auth_error("IO_ERROR", f"写入失败: {e}", 500)
        return jsonify({
            "ok": True,
            "authenticated": True,
            "token": token,
            "path": str(path),
            "message": "访问密钥已创建，请妥善保存",
        })

    @app.route("/api/auth/login", methods=["POST"])
    def api_auth_login():
        expected = _read_access_token()
        if not expected:
            return jsonify({
                "ok": True,
                "authenticated": True,
                "authEnabled": False,
                "message": "未启用访问密钥，已直接进入控制台",
            })
        data = request.get_json(force=True, silent=True) or {}
        token = str(data.get("token") or data.get("accessToken") or "").strip()
        if not token:
            token = _extract_request_token()
        if not _token_ok(token, expected):
            return _auth_error(
                "TOKEN_INVALID",
                "访问密钥错误",
                401,
                next_step="请检查密钥是否与服务器一致（data/webui_access_token 或 ECLOUD_WEBUI_TOKEN）",
            )
        return jsonify({"ok": True, "authenticated": True, "token": token})

    @app.route("/api/auth/change", methods=["POST"])
    def api_auth_change():
        expected = _read_access_token()
        data = request.get_json(force=True, silent=True) or {}
        current = str(data.get("currentToken") or data.get("oldToken") or "").strip()
        if not current:
            current = _extract_request_token()
        if expected and not _token_ok(current, expected):
            return _auth_error(
                "TOKEN_INVALID",
                "当前访问密钥错误，无法修改",
                401,
                next_step="请输入正确的当前密钥后再改密",
            )
        generate = bool(data.get("generate"))
        new_token = str(data.get("token") or data.get("newToken") or data.get("accessToken") or "").strip()
        if generate or not new_token:
            new_token = secrets.token_urlsafe(18)
        try:
            path = _write_access_token(new_token)
        except ValueError as e:
            return _auth_error("VALIDATION", str(e), 400)
        except OSError as e:
            return _auth_error("IO_ERROR", f"写入失败: {e}", 500)
        return jsonify({
            "ok": True,
            "authenticated": True,
            "token": new_token,
            "path": str(path),
            "message": "访问密钥已更新",
        })

    @app.route("/api/auth/disable", methods=["POST"])
    def api_auth_disable():
        expected = _read_access_token()
        has_env = bool((os.environ.get(_ACCESS_TOKEN_ENV) or "").strip())
        if has_env and not _access_token_path().is_file():
            return _auth_error(
                "ENV_TOKEN",
                f"当前密钥来自环境变量 {_ACCESS_TOKEN_ENV}，无法通过本接口关闭",
                400,
                next_step="请取消环境变量或改用文件密钥后再关闭鉴权",
            )
        if expected:
            data = request.get_json(force=True, silent=True) or {}
            current = str(data.get("token") or data.get("currentToken") or "").strip()
            if not current:
                current = _extract_request_token()
            if not _token_ok(current, expected):
                return _auth_error("TOKEN_INVALID", "当前访问密钥错误，无法关闭鉴权", 401)
        removed = _clear_access_token_file()
        return jsonify({
            "ok": True,
            "authEnabled": False,
            "removedFile": removed,
            "message": "已关闭访问密钥（文件已删除；若仍设环境变量则仍会启用）",
        })

    # -----------------------------------------------------------------------
    # 状态
    # -----------------------------------------------------------------------
    @app.route("/api/status")
    def api_status():
        cfg = _app_state["cfg"]
        logged_in = False
        error = ""
        if cfg.get("access_token"):
            try:
                http = _get_or_create_http()
                login.get_user_info(http)
                logged_in = True
            except EcloudError as e:
                if _token_maybe_expired(e):
                    log.info("saved token rejected by user-info check: %s", e.message)
                    if _relogin_with_saved_credentials():
                        logged_in = True
                    else:
                        error = e.message
                else:
                    log.info("user-info check failed, falling back to desktop list: %s", e.message)
                    try:
                        desktop_list.get_desktop_list(_get_or_create_http())
                        logged_in = True
                    except EcloudError as e2:
                        log.info("saved token rejected by desktop-list check: %s", e2.message)
                        if _token_maybe_expired(e2) and _relogin_with_saved_credentials():
                            logged_in = True
                        else:
                            error = e2.message
            except Exception as e:
                error = str(e)
                log.warning("saved token check failed: %s", e)

        payload = {
            "logged_in": logged_in,
            "username": cfg.get("username", ""),
            "device_uid": cfg.get("device_uid", ""),
            "account_keepalive": _account_ka.get_status(),
            "keepalive": _ka.get_status(),
        }
        if error:
            payload["error"] = error
        return jsonify(payload)

    # -----------------------------------------------------------------------
    # 登录
    # -----------------------------------------------------------------------
    @app.route("/api/login", methods=["POST"])
    def api_login():
        data = request.get_json(force=True)
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            return jsonify({"status": "failed", "error": "账号和密码不能为空"}), 400

        http = _get_or_create_http()
        http.clear_token()
        result = login.login_with_password(http, username, password)
        log.info("login result: %s", json.dumps(_safe_log_obj({
            "status": result.get("status"),
            "error_code": result.get("error_code"),
            "error": result.get("error"),
            "mobile_present": bool(result.get("mobile")),
            "login_code_present": bool(result.get("login_code")),
        }), ensure_ascii=False))

        with _lock:
            _app_state["username"] = username
            _app_state["password"] = password
            _app_state["cfg"]["username"] = username
            _app_state["cfg"]["password"] = password

        if result["status"] == login.LoginResult.SUCCESS:
            token = result["access_token"]
            _set_token(token)
            _save_cfg(_app_state["cfg"])
            return jsonify({"status": "success", "token": token[:20] + "..."})

        if result["status"] == login.LoginResult.NEED_DEVICE_TRUST:
            with _lock:
                _app_state["mobile"] = result.get("mobile", "")
                _app_state["login_type"] = "device_trust"
                _app_state["login_code"] = result.get("login_code")
            return jsonify({
                "status": "need_sms",
                "mobile": result.get("mobile", ""),
                "login_type": "device_trust",
                "message": "该设备未授信，需要短信验证",
            })

        if result["status"] == login.LoginResult.NEED_TWO_FACTOR:
            with _lock:
                _app_state["mobile"] = result.get("mobile", "")
                _app_state["login_type"] = "two_factor"
                _app_state["login_code"] = result.get("login_code")
            return jsonify({
                "status": "need_sms",
                "mobile": result.get("mobile", ""),
                "login_type": "two_factor",
                "message": "需要二次验证",
            })

        if result["status"] == login.LoginResult.NEED_ENHANCED_SMS:
            with _lock:
                _app_state["mobile"] = result.get("mobile", "")
                _app_state["login_type"] = "enhanced_sms"
                _app_state["login_code"] = result.get("login_code")
            return jsonify({
                "status": "need_sms",
                "mobile": result.get("mobile", ""),
                "login_type": "enhanced_sms",
                "message": "需要增强策略短信验证",
            })

        if result["status"] == login.LoginResult.NEED_4A:
            return jsonify({
                "status": "failed",
                "error": "需要 4A MFA 验证，暂不支持",
            })

        return jsonify({"status": "failed", "error": result.get("error", "登录失败")})

    @app.route("/api/send-sms", methods=["POST"])
    def api_send_sms():
        data = request.get_json(force=True)
        mobile = data.get("mobile", "").strip()
        with _lock:
            mobile = mobile or _app_state.get("mobile", "")
            login_type = _app_state.get("login_type", "")
            username = _app_state.get("username", "")
        if not mobile:
            return jsonify({"ok": False, "error": "缺少手机号"}), 400
        http = _get_or_create_http()
        try:
            if login_type == "two_factor":
                login.send_two_factor_sms(http, mobile, username)
            elif login_type == "device_trust":
                # 官方 certificaty: codeType="trust"；用 login 会导致 30002004
                login.send_sms(http, mobile, code_type="trust")
            else:
                # enhanced_sms 等：默认 login；sendSMSCode 不返回/覆盖登录会话 code
                login.send_sms(http, mobile, code_type="login")
            with _lock:
                _app_state["mobile"] = mobile
                # login_code 必须保留密码登录 body.code，禁止用短信响应覆盖
            log.info("send sms ok: login_type=%s mobile_present=%s login_code_present=%s",
                     login_type, bool(mobile), bool(_app_state.get("login_code")))
            return jsonify({"ok": True, "message": "短信已发送"})
        except EcloudError as e:
            log.warning("send sms failed: login_type=%s error=%s raw=%s",
                        login_type, e.message,
                        json.dumps(_safe_log_obj(e.resp), ensure_ascii=False))
            return jsonify({"ok": False, "error": e.message}), 200

    @app.route("/api/verify-sms", methods=["POST"])
    def api_verify_sms():
        data = request.get_json(force=True)
        code = login.normalize_sms_code(data.get("code", ""))
        mobile = data.get("mobile", "").strip()
        login_type = data.get("login_type", "")
        if not code:
            return jsonify({"status": "failed", "error": "验证码不能为空"}), 400

        with _lock:
            mobile = mobile or _app_state.get("mobile", "")
            login_type = login_type or _app_state.get("login_type", "device_trust")
            username = _app_state.get("username", "")
            password = _app_state.get("password", "")
            login_code = _app_state.get("login_code")

        http = _get_or_create_http()
        log.info("verify sms start: login_type=%s mobile_present=%s username_present=%s login_code_present=%s",
                 login_type, bool(mobile), bool(username), bool(login_code))
        try:
            if login_type == "device_trust":
                # 真网 30002009 的 body.code 常为 null；官方仍调用 trustDevice
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
                return jsonify({"status": "failed", "error": f"未知登录类型: {login_type}"})
        except EcloudError as e:
            log.warning("verify sms api error: login_type=%s error=%s raw=%s",
                        login_type, e.message,
                        json.dumps(_safe_log_obj(e.resp), ensure_ascii=False))
            return jsonify({
                "status": "failed",
                "error": e.message,
                "error_code": e.code,
            })

        if r["status"] == login.LoginResult.SUCCESS:
            token = r["access_token"]
            _set_token(token)
            with _lock:
                # 登录完成，清理一次性会话 code
                _app_state["login_code"] = None
                _app_state["login_type"] = ""
            return jsonify({"status": "success", "token": token[:20] + "..."})
        if r["status"] == login.LoginResult.NEED_4A:
            return jsonify({
                "status": "failed",
                "error": "需要 4A MFA 验证，暂不支持",
            })
        log.warning("verify sms failed: login_type=%s result=%s",
                    login_type, json.dumps(_safe_log_obj(r), ensure_ascii=False))
        return jsonify({
            "status": "failed",
            "error": r.get("error", "验证失败"),
            "error_code": r.get("error_code"),
            "raw": _safe_log_obj(r.get("raw")),
        })

    # -----------------------------------------------------------------------
    # 桌面列表
    # -----------------------------------------------------------------------
    @app.route("/api/desktops")
    def api_desktops():
        cfg = _app_state["cfg"]
        if not cfg.get("access_token"):
            return jsonify({"error": "未登录"}), 401
        http = _get_or_create_http()
        try:
            desktops = desktop_list.get_desktop_list(http)
            result = []
            for d in desktops:
                result.append({
                    "instance_id": d.instance_id,
                    "machine_id": d.machine_id,
                    "machine_name": d.machine_name,
                    "vendor": d.origin_company_code,
                    "status": d.status,
                })
            # 尝试获取状态
            try:
                statuses = desktop_list.get_desktop_status(http, desktops)
                for r in result:
                    r["status"] = statuses.get(r["instance_id"], "?")
            except EcloudError:
                pass
            return jsonify({"desktops": result})
        except EcloudError as e:
            return jsonify({"error": e.message}), 200

    # -----------------------------------------------------------------------
    # 保活控制
    # -----------------------------------------------------------------------
    @app.route("/api/account-keepalive/start", methods=["POST"])
    def api_account_ka_start():
        cfg = _app_state["cfg"]
        if not cfg.get("access_token"):
            return jsonify({"error": "未登录"}), 401

        data = request.get_json(silent=True) or {}
        try:
            interval = int(data.get("interval", 300))
        except (TypeError, ValueError):
            return jsonify({"error": "保活间隔必须是数字"}), 400
        if interval < 30:
            interval = 30

        http = _get_or_create_http()

        def _relogin():
            return _relogin_with_saved_credentials()

        ok = _account_ka.start(http, interval=interval, relogin_fn=_relogin)
        if not ok:
            return jsonify({"error": "账号保活已在运行"})
        _persist_account_keepalive_autostart(True, interval=interval)
        return jsonify({"ok": True, "interval": interval})

    @app.route("/api/account-keepalive/stop", methods=["POST"])
    def api_account_ka_stop():
        _persist_account_keepalive_autostart(False)
        ok = _account_ka.stop()
        return jsonify({"ok": ok})

    @app.route("/api/account-keepalive/status")
    def api_account_ka_status():
        return jsonify(_account_ka.get_status())

    @app.route("/api/account-keepalive/logs")
    def api_account_ka_logs():
        since = int(request.args.get("since", 0))
        return jsonify({"logs": _account_ka.get_logs(since)})

    @app.route("/api/keepalive/start", methods=["POST"])
    def api_ka_start():
        cfg = _app_state["cfg"]
        if not cfg.get("access_token"):
            return jsonify({"error": "未登录"}), 401

        data = request.get_json(silent=True) or {}
        instance_id = data.get("instance_id", "")
        machine_id = data.get("machine_id", "")
        ticket = data.get("ticket", "") or cfg.get("ticket", "")
        try:
            interval = int(data.get("interval", 300))
        except (TypeError, ValueError):
            return jsonify({"error": "保活间隔必须是数字"}), 400
        if interval < 30:
            interval = 30

        http = _get_or_create_http()

        def _relogin():
            """token 失效重登回调。"""
            return _relogin_with_saved_credentials()

        def _call_with_relogin(fn):
            try:
                return fn()
            except EcloudError as e:
                if _token_maybe_expired(e) and _relogin():
                    return fn()
                raise

        # 自动选桌面
        if not instance_id:
            try:
                desktops = _call_with_relogin(lambda: desktop_list.get_desktop_list(http))
                if not desktops:
                    return jsonify({"error": "账号下没有可用桌面"})
                try:
                    statuses = _call_with_relogin(lambda: desktop_list.get_desktop_status(http, desktops))
                except EcloudError as e:
                    statuses = {}
                    log.info("desktop status unavailable during start preflight: %s", e.message)

                selected = None
                preflight_errors = []
                for d in desktops:
                    st = statuses.get(d.instance_id, "")
                    try:
                        uptime = _call_with_relogin(lambda d=d: _preflight_uptime(http, d.instance_id))
                    except EcloudError as e:
                        label = d.machine_name or d.instance_id[:20] or "未知桌面"
                        state = f", status={st}" if st else ""
                        preflight_errors.append(f"{label}{state}: {e.message}")
                    else:
                        log.info("desktop preflight ok: instance=%s status=%s uptime=%s",
                                 d.instance_id[:20], st or "?", uptime)
                        selected = d
                        break
                if selected is None:
                    detail = preflight_errors[0] if preflight_errors else "desktopUptime 未返回运行时长"
                    return jsonify({"error": f"没有可保活桌面：{detail}"})
                instance_id = selected.instance_id
                machine_id = selected.machine_id
                cfg["instance_id"] = instance_id
                cfg["machine_id"] = selected.machine_id
                _save_cfg(cfg)
            except EcloudError as e:
                return jsonify({"error": f"拉取桌面列表失败: {e.message}"})
        else:
            if not machine_id and cfg.get("instance_id") == instance_id:
                machine_id = cfg.get("machine_id", "")
            if not machine_id:
                try:
                    desktops = _call_with_relogin(lambda: desktop_list.get_desktop_list(http))
                    for d in desktops:
                        if d.instance_id == instance_id:
                            machine_id = d.machine_id
                            break
                except EcloudError as e:
                    log.info("desktop machine_id lookup failed during start: %s", e.message)
            try:
                uptime = _call_with_relogin(lambda: _preflight_uptime(http, instance_id))
                log.info("desktop preflight ok: instance=%s uptime=%s", instance_id[:20], uptime)
            except EcloudError as e:
                return jsonify({"error": f"桌面不可保活: {e.message}"})
            cfg["instance_id"] = instance_id
            if machine_id:
                cfg["machine_id"] = machine_id
            if ticket:
                cfg["ticket"] = ticket
            _save_cfg(cfg)

        ok = _ka.start(
            http,
            instance_id,
            machine_id=machine_id,
            ticket=ticket,
            interval=interval,
            relogin_fn=_relogin,
        )
        if not ok:
            return jsonify({"error": "保活已在运行"})
        _persist_keepalive_autostart(True, interval=interval)
        return jsonify({"ok": True, "instance_id": instance_id, "interval": interval})

    @app.route("/api/keepalive/stop", methods=["POST"])
    def api_ka_stop():
        _persist_keepalive_autostart(False)
        ok = _ka.stop()
        return jsonify({"ok": ok})

    @app.route("/api/keepalive/status")
    def api_ka_status():
        return jsonify(_ka.get_status())

    # -----------------------------------------------------------------------
    # 日志
    # -----------------------------------------------------------------------
    @app.route("/api/logs")
    def api_logs():
        since = int(request.args.get("since", 0))
        return jsonify({"logs": _ka.get_logs(since)})

    @app.route("/api/all-logs")
    def api_all_logs():
        since = int(request.args.get("since", 0))
        desktop_since = int(request.args.get("desktop_since", since))
        account_since = int(request.args.get("account_since", since))
        logs = []
        for entry in _ka.get_logs(desktop_since):
            item = dict(entry)
            item["source"] = "桌面"
            logs.append(item)
        for entry in _account_ka.get_logs(account_since):
            item = dict(entry)
            item["source"] = "账号"
            logs.append(item)
        logs.sort(key=lambda item: (item.get("created_at", ""), item["seq"], item["source"]))
        return jsonify({"logs": logs})

    # -----------------------------------------------------------------------
    # 登出
    # -----------------------------------------------------------------------
    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        _persist_account_keepalive_autostart(False)
        _persist_keepalive_autostart(False)
        if _account_ka.is_running():
            _account_ka.stop()
        if _ka.is_running():
            _ka.stop()
        cfg = _app_state["cfg"]
        if cfg.get("access_token"):
            try:
                http = _get_or_create_http()
                login.logout(http)
            except Exception:
                pass
        cfg.pop("access_token", None)
        _save_cfg(cfg)
        with _lock:
            _app_state["http"] = None
        return jsonify({"ok": True})

    # -----------------------------------------------------------------------
    # Multi-account cards (Path B per-account; does not replace legacy /api/*)
    # -----------------------------------------------------------------------
    def _acc_or_404(account_id: str):
        acc = get_registry().get(account_id)
        if not acc:
            return None, (jsonify({"ok": False, "error": "账号不存在"}), 404)
        return acc, None

    @app.route("/api/accounts", methods=["GET"])
    def api_accounts_list():
        reg = get_registry()
        return jsonify({"ok": True, "accounts": reg.list_accounts()})

    @app.route("/api/accounts", methods=["POST"])
    def api_accounts_create():
        data = request.get_json(force=True, silent=True) or {}
        label = str(data.get("label") or "").strip()
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        reg = get_registry()
        result = reg.create(label=label, username=username, password=password)
        return jsonify({"ok": True, **result})

    @app.route("/api/accounts/<account_id>", methods=["GET"])
    def api_accounts_get(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        return jsonify({"ok": True, "account": acc.public_meta()})

    @app.route("/api/accounts/<account_id>", methods=["PATCH"])
    def api_accounts_patch(account_id: str):
        """Update label / password / Path-B interval / account-keepalive interval."""
        data = request.get_json(force=True, silent=True) or {}
        kwargs = {}
        if "label" in data:
            kwargs["label"] = str(data.get("label") or "").strip()
        if "password" in data and data.get("password") is not None:
            kwargs["password"] = str(data.get("password") or "")
        if "keepalive_interval" in data and data.get("keepalive_interval") is not None:
            kwargs["keepalive_interval"] = data.get("keepalive_interval")
        if (
            "account_keepalive_interval" in data
            and data.get("account_keepalive_interval") is not None
        ):
            kwargs["account_keepalive_interval"] = data.get(
                "account_keepalive_interval"
            )
        if "instance_id" in data:
            kwargs["instance_id"] = str(data.get("instance_id") or "").strip()
        if "machine_id" in data:
            kwargs["machine_id"] = str(data.get("machine_id") or "").strip()
        if "machine_name" in data:
            kwargs["machine_name"] = str(data.get("machine_name") or "").strip()
        if not kwargs:
            return jsonify({"ok": False, "error": "无更新字段"}), 400
        reg = get_registry()
        result = reg.update_account(account_id, **kwargs)
        if not result.get("ok"):
            code = 404 if result.get("error") == "账号不存在" else 400
            return jsonify(result), code
        return jsonify(result)

    @app.route("/api/accounts/<account_id>", methods=["DELETE"])
    def api_accounts_delete(account_id: str):
        reg = get_registry()
        result = reg.delete(account_id)
        if not result.get("ok"):
            return jsonify(result), 404
        return jsonify(result)

    @app.route("/api/accounts/<account_id>/login", methods=["POST"])
    def api_accounts_login(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        # allow re-login with stored creds when body empty
        if not username:
            username = str(acc._cfg.get("username") or acc._username or "").strip()
        if not password:
            password = str(acc._cfg.get("password") or acc._password or "")
        result = acc.login(username, password)
        return jsonify({**result, "account": acc.public_meta()})

    @app.route("/api/accounts/<account_id>/send-sms", methods=["POST"])
    def api_accounts_send_sms(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        mobile = str(data.get("mobile") or "").strip()
        result = acc.send_sms(mobile=mobile)
        status = 200 if result.get("ok") else 400
        return jsonify(result), status

    @app.route("/api/accounts/<account_id>/verify-sms", methods=["POST"])
    def api_accounts_verify_sms(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        mobile = str(data.get("mobile") or "").strip()
        code = str(data.get("code") or data.get("verification_code") or "")
        login_type = str(data.get("login_type") or "").strip()
        result = acc.verify_sms(mobile=mobile, code=code, login_type=login_type)
        return jsonify({**result, "account": acc.public_meta()})

    @app.route("/api/accounts/<account_id>/desktops", methods=["GET"])
    def api_accounts_desktops(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        result = acc.list_desktops()
        if result.get("error") and not result.get("desktops"):
            return jsonify({"ok": False, **result}), 400
        return jsonify({"ok": True, **result})

    @app.route("/api/accounts/<account_id>/keepalive/start", methods=["POST"])
    def api_accounts_ka_start(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        instance_id = str(data.get("instance_id") or "").strip()
        machine_id = str(data.get("machine_id") or "").strip()
        try:
            interval = int(data.get("interval") or 300)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "interval 必须是数字"}), 400
        result = acc.start_keepalive(
            instance_id=instance_id,
            machine_id=machine_id,
            interval=interval,
        )
        status = 200 if result.get("ok") else 400
        return jsonify({**result, "account": acc.public_meta()}), status

    @app.route("/api/accounts/<account_id>/keepalive/stop", methods=["POST"])
    def api_accounts_ka_stop(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        result = acc.stop_keepalive()
        return jsonify({**result, "account": acc.public_meta()})

    @app.route(
        "/api/accounts/<account_id>/account-keepalive/start", methods=["POST"]
    )
    def api_accounts_aka_start(account_id: str):
        """L1 账号登录态保活（CLI `python main.py keepalive`），独立于 Path B。"""
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        data = request.get_json(force=True, silent=True) or {}
        interval = data.get("interval")
        result = acc.start_account_keepalive(
            interval=int(interval) if interval is not None else None
        )
        status = 200 if result.get("ok") else 400
        return jsonify({**result, "account": acc.public_meta()}), status

    @app.route(
        "/api/accounts/<account_id>/account-keepalive/stop", methods=["POST"]
    )
    def api_accounts_aka_stop(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        result = acc.stop_account_keepalive()
        return jsonify({**result, "account": acc.public_meta()})

    @app.route("/api/accounts/<account_id>/logs", methods=["GET"])
    def api_accounts_logs(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        since = int(request.args.get("since", 0) or 0)
        return jsonify({"ok": True, "logs": acc.get_logs(since)})

    @app.route("/api/accounts/<account_id>/logs", methods=["DELETE"])
    def api_accounts_logs_clear(account_id: str):
        """Clear per-account backend log ring (爱家 clear-logs 真源)."""
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        result = acc.clear_logs()
        return jsonify(result)

    @app.route("/api/accounts/<account_id>/logout", methods=["POST"])
    def api_accounts_logout(account_id: str):
        acc, err = _acc_or_404(account_id)
        if err:
            return err
        result = acc.logout()
        return jsonify({**result, "account": acc.public_meta()})

    @app.route("/api/global-logs", methods=["GET"])
    def api_global_logs():
        since = int(request.args.get("since", 0) or 0)
        reg = get_registry()
        return jsonify({"ok": True, "logs": reg.get_global_logs(since)})

    @app.route("/api/global-logs/clear", methods=["POST"])
    def api_global_logs_clear():
        reg = get_registry()
        return jsonify(reg.clear_global_logs())

    return app


def run(host: str = "0.0.0.0", port: int = 8080):
    """启动 Flask 服务。"""
    app = create_app()
    _start_keepalive_autostart_watchdog()
    log.info("Web UI 启动: http://%s:%d", host, port)
    app.run(host=host, port=port, debug=False, threaded=True)
