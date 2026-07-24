"""
Ecloud Cloud Computer V3.8.2 keepalive tool - CLI entry.

Usage:
  python main.py login          interactive login, save cloud_pc.json
  python main.py keepalive      keepalive loop (default 300s, unlimited)
  python main.py keepalive --interval 300 --rounds 100
  python main.py path-b-keepalive --rounds 1
  python main.py path-b-keepalive --interval 300 --rounds 312 --heart-listen 60
  python main.py path-a-probe --origin-company-code CMSSZTE
  python main.py spice-keepalive --dry-run --origin-company-code CMSSZTE
  python main.py status         check token validity
  python main.py logout         logout and clear config

cloud_pc.json schema:
{
  "username": "...",
  "password": "...",
  "device_uid": "...",
  "access_token": "...",
  "device_info": {...}
}
"""
import argparse
import getpass
import json
import logging
import os
import sys
import traceback

import config
import device
import keepalive
import login
from ecloud_client import EcloudHttpUtil, EcloudError

CONFIG_FILE = os.environ.get(
    "CLOUD_PC_CONFIG_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloud_pc.json"),
)

log = logging.getLogger("cloudpc")


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def _ensure_interactive(action: str = "登录") -> None:
    """Non-TTY must not fall into input()/EOFError (systemd/pipe/Docker exec)."""
    if not sys.stdin.isatty():
        log.error(
            "需要交互%s，但当前 stdin 非 TTY。请先执行: python3 main.py login",
            action,
        )
        sys.exit(2)


def _prompt_line(prompt: str) -> str:
    _ensure_interactive()
    return input(prompt).strip()


def build_client(cfg: dict) -> EcloudHttpUtil:
    """Build a client injected with device fingerprint and token from config.

    Only device_uid matters (server identifies device by it). All other
    commonParams fields are unverified by the server — see device.py docstring.
    """
    dev = device.detect(device_uid=cfg.get("device_uid"))
    cfg["device_uid"] = dev.device_uid  # ensure persisted (stable across runs)

    client = EcloudHttpUtil(dev.to_common_params())
    if cfg.get("access_token"):
        client.set_token(cfg["access_token"])
    return client


def do_login(cfg: dict):
    """Run full login flow (with SMS branch interaction). Returns access_token or None."""
    client = build_client(cfg)

    username = cfg.get("username")
    password = cfg.get("password")
    if not username or not password:
        _ensure_interactive("登录（需账号/密码）")
    username = username or _prompt_line("account: ")
    if not password:
        password = getpass.getpass("password: ")
    cfg["username"], cfg["password"] = username, password

    # #75fixam-fix: CLI interactive login 不限流（用户明确：限流只挡 WebUI 交互重登，
    # 避免运维/CLI 被误伤；保活 quiet 路径本来也不计次）
    # 文案提示：WebUI 交互登录仍有 10 分钟 ≤3 次保护，CLI 手动登录不受影响
    log.info(
        "login %s ... (CLI 不限流；WebUI 交互登录 10 分钟内 ≤3 次，超限会临时锁定)",
        username,
    )
    result = login.login_with_password(client, username, password)

    if result["status"] == login.LoginResult.SUCCESS:
        log.info("OK: login success")
        token = result["access_token"]
        cfg["access_token"] = token
        save_config(cfg)
        try:
            info = login.get_user_info(client)
            log.info("user info: %s", info)
        except EcloudError as e:
            log.warning("get user info failed: %s", e)
        return token

    status = result["status"]
    login_code = result.get("login_code")
    if status == login.LoginResult.NEED_DEVICE_TRUST:
        # 真网 30002009 的 body.code 常为 null；官方仍调用 trustDevice
        log.info("need device trust. mobile: %s login_code_present=%s",
                 result.get("mobile"), bool(login_code))
        mobile = result.get("mobile") or _prompt_line("mobile: ")
        # 官方 certificaty 发信用 codeType=trust；login 场景码无法用于 trustDevice
        login.send_sms(client, mobile, code_type="trust")
        # 请用半角数字；程序也会把全角 ０-９ 自动转半角
        sms_code = login.normalize_sms_code(_prompt_line("sms code (half-width digits): "))
        log.info("sms code normalized len=%d", len(sms_code))
        try:
            r = login.complete_device_trust(
                client, mobile, sms_code, username, code=login_code,
            )
        except EcloudError as e:
            log.error("device trust failed: [%s] %s", e.code, e.message)
            return None
        if r["status"] == login.LoginResult.SUCCESS:
            cfg["access_token"] = r["access_token"]
            save_config(cfg)
            log.info("OK: device trusted, login success")
            return r["access_token"]
        log.error("device trust failed: %s", r.get("error", r.get("raw")))
    elif status == login.LoginResult.NEED_TWO_FACTOR:
        log.info("need two-factor. mobile: %s login_code_present=%s",
                 result.get("mobile"), bool(login_code))
        mobile = result.get("mobile") or _prompt_line("mobile: ")
        login.send_two_factor_sms(client, mobile, username)
        sms_code = login.normalize_sms_code(_prompt_line("two-factor sms code (half-width): "))
        try:
            r = login.complete_two_factor(
                client, mobile, username, password, sms_code, code=login_code,
            )
        except EcloudError as e:
            log.error("two-factor failed: [%s] %s", e.code, e.message)
            return None
        if r["status"] == login.LoginResult.SUCCESS:
            cfg["access_token"] = r["access_token"]
            save_config(cfg)
            log.info("OK: two-factor passed, login success")
            return r["access_token"]
        log.error("two-factor failed: %s", r.get("error", r.get("raw")))
    elif status == login.LoginResult.NEED_ENHANCED_SMS:
        log.info("need enhanced-strategy sms. mobile: %s login_code_present=%s",
                 result.get("mobile"), bool(login_code))
        mobile = result.get("mobile") or _prompt_line("mobile: ")
        login.send_sms(client, mobile)
        sms_code = login.normalize_sms_code(_prompt_line("enhanced sms code (half-width): "))
        try:
            r = login.complete_enhanced_sms(
                client, mobile, username, sms_code, code=login_code,
            )
        except EcloudError as e:
            log.error("enhanced sms failed: [%s] %s", e.code, e.message)
            return None
        if r["status"] == login.LoginResult.SUCCESS:
            cfg["access_token"] = r["access_token"]
            save_config(cfg)
            log.info("OK: enhanced sms passed, login success")
            return r["access_token"]
        log.error("enhanced sms failed: %s", r.get("error", r.get("raw")))
    elif status == login.LoginResult.NEED_4A:
        log.error("need 4A MFA (userId=%s), not supported, use another method",
                  result.get("user_id"))
    else:
        log.error("login failed: %s", result.get("error", result.get("raw")))

    return None


def cmd_login(args):
    cfg = load_config()
    token = do_login(cfg)
    if token:
        log.info("token: %s...%s", token[:8], token[-6:])
    sys.exit(0 if token else 1)


def _resolve_desktop_for_spice(args, cfg, client, relogin_fn):
    """Pick instance_id/machine_id (+ origin) from CLI, cfg cache, or auto list.

    Returns (instance_id, machine_id, origin_company_code).
    #75fixaj: origin drives CMSSZTE→path_b / non-CMSS→http routing.
    """
    import desktop_list

    instance_id = getattr(args, "instance_id", None) or cfg.get("instance_id") or ""
    machine_id = getattr(args, "machine_id", None) or cfg.get("machine_id") or ""
    origin = (
        getattr(args, "origin_company", None)
        or cfg.get("origin_company_code")
        or ""
    )
    no_auto = bool(getattr(args, "no_auto_select", False))
    desktop = None

    if not instance_id and not no_auto:
        log.info("auto-selecting desktop from /user/getDeviceInfo ...")
        try:
            desktop = desktop_list.select_running_desktop(client)
        except EcloudError as e:
            log.error("拉取桌面列表失败: %s", e)
            if _token_maybe_expired(e) and relogin_fn and relogin_fn():
                desktop = desktop_list.select_running_desktop(client)
            else:
                sys.exit(1)
        if desktop is None:
            log.error("账号下没有可用桌面。请先在门户或本工具内创建/开机桌面。")
            sys.exit(1)
        instance_id = desktop.instance_id
        machine_id = desktop.machine_id or machine_id
        origin = getattr(desktop, "origin_company_code", "") or origin
        log.info("auto-selected: %s origin=%s", desktop, origin or "?")
    elif instance_id and not origin:
        # Look up origin for specified instance so vendor routing is correct
        try:
            desktops = desktop_list.get_desktop_list(client)
            for d in desktops:
                if d.instance_id == instance_id:
                    desktop = d
                    machine_id = machine_id or d.machine_id or ""
                    origin = getattr(d, "origin_company_code", "") or origin
                    break
        except EcloudError as e:
            log.warning("origin lookup failed: %s", e)
            if _token_maybe_expired(e) and relogin_fn and relogin_fn():
                try:
                    desktops = desktop_list.get_desktop_list(client)
                    for d in desktops:
                        if d.instance_id == instance_id:
                            origin = getattr(d, "origin_company_code", "") or origin
                            machine_id = machine_id or d.machine_id or ""
                            break
                except EcloudError:
                    pass

    if not instance_id:
        log.error("need instance_id (CLI / cfg / auto-select).")
        sys.exit(1)

    cfg["instance_id"] = instance_id
    if machine_id:
        cfg["machine_id"] = machine_id
    if origin:
        cfg["origin_company_code"] = origin
    save_config(cfg)
    return instance_id, machine_id, (origin or "")


def _run_spice_oracle_entry(args, cfg, client, relogin_fn):
    """Shared entry: SPICE path_B HEART + status/uptime oracle (claim=false)."""
    from pathlib import Path

    from l3.platform_paths import DEFAULT_PLAIN, DEFAULT_POST, DEFAULT_PRE
    from l3.product_setup import run_product_setup
    from l3.spice_oracle_keepalive_loop import run_spice_oracle_keepalive_loop

    # #75fixaj: resolver now returns (instance_id, machine_id, origin)
    instance_id, machine_id, _origin = _resolve_desktop_for_spice(
        args, cfg, client, relogin_fn
    )
    # issue#1: cross-platform defaults (no bare /tmp on Windows)
    plain = Path(getattr(args, "plain", "") or cfg.get("plain_path") or DEFAULT_PLAIN)
    if not plain.is_file() or plain.stat().st_size <= 0:
        # Align with WebUI: auto mint via product_setup when plain missing
        log.info(
            "SPICE plain missing at %s → auto mint via product_setup (issue#1)",
            plain,
        )
        try:
            mint_result = run_product_setup(
                cfg=cfg,
                client=client,
                save_config=save_config,
                plain_path=plain,
                do_power=True,
                force_power=False,
                do_mint=True,
                do_path_b=False,
                instance_id=instance_id or str(cfg.get("instance_id") or ""),
                machine_id=machine_id or str(cfg.get("machine_id") or ""),
            )
            cfg = load_config()  # reload after mint may update gateway
            if not (plain.is_file() and plain.stat().st_size > 0):
                log.error(
                    "SPICE plain still missing after auto-mint at %s "
                    "(stage=%s err=%s). Run: python3 main.py setup "
                    "or set --plain / SHORT_CONNECT_PLAIN_FILE.",
                    plain,
                    getattr(mint_result, "stage", ""),
                    getattr(mint_result, "error", ""),
                )
                sys.exit(1)
            log.info("SPICE plain minted ok stage=%s", getattr(mint_result, "stage", ""))
        except Exception as e:
            log.error(
                "SPICE plain auto-mint failed at %s: %s:%s. "
                "Run: python3 main.py setup or set --plain.",
                plain,
                type(e).__name__,
                e,
            )
            sys.exit(1)

    # issue#2: empty/default host → resolve_gateway(cloud_pc regional CAG);
    # stock GZ4 must not hard-override device_customLoginParams.
    host = (getattr(args, "host", None) or "").strip()
    if not host:
        try:
            from l3.gateway_config import resolve_gateway

            _gw = resolve_gateway(try_client_discovery=True, allow_default=True)
            host = str(_gw.cag_host or "")
            log.info(
                "SPICE host from resolve_gateway: %s src=%s",
                host,
                getattr(_gw, "source", ""),
            )
        except Exception as e:  # noqa: BLE001
            from l3.gateway_config import DEFAULT_CAG_HOST

            host = DEFAULT_CAG_HOST
            log.warning("resolve_gateway failed (%s); fallback host=%s", e, host)
    pre = Path(getattr(args, "pre", None) or DEFAULT_PRE)
    post = Path(getattr(args, "post", None) or DEFAULT_POST)
    out_dir = Path(
        getattr(args, "out_dir", None)
        or "reports/r26_live/spice_oracle_soak"
    )
    heart_listen = float(getattr(args, "heart_listen", 60.0) or 60.0)
    ticket_mode = str(getattr(args, "ticket_mode", None) or "zeros")
    session_nudge = getattr(args, "session_nudge", None)
    agent_hb_every = float(getattr(args, "agent_hb_every", 0.0) or 0.0)
    do_account_ping = not bool(getattr(args, "no_account_ping", False))
    stop_on_fatal = bool(getattr(args, "stop_on_fatal", False))
    # default ON: power-on / stale plain → remint once then retry path_B
    auto_remint = not bool(getattr(args, "no_auto_remint", False))
    remint_timeout_s = float(getattr(args, "remint_timeout", 20.0) or 20.0)
    plain_ttl_s = float(getattr(args, "plain_ttl", 0.0) or 0.0)
    mid_session_reconnect = not bool(getattr(args, "no_mid_session_reconnect", False))

    log.info(
        "SPICE+oracle keepalive start host=%s instance=%s interval=%s "
        "heart_listen=%s auto_remint=%s plain_ttl=%s mid_session=%s "
        "claim=false dual_ok=false",
        host,
        instance_id[:20] if instance_id else "-",
        args.interval,
        heart_listen,
        auto_remint,
        plain_ttl_s,
        mid_session_reconnect,
    )
    finished = run_spice_oracle_keepalive_loop(
        http=client,
        instance_id=instance_id,
        machine_id=machine_id or "",
        host=host,
        plain=plain,
        pre=pre,
        post=post,
        heart_listen=heart_listen,
        ticket_mode=ticket_mode,
        session_nudge=session_nudge,
        agent_hb_every=agent_hb_every,
        interval=int(args.interval),
        max_rounds=args.rounds,
        out_dir=out_dir,
        relogin_fn=relogin_fn,
        do_account_ping=do_account_ping,
        stop_on_fatal=stop_on_fatal,
        auto_remint=auto_remint,
        remint_timeout_s=remint_timeout_s,
        plain_ttl_s=plain_ttl_s,
        mid_session_reconnect=mid_session_reconnect,
    )
    log.info(
        "SPICE+oracle done rounds=%s ok_heart=%s ok_redq=%s fail=%s "
        "oracle_ok=%s remint_ok=%s remint_retry=%s last_status=%s last_uptime=%s claim=false",
        finished.get("rounds"),
        finished.get("ok_heart_rounds"),
        finished.get("ok_redq_rounds"),
        finished.get("fail_rounds"),
        finished.get("oracle_ok_rounds"),
        finished.get("remint_ok_rounds"),
        finished.get("remint_retry_rounds"),
        finished.get("last_resource_status"),
        finished.get("last_uptime"),
    )
    if finished.get("ok_heart_rounds", 0) > 0:
        sys.exit(0)
    if finished.get("ok_redq_rounds", 0) > 0:
        sys.exit(2)
    sys.exit(3)


def cmd_keepalive(args):
    """Default: SPICE path_B HEART + status/uptime oracle (claim=false).

    --legacy-http: old L1 account HTTP keepalive only (not desktop keep-alive).
    """
    cfg = load_config()
    if not cfg.get("access_token"):
        log.info("no saved token, login first")
        if not do_login(cfg):
            sys.exit(1)

    client = build_client(cfg)

    def _relogin():
        log.info("relogin %s", cfg.get("username"))
        t = do_login(cfg)
        if t:
            client.set_token(t)
        return t

    if bool(getattr(args, "legacy_http", False)):
        log.warning(
            "legacy-http: L1 account keepalive only "
            "(desktopUptime/SPICE NOT used; not desktop keep-alive)"
        )
        keepalive.run_keepalive_loop(
            client,
            relogin_fn=_relogin,
            interval=args.interval,
            max_rounds=args.rounds,
        )
        return

    _run_spice_oracle_entry(args, cfg, client, _relogin)


def cmd_setup(args):
    """Product setup: gateway → list → power_once → mint → optional path_B.

    Public ecloud only. No official client / no CDP.
    Power-on (operate=available) runs at most once per cloud_pc.json session.
    Never dumps plain/token. production_claim=false.
    """
    from pathlib import Path

    from l3.product_setup import DEFAULT_PLAIN, run_product_setup, selfcheck as setup_selfcheck

    if bool(getattr(args, "selfcheck", False)):
        sc = setup_selfcheck()
        print(json.dumps(sc, ensure_ascii=False, indent=2))
        sys.exit(0 if sc.get("ok") else 1)

    cfg = load_config()
    # optional: login first if no token and username present (password may prompt)
    if not cfg.get("access_token"):
        if cfg.get("username"):
            log.info("setup: no access_token → trying login ...")
            token = do_login(cfg)
            if not token:
                log.error("setup: login failed; fix cloud_pc.json then re-run")
                sys.exit(1)
            cfg = load_config()  # reload after login
        else:
            log.error("setup: no access_token; run: python3 main.py login")
            sys.exit(1)

    client = build_client(cfg)
    plain = getattr(args, "plain", None) or cfg.get("plain_path") or DEFAULT_PLAIN
    # argparse dest for --host/--cag-host is cag_host
    from l3.product_setup import DEFAULT_POWER_WAIT_S

    # --power-wait None → product default (15s / CLOUD_PC_POWER_WAIT)
    _pw = getattr(args, "power_wait", None)
    power_wait_s = float(DEFAULT_POWER_WAIT_S if _pw is None else _pw)
    result = run_product_setup(
        cfg=cfg,
        client=client,
        save_config=save_config,
        plain_path=plain,
        do_power=not bool(getattr(args, "no_power", False)),
        force_power=bool(getattr(args, "force_power", False)),
        do_mint=not bool(getattr(args, "no_mint", False)),
        do_path_b=bool(getattr(args, "with_path_b", False)),
        path_b_rounds=int(getattr(args, "path_b_rounds", 1) or 1),
        heart_listen=float(getattr(args, "heart_listen", 30.0) or 30.0),
        cag_host=getattr(args, "cag_host", None),
        cag_port=getattr(args, "cag_port", None),
        csapip=getattr(args, "csapip", None),
        instance_id=str(getattr(args, "instance_id", None) or ""),
        machine_id=str(getattr(args, "machine_id", None) or ""),
        mint_timeout=float(getattr(args, "mint_timeout", 25.0) or 25.0),
        power_wait_s=power_wait_s,
        mint_power_retry=not bool(getattr(args, "no_mint_power_retry", False)),
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    public = result.as_public_dict()
    print(json.dumps(public, ensure_ascii=False, indent=2))
    if result.ok:
        log.info(
            "setup OK stage=%s power_acted=%s mint_ok=%s",
            result.stage,
            (result.power or {}).get("acted"),
            (result.mint or {}).get("ok"),
        )
        sys.exit(0)
    log.error("setup FAIL stage=%s err=%s", result.stage, result.error)
    sys.exit(1)


def cmd_path_b_keepalive(args):
    """Path B SPICE HEART keepalive loop (claim=false; public_ecloud only).

    Wraps l3.path_b_keepalive_package with default interval=300s.
    Never dumps -k/plain/connectStr. dual_evidence_ok remains false until
    local_key LIVE pair lands.
    """
    from pathlib import Path

    from l3.platform_paths import DEFAULT_PLAIN, DEFAULT_POST, DEFAULT_PRE
    from l3.path_b_keepalive_loop import run_path_b_keepalive_loop

    plain = Path(getattr(args, "plain", "") or DEFAULT_PLAIN)
    if not plain.is_file():
        log.error(
            "path-b-keepalive: plain missing at %s (not logging contents). "
            "Run: python3 main.py setup  (or set --plain / SHORT_CONNECT_PLAIN_FILE)",
            plain,
        )
        sys.exit(1)

    session_nudge = None
    if bool(getattr(args, "session_nudge", False)):
        session_nudge = True
    if bool(getattr(args, "no_session_nudge", False)):
        session_nudge = False

    out_dir = Path(getattr(args, "out_dir", "") or "reports/r26_live/path_b_soak")
    # issue#2: empty host → resolve_gateway (cloud_pc regional CAG)
    _pb_host = str(getattr(args, "host", "") or "").strip()
    if not _pb_host:
        try:
            from l3.gateway_config import resolve_gateway

            _pb_host = str(resolve_gateway(try_client_discovery=True, allow_default=True).cag_host or "")
        except Exception:  # noqa: BLE001
            from l3.gateway_config import DEFAULT_CAG_HOST

            _pb_host = DEFAULT_CAG_HOST
    finished = run_path_b_keepalive_loop(
        host=_pb_host,
        plain=plain,
        pre=Path(getattr(args, "pre", "") or DEFAULT_PRE),
        post=Path(getattr(args, "post", "") or DEFAULT_POST),
        heart_listen=float(getattr(args, "heart_listen", 60.0) or 60.0),
        ticket_mode=str(getattr(args, "ticket_mode", "zeros") or "zeros"),
        session_nudge=session_nudge,
        agent_hb_every=float(getattr(args, "agent_hb_every", 0.0) or 0.0),
        interval=int(getattr(args, "interval", 300) or 300),
        max_rounds=getattr(args, "rounds", None),
        out_dir=out_dir,
        stop_on_fatal=bool(getattr(args, "stop_on_fatal", False)),
    )
    log.info(
        "path-b-keepalive done rounds=%s ok_heart=%s fail=%s claim=false",
        finished.get("rounds"),
        finished.get("ok_heart_rounds"),
        finished.get("fail_rounds"),
    )
    # Exit 0 if any heart ok or all rounds heart ok; 2 if only redq; 3 hard fail
    if finished.get("ok_heart_rounds", 0) > 0:
        sys.exit(0)
    if finished.get("ok_redq_rounds", 0) > 0:
        sys.exit(2)
    sys.exit(3)


def cmd_status(args):
    """检查 token 是否有效 + 显示桌面列表与保活状态。"""
    cfg = load_config()
    if not cfg.get("access_token"):
        log.info("not logged in (no token)")
        sys.exit(1)
    client = build_client(cfg)
    import desktop_list
    try:
        desktops = desktop_list.get_desktop_list(client)
        log.info("OK: token valid. %d desktop(s):", len(desktops))
        for d in desktops:
            print(f"  {d.machine_name}  instance={d.instance_id}  vendor={d.origin_company_code}")
        # 如果有缓存的 instance_id，顺便查一下运行时长
        inst = cfg.get("instance_id")
        if inst:
            import desktop_session
            sess = desktop_session.DesktopSession(client, inst)
            try:
                uptime = sess.report_uptime()
                log.info("desktop uptime (%s): %s", inst[:16], uptime)
            except EcloudError as e:
                log.warning("uptime query failed: %s", e)
    except EcloudError as e:
        log.error("FAIL: token invalid or api error: %s", e)
        sys.exit(1)


def cmd_logout(args):
    cfg = load_config()
    if cfg.get("access_token"):
        try:
            client = build_client(cfg)
            login.logout(client)
        except Exception as e:
            log.warning("logout request failed (ignored): %s", e)
    cfg.pop("access_token", None)
    save_config(cfg)
    log.info("logged out, token cleared")


def cmd_desktop_keepalive(args):
    """Desktop keepalive with vendor routing (#75fixaj).

    Flow: login → resolve desktop → power-on(preflight path) →
      CMSSZTE/ZTE → SPICE path_B (claim=false)
      non-CMSSZTE (H3C etc.) → pure HTTP desktopUptime

    --legacy-http: force HTTP loop regardless of vendor.
    --force-path-b: force Path B regardless of vendor (needs plain).
    """
    import desktop_session

    cfg = load_config()
    if not cfg.get("access_token"):
        log.info("no saved token, login first")
        if not do_login(cfg):
            sys.exit(1)

    client = build_client(cfg)

    def _relogin():
        log.info("relogin %s", cfg.get("username"))
        t = do_login(cfg)
        # #75fixaj: only set non-empty str token (do_login already returns str|None)
        if isinstance(t, str) and t.strip():
            client.set_token(t.strip())
            return t.strip()
        return None

    instance_id, machine_id, origin = _resolve_desktop_for_spice(
        args, cfg, client, _relogin
    )

    # #75fixaj: always power-on first (both Path B and HTTP), same as WebUI.
    # Docstring promised this; was missing → shutdown desktop skipped operate.
    if not bool(getattr(args, "no_power", False)):
        from l3.desktop_power_once import ensure_powered_once
        from l3.product_setup import DEFAULT_POWER_WAIT_S

        _pw = getattr(args, "power_wait", None)
        power_wait_s = float(DEFAULT_POWER_WAIT_S if _pw is None else _pw)
        try:
            pr = ensure_powered_once(
                client,
                cfg,
                machine_id=machine_id or "",
                instance_id=instance_id or "",
                wait_s=power_wait_s,
                save_cfg_fn=save_config,
            )
            log.info(
                "desktop-keepalive power_once acted=%s skip=%s "
                "status_before=%s status_after=%s wait_s=%s",
                pr.acted,
                pr.skipped_reason or "-",
                pr.status_before or "-",
                pr.status_after or "-",
                power_wait_s,
            )
        except Exception as e:
            log.warning(
                "desktop-keepalive power_once failed (continue to route): %s",
                e,
            )

    origin_u = (origin or "").strip().upper()
    force_http = bool(getattr(args, "legacy_http", False))
    force_path_b = bool(getattr(args, "force_path_b", False))

    # Vendor routing: CMSSZTE/ZTEECloud/ZTE → path_b; else → http
    is_cmss = origin_u in ("CMSSZTE", "ZTEECLOUD", "ZTE")
    use_http = force_http or (not force_path_b and origin_u and not is_cmss)
    # Unknown origin with no force: keep historical default path_b
    if not origin_u and not force_http:
        use_http = False

    if use_http:
        log.info(
            "HTTP desktopUptime keepalive: origin=%s force_http=%s "
            "(non-CMSSZTE or --legacy-http; claim=false)",
            origin_u or "?",
            force_http,
        )
        ticket = getattr(args, "ticket", None) or cfg.get("ticket") or ""
        if ticket:
            cfg["ticket"] = ticket
            save_config(cfg)
        desktop_session.run_desktop_keepalive(
            client,
            instance_id=instance_id,
            machine_id=machine_id,
            ticket=ticket,
            interval=args.interval,
            max_rounds=args.rounds,
            relogin_fn=_relogin,
        )
        return

    log.info(
        "Path B keepalive: origin=%s force_path_b=%s (CMSSZTE path; claim=false)",
        origin_u or "?",
        force_path_b,
    )
    _run_spice_oracle_entry(args, cfg, client, _relogin)


def cmd_web(args):
    """启动 Web UI（Flask）。"""
    from web import server
    server.run(host=args.host, port=args.port)


def _token_maybe_expired(err: EcloudError) -> bool:
    msg = (err.message or "").lower()
    return any(h in msg for h in ["token", "失效", "未登录", "expire", "401", "授权"])


def cmd_list_desktops(args):
    """列出可用云电脑。"""
    cfg = load_config()
    if not cfg.get("access_token"):
        log.info("no saved token, login first")
        if not do_login(cfg):
            sys.exit(1)
    client = build_client(cfg)
    import desktop_list
    try:
        desktops = desktop_list.get_desktop_list(client)
        if not desktops:
            log.info("no desktops found")
            return
        # 查状态
        try:
            statuses = desktop_list.get_desktop_status(client, desktops)
            for d in desktops:
                d.status = statuses.get(d.instance_id, "?")
        except EcloudError:
            pass
        log.info("found %d desktop(s):", len(desktops))
        for i, d in enumerate(desktops):
            print(f"  [{i}] instance={d.instance_id}")
            print(f"      machine={d.machine_id}")
            print(f"      name={d.machine_name}, vendor={d.origin_company_code}, status={d.status}")
        cur_i = cfg.get("instance_id") or ""
        cur_m = cfg.get("machine_id") or ""
        if cur_i or cur_m:
            print(
                f"  (current cfg) instance={cur_i or '-'} machine={cur_m or '-'}"
            )
            print("  tip: python3 main.py select-desktop  # 交互选一台写入配置")
    except EcloudError as e:
        log.error("failed: %s", e)
        sys.exit(1)


def cmd_select_desktop(args):
    """交互选择一台云电脑，写入 cloud_pc.json（多桌面时用）。"""
    cfg = load_config()
    if not cfg.get("access_token"):
        log.info("no saved token, login first")
        if not do_login(cfg):
            sys.exit(1)
    client = build_client(cfg)
    import desktop_list

    try:
        desktops = desktop_list.get_desktop_list(client)
    except EcloudError as e:
        log.error("拉取桌面列表失败: %s", e)
        sys.exit(1)
    if not desktops:
        log.error("账号下没有可用桌面。请先在门户或本工具内创建/开机桌面。")
        sys.exit(1)

    try:
        statuses = desktop_list.get_desktop_status(client, desktops)
        for d in desktops:
            d.status = statuses.get(d.instance_id, "?")
    except EcloudError:
        pass

    print(f"found {len(desktops)} desktop(s):")
    for i, d in enumerate(desktops):
        mark = ""
        if cfg.get("instance_id") and cfg.get("instance_id") == d.instance_id:
            mark = "  ← 当前配置"
        print(f"  [{i}] name={d.machine_name or '?'} status={getattr(d, 'status', '?')}{mark}")
        print(f"      instance={d.instance_id}")
        print(f"      machine={d.machine_id}")
        print(f"      vendor={d.origin_company_code}")

    # 非交互：--index / --instance-id
    pick = None
    idx = getattr(args, "index", None)
    want_id = (getattr(args, "instance_id", None) or "").strip()
    if want_id:
        for d in desktops:
            if d.instance_id == want_id:
                pick = d
                break
        if pick is None:
            log.error("instance_id 不在列表中: %s", want_id)
            sys.exit(1)
    elif idx is not None:
        if idx < 0 or idx >= len(desktops):
            log.error("index 越界: %s (0..%s)", idx, len(desktops) - 1)
            sys.exit(1)
        pick = desktops[idx]
    else:
        if not sys.stdin.isatty():
            log.error(
                "非交互环境请用: select-desktop --index N 或 --instance-id ID"
            )
            sys.exit(1)
        while True:
            raw = input(
                f"选择桌面序号 [0-{len(desktops) - 1}]"
                f"（回车=0，当前={cfg.get('instance_id') or '无'}）: "
            ).strip()
            if raw == "":
                pick = desktops[0]
                break
            try:
                n = int(raw)
            except ValueError:
                print("请输入数字序号")
                continue
            if 0 <= n < len(desktops):
                pick = desktops[n]
                break
            print("序号越界，请重试")

    cfg["instance_id"] = pick.instance_id
    if pick.machine_id:
        cfg["machine_id"] = pick.machine_id
    if getattr(pick, "origin_company_code", None):
        cfg["origin_company_code"] = pick.origin_company_code
    save_config(cfg)
    log.info(
        "已写入配置: instance=%s machine=%s name=%s",
        pick.instance_id,
        pick.machine_id,
        pick.machine_name,
    )
    print("OK: 下次 setup / run / desktop-keepalive 将使用这台桌面。")
    print("    多账号请用 WebUI 多卡片，或不同配置文件分进程。")


def _print_vendor_profile(profile, *, origin: str, source: str) -> None:
    """Print Path A VendorProfile fields only (no secrets, no VDI launch)."""
    print(f"path-a-probe: dry-run (no VDI launch)")
    print(f"  source={source}")
    print(f"  origin_company_code={origin}")
    print(f"  vendor_id={profile.vendor_id}")
    print(f"  service_name={profile.service_name}")
    print(f"  connect_schema_id={profile.connect_schema_id}")
    print(f"  pubkey_slot={profile.pubkey_slot}")
    print(f"  vdi_wrapper_path={profile.vdi_wrapper_path}")
    print(f"  vdi_client_path={profile.vdi_client_path}")
    print(f"  spice_conf_path={profile.spice_conf_path or ''}")
    print(f"  supports_path_a={profile.supports_path_a}")
    if profile.notes:
        print(f"  notes={profile.notes}")


def _print_spice_keepalive_plan(plan: dict, *, dry: bool) -> None:
    """Print Path A pipeline plan (no secrets / no raw cipher)."""
    mode = "dry-run (no VDI launch)" if dry else "LIVE (allow_live + i-know-risks)"
    print(f"spice-keepalive: {mode}")
    print(f"  origin={plan.get('origin')}")
    print(f"  vendor_id={plan.get('vendor_id')}")
    print(f"  machine_id={plan.get('machine_id') or ''}")
    print(f"  socketHost={plan.get('socketHost')}")
    print(f"  socketPort={plan.get('socketPort')}")
    print(f"  pubkey_slot={plan.get('pubkey_slot')}")
    print(f"  stage={plan.get('stage')}")
    plain = plan.get("plain_redacted") or {}
    if isinstance(plain, dict):
        print(f"  connect_json_fields={sorted(plain.keys())}")
    else:
        print(f"  plain_key_count={plan.get('plain_key_count')}")
    launch = plan.get("launch") or {}
    if isinstance(launch, dict):
        print(f"  vdi_wrapper_path={launch.get('wrapper_path') or ''}")
        print(f"  vdi_client_path={launch.get('client_path') or ''}")
        print(f"  launch_style={launch.get('launch_style') or ''}")
        print(f"  mode={launch.get('mode') or ''}")
        argv_disp = launch.get("argv") or launch.get("argv_display") or []
        print(f"  argv_display={argv_disp}")
        notes = launch.get("notes") or []
        if notes:
            for n in notes[:8]:
                print(f"  note={n}")
    rsa = plan.get("rsa") or {}
    if isinstance(rsa, dict):
        print(
            "  rsa="
            f"dry_run={rsa.get('dry_run')} "
            f"cipher_is_stub={rsa.get('cipher_is_stub')} "
            f"cipher_display={rsa.get('cipher_display')} "
            f"resolved_via={rsa.get('resolved_via')}"
        )
    notes = plan.get("notes") or []
    if isinstance(notes, list):
        for n in notes[:8]:
            print(f"  note={n}")


def cmd_spice_keepalive(args):
    """Path A: Local15900 + connect schema + VDI plan; dry by default.

    Live VDI requires --i-know-risks (and not --dry-run). Never prints token/password.
    """
    from l3.path_a_session import dry_run_pipeline, live_pipeline
    from l3.vdi_launcher import LiveLaunchDenied
    from l3.vendor_resolver import (
        UnknownVendor,
        VendorBinaryMissing,
        VendorNotImplemented,
    )

    # Default dry. Live only when --i-know-risks and user did not force --dry-run.
    force_dry = bool(getattr(args, "dry_run", False))
    want_live = bool(getattr(args, "i_know_risks", False)) and not force_dry
    # If neither flag: still dry (safe default per plan #11).
    dry = not want_live

    origin = (getattr(args, "origin_company_code", None) or getattr(args, "vendor", None) or "").strip()
    instance_id = (getattr(args, "instance_id", None) or "").strip()
    require_binaries = not bool(getattr(args, "skip_binary_check", False))
    start_port = int(getattr(args, "start_port", 15900) or 15900)
    desktop = None
    source = "cli-mock"

    if not origin:
        # Optional live desktop selection (token); still no secrets printed.
        cfg = load_config()
        if cfg.get("access_token"):
            import desktop_list

            client = build_client(cfg)
            try:
                desktops = desktop_list.get_desktop_list(client)
            except EcloudError as e:
                log.error("spice-keepalive: desktop list failed: %s", e)
                sys.exit(1)
            if not desktops:
                log.error("spice-keepalive: no desktops; pass --origin-company-code CMSSZTE")
                sys.exit(1)
            chosen = None
            if instance_id:
                for d in desktops:
                    if d.instance_id == instance_id:
                        chosen = d
                        break
                if chosen is None:
                    log.error("spice-keepalive: instance_id not found: %s", instance_id)
                    sys.exit(1)
            else:
                chosen = desktops[0]
            origin = (chosen.origin_company_code or "").strip() or "CMSSZTE"
            source = f"desktop:{chosen.machine_name or chosen.instance_id[:16]}"
            desktop = {
                "originCompanyCode": origin,
                "machineId": getattr(chosen, "machine_id", "") or "",
                "instanceId": chosen.instance_id,
                "machineName": getattr(chosen, "machine_name", "") or "",
            }
        else:
            origin = "CMSSZTE"
            source = "cli-default-CMSSZTE"
            log.info(
                "spice-keepalive: no token / no --origin-company-code; "
                "using mock origin CMSSZTE"
            )

    print(f"spice-keepalive: source={source}")

    # machineId required by connect_schema; CLI mock uses stable placeholder
    mid = ""
    if desktop:
        mid = str(
            desktop.get("machineId")
            or desktop.get("instanceId")
            or desktop.get("id")
            or ""
        )
    if not mid:
        mid = instance_id or "cli-mock-vmid"
        if desktop is None:
            desktop = {
                "originCompanyCode": origin,
                "machineId": mid,
            }
        else:
            desktop = dict(desktop)
            desktop.setdefault("machineId", mid)

    try:
        if dry:
            plan = dry_run_pipeline(
                origin,
                desktop=desktop,
                machine_id=mid,
                start_port=start_port,
                require_binaries=require_binaries,
            )
            _print_spice_keepalive_plan(plan, dry=True)
            return

        # LIVE path — gated by --i-know-risks
        log.warning(
            "spice-keepalive: LIVE path with --i-know-risks "
            "(VDI may Popen; ensure lib/Qt gates + exclusive session)"
        )
        plan = live_pipeline(
            origin,
            desktop=desktop,
            machine_id=mid,
            start_port=start_port,
            allow_live=True,
            require_binaries=require_binaries,
            stop_after=True,
        )
        _print_spice_keepalive_plan(plan, dry=False)
    except LiveLaunchDenied as e:
        log.error("spice-keepalive: LiveLaunchDenied: %s", e)
        sys.exit(3)
    except (UnknownVendor, VendorNotImplemented, VendorBinaryMissing) as e:
        log.error("spice-keepalive failed: %s: %s", type(e).__name__, e)
        sys.exit(2)
    except Exception as e:
        log.error("spice-keepalive failed: %s: %s", type(e).__name__, e)
        sys.exit(1)


def cmd_longtest_sim(args):
    """Longtest gate runner skeleton: sim/dry only; never live VDI or login."""
    from l3.longtest_runner import main as longtest_main

    argv = ["--mode", args.mode, "--tier", args.tier, "--scenario", args.scenario]
    if args.nest_root:
        argv.extend(["--nest-root", args.nest_root])
    if args.no_write:
        argv.append("--no-write")
    raise SystemExit(longtest_main(argv))


def cmd_path_a_probe(args):
    """Path A dry-run: resolve originCompanyCode → VendorProfile; never launch VDI."""
    from l3.vendor_resolver import (
        UnknownVendor,
        VendorBinaryMissing,
        VendorNotImplemented,
        resolve,
        resolve_desktop,
    )

    require_binaries = not args.skip_binary_check
    origin = (args.origin_company_code or "").strip()
    source = "cli-mock"

    if origin:
        try:
            profile = resolve(origin, require_binaries=require_binaries)
        except (UnknownVendor, VendorNotImplemented, VendorBinaryMissing) as e:
            log.error("path-a-probe failed: %s: %s", type(e).__name__, e)
            sys.exit(2)
        _print_vendor_profile(profile, origin=origin, source=source)
        return

    # Live desktop list path (token required). Never print password/token.
    cfg = load_config()
    if not cfg.get("access_token"):
        log.error(
            "path-a-probe: no access_token and no --origin-company-code; "
            "login first or pass mock origin"
        )
        sys.exit(1)

    import desktop_list

    client = build_client(cfg)
    try:
        desktops = desktop_list.get_desktop_list(client)
    except EcloudError as e:
        log.error("path-a-probe: desktop list failed: %s", e)
        sys.exit(1)

    if not desktops:
        log.error("path-a-probe: no desktops found")
        sys.exit(1)

    chosen = None
    if args.instance_id:
        for d in desktops:
            if d.instance_id == args.instance_id:
                chosen = d
                break
        if chosen is None:
            log.error("path-a-probe: instance_id not found: %s", args.instance_id)
            sys.exit(1)
    else:
        chosen = desktops[0]

    origin = chosen.origin_company_code or ""
    source = f"desktop:{chosen.machine_name or chosen.instance_id[:16]}"
    try:
        profile = resolve_desktop(chosen, require_binaries=require_binaries)
    except (UnknownVendor, VendorNotImplemented, VendorBinaryMissing) as e:
        log.error(
            "path-a-probe failed for origin=%r: %s: %s",
            origin,
            type(e).__name__,
            e,
        )
        sys.exit(2)

    _print_vendor_profile(profile, origin=origin, source=source)



def _add_shared_path_b_loop_args(ap, *, out_dir_default: str, with_account_ping: bool = True):
    """#75fixal: shared path_B loop flags for keepalive / desktop-keepalive (claim=false)."""
    ap.add_argument("--interval", type=int, default=300,
                    help="interval seconds (default 300)")
    ap.add_argument("--rounds", type=int, default=None,
                    help="max rounds (default unlimited; 312≈26h @300s)")
    from l3.platform_paths import DEFAULT_PLAIN, DEFAULT_POST, DEFAULT_PRE

    ap.add_argument(
        "--host",
        default="",
        help=(
            "CAG host override (empty=resolve from cloud_pc / env / "
            "regional cagList; stock GZ4 only as last resort)"
        ),
    )
    ap.add_argument("--plain", default=DEFAULT_PLAIN,
                    help="connectStr plain path (contents never logged; "
                         "default: OS temp/ecloud-pathb or SHORT_CONNECT_PLAIN_FILE)")
    ap.add_argument("--pre", default=DEFAULT_PRE, help="pre-TLS template dir")
    ap.add_argument("--post", default=DEFAULT_POST, help="post-TLS template dir")
    ap.add_argument("--heart-listen", type=float, default=60.0,
                    help="per-round HEART listen window seconds (default 60)")
    ap.add_argument("--ticket-mode", default="zeros",
                    help="ticket mode (default zeros; claim=false)")
    ap.add_argument("--session-nudge", action="store_true", default=None,
                    help="enable session nudge (optional)")
    ap.add_argument("--agent-hb-every", type=float, default=0.0,
                    help="agent hb every N seconds (default 0=off)")
    ap.add_argument("--out-dir", default=out_dir_default,
                    help="jsonl/meta output dir")
    if with_account_ping:
        ap.add_argument("--no-account-ping", action="store_true",
                        help="skip L1 account HTTP ping each round")
    ap.add_argument("--stop-on-fatal", action="store_true",
                    help="stop loop on hard SPICE fail (default continue)")
    ap.add_argument(
        "--no-auto-remint", action="store_true",
        help="disable auto remint on auth220/handshake fail (default: remint once+retry)",
    )
    ap.add_argument(
        "--remint-timeout", type=float, default=20.0,
        help="connectStr mint timeout seconds when auto-remint (default 20)",
    )


def main():
    p = argparse.ArgumentParser(
        description="Ecloud Cloud Computer V3.8.2 keepalive tool",
    )
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="verbose (-vv for debug)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("login", help="interactive login, save config")
    ka = sub.add_parser(
        "keepalive",
        help=(
            "SPICE path_B HEART + status/uptime oracle "
            "(default; claim=false). --legacy-http for old L1 HTTP only"
        ),
    )
    ka.add_argument(
        "--legacy-http", action="store_true",
        help="opt-in: old L1 account HTTP keepalive only (NOT desktop/SPICE)",
    )
    ka.add_argument("--instance-id", help="desktop instance ID (CCA-xxxx); omit to auto-select")
    ka.add_argument("--machine-id", help="desktop machine ID (UUID), optional")
    ka.add_argument("--no-auto-select", action="store_true",
                    help="disable auto desktop selection (require --instance-id)")
    _add_shared_path_b_loop_args(ka, out_dir_default="reports/r26_live/spice_oracle_soak")
    ka.add_argument(
        "--plain-ttl", type=float, default=0.0,
        help="proactive remint when plain mtime age >= N seconds (0=off)",
    )
    ka.add_argument(
        "--no-mid-session-reconnect", action="store_true",
        help="disable mid-session path_B reconnect (auth ok / heart drop)",
    )

    # Path B SPICE HEART keepalive (claim=false; public_ecloud only)
    pbk = sub.add_parser(
        "path-b-keepalive",
        help=(
            "Path B SPICE HEART keepalive loop (claim=false; "
            "default interval=300s, heart-listen=60s)"
        ),
    )
    pbk.add_argument(
        "--interval", type=int, default=300,
        help="seconds between full connect rounds (default 300)",
    )
    pbk.add_argument(
        "--rounds", type=int, default=None,
        help="max rounds (default unlimited; 312≈26h @300s)",
    )
    pbk.add_argument(
        "--heart-listen", type=float, default=60.0,
        help="per-round HEART listen window seconds (default 60)",
    )
    pbk.add_argument(
        "--host",
        default="",
        help=(
            "CAG host override (empty=resolve from cloud_pc / env / "
            "regional cagList; stock GZ4 only as last resort)"
        ),
    )
    from l3.platform_paths import DEFAULT_PLAIN, DEFAULT_POST, DEFAULT_PRE

    pbk.add_argument(
        "--plain", default=DEFAULT_PLAIN,
        help="path to connectStr plain file (not logged; "
             "default: OS temp/ecloud-pathb or SHORT_CONNECT_PLAIN_FILE)",
    )
    pbk.add_argument("--pre", default=DEFAULT_PRE, help="pre-TLS template dir")
    pbk.add_argument("--post", default=DEFAULT_POST, help="post-TLS template dir")
    pbk.add_argument(
        "--ticket-mode", default="zeros",
        help="ticket mode (default zeros; claim=false)",
    )
    pbk.add_argument(
        "--session-nudge", action="store_true",
        help="force session nudge on",
    )
    pbk.add_argument(
        "--no-session-nudge", action="store_true",
        help="force session nudge off",
    )
    pbk.add_argument(
        "--agent-hb-every", type=float, default=0.0,
        help="agent heartbeat every N seconds (0=off; dual still false)",
    )
    pbk.add_argument(
        "--out-dir", default="reports/r26_live/path_b_soak",
        help="soak report directory",
    )
    pbk.add_argument(
        "--stop-on-fatal", action="store_true",
        help="stop loop on hard fail (default continue)",
    )
    pbk.add_argument(
        "--no-auto-remint", action="store_true",
        help="disable auto remint on auth220/handshake fail (default: remint once+retry)",
    )
    pbk.add_argument(
        "--remint-timeout", type=float, default=20.0,
        help="connectStr mint timeout seconds when auto-remint (default 20)",
    )

    # 桌面会话保活：默认 SPICE+oracle；--legacy-http 才走纯 desktopUptime
    dka = sub.add_parser(
        "desktop-keepalive",
        help=(
            "SPICE path_B HEART + status/uptime oracle "
            "(default; claim=false). --legacy-http for pure desktopUptime"
        ),
    )
    dka.add_argument("--instance-id", help="desktop instance ID (CCA-xxxx); omit to auto-select")
    dka.add_argument("--machine-id", help="desktop machine ID (UUID), optional")
    dka.add_argument("--ticket", help="session ticket (ticket:xxxx), optional; legacy-http only")
    dka.add_argument("--no-auto-select", action="store_true",
                     help="disable auto desktop selection (require --instance-id)")
    dka.add_argument(
        "--legacy-http", action="store_true",
        help="opt-in: force pure desktopUptime HTTP (bypass vendor routing)",
    )
    dka.add_argument(
        "--force-path-b", action="store_true",
        help="#75fixaj: force SPICE path_B regardless of originCompanyCode",
    )
    dka.add_argument(
        "--no-power", action="store_true",
        help="#75fixaj: skip ensure_powered_once preflight (default: power first)",
    )
    dka.add_argument(
        "--power-wait", type=float, default=None,
        help="#75fixaj: wait seconds after operate=available "
        "(default CLOUD_PC_POWER_WAIT or 60)",
    )
    _add_shared_path_b_loop_args(dka, out_dir_default="reports/r26_live/spice_oracle_soak")

    sub.add_parser("list-desktops", help="try to fetch desktop list")
    sd = sub.add_parser(
        "select-desktop",
        help="交互选择云电脑并写入配置（一账号多桌面时用）",
    )
    sd.add_argument(
        "--index",
        type=int,
        default=None,
        help="非交互：直接选列表序号（0 起）",
    )
    sd.add_argument(
        "--instance-id",
        default=None,
        help="非交互：按 instanceId 选定",
    )
    sub.add_parser("status", help="check token validity")
    sub.add_parser("logout", help="logout and clear config")

    # Path A dry-run probe (no VDI launch)
    pap = sub.add_parser(
        "path-a-probe",
        help="Path A dry-run: resolve vendor profile (no VDI launch)",
    )
    pap.add_argument(
        "--origin-company-code",
        help="mock originCompanyCode (skip desktop API; e.g. CMSSZTE)",
    )
    pap.add_argument(
        "--instance-id",
        help="when loading live desktops, pick this instanceId",
    )
    pap.add_argument(
        "--skip-binary-check",
        action="store_true",
        help="skip on-disk VDI binary existence/exec checks",
    )

    # Path A spice-keepalive: Local15900 + schema + VDI plan (dry default)
    sk = sub.add_parser(
        "spice-keepalive",
        help=(
            "Path A: Local15900 + connect schema + VDI plan; "
            "dry-run by default (no VDI Popen)"
        ),
    )
    sk.add_argument(
        "--origin-company-code",
        "--vendor",
        dest="origin_company_code",
        help="originCompanyCode (default CMSSZTE if no token)",
    )
    sk.add_argument(
        "--instance-id",
        help="when loading live desktops, pick this instanceId",
    )
    sk.add_argument(
        "--dry-run",
        action="store_true",
        help="force dry-run (default; never launch VDI)",
    )
    sk.add_argument(
        "--i-know-risks",
        action="store_true",
        dest="i_know_risks",
        help="allow live VDI Popen (requires not --dry-run)",
    )
    sk.add_argument(
        "--skip-binary-check",
        action="store_true",
        help="skip checking that VDI wrapper/client binaries exist",
    )
    sk.add_argument(
        "--start-port",
        type=int,
        default=15900,
        help="Local15900 start port (default 15900)",
    )

    # Longtest sim/dry skeleton (no live VDI)
    lt = sub.add_parser(
        "longtest-sim",
        help="longtest gate runner skeleton (sim/dry; no live VDI)",
    )
    lt.add_argument("--mode", choices=("sim", "dry"), default="sim")
    lt.add_argument(
        "--tier",
        choices=("S0", "S1", "S2", "S3"),
        default="S1",
        help="duration tier from longtest_gate.md",
    )
    lt.add_argument(
        "--scenario",
        choices=("l3_pass", "l3_weak", "l3_fail_biz", "l3_fail_proto", "l2_only"),
        default="l3_pass",
        help="synthetic scenario for sim mode",
    )
    lt.add_argument(
        "--nest-root",
        default=".",
        help="nest root for reports/longtest outputs",
    )
    lt.add_argument(
        "--no-write",
        action="store_true",
        help="score only; skip writing reports/longtest files",
    )

    # Product setup (public ecloud Path B; no client/CDP; claim=false)
    su = sub.add_parser(
        "setup",
        help=(
            "product setup: gateway → list → power_once(operate=available) "
            "→ mint → optional path_B 1r (claim=false; no CDP)"
        ),
    )
    su.add_argument("--selfcheck", action="store_true", help="offline module selfcheck only")
    su.add_argument("--dry-run", action="store_true", help="resolve/list only; skip power/mint/path_B IO")
    su.add_argument("--no-power", action="store_true", help="skip ensure_powered_once")
    su.add_argument("--force-power", action="store_true", help="ignore power_on_done flag and re-call operate")
    su.add_argument("--no-mint", action="store_true", help="skip connectStr mint")
    su.add_argument(
        "--no-mint-power-retry",
        action="store_true",
        help="disable mint 501/no_connectStr → force power + remint once (default: enabled)",
    )
    su.add_argument("--with-path-b", action="store_true", help="run path_B 1-round after mint")
    su.add_argument("--path-b-rounds", type=int, default=1, help="path_B rounds when --with-path-b (default 1)")
    su.add_argument("--heart-listen", type=float, default=30.0, help="path_B HEART window s (default 30)")
    su.add_argument("--plain", help="connectStr plain path (never logged; default ~/.cache/ecloud-pathb/...)")
    su.add_argument("--host", "--cag-host", dest="cag_host", help="CAG host override")
    su.add_argument("--cag-port", type=int, help="CAG port override (default 8899)")
    su.add_argument("--csapip", help="csapip host:port override")
    su.add_argument("--instance-id", help="desktop instance ID; omit to auto-select")
    su.add_argument("--machine-id", help="desktop machine ID; omit to auto-select")
    su.add_argument("--mint-timeout", type=float, default=25.0, help="mint timeout seconds")
    su.add_argument(
        "--power-wait",
        type=float,
        default=None,
        help="seconds to wait after operate=available (default 15; env CLOUD_PC_POWER_WAIT)",
    )

    # Web UI
    wp = sub.add_parser("web", help="start Web UI (Flask)")
    wp.add_argument("--host", default="0.0.0.0", help="bind host (default 0.0.0.0)")
    wp.add_argument("--port", type=int, default=8081, help="port (default 8081; same as Docker)")

    args = p.parse_args()
    level = logging.DEBUG if args.verbose >= 2 else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        {"login": cmd_login, "keepalive": cmd_keepalive,
         "path-b-keepalive": cmd_path_b_keepalive,
         "desktop-keepalive": cmd_desktop_keepalive,
         "list-desktops": cmd_list_desktops,
         "select-desktop": cmd_select_desktop,
         "path-a-probe": cmd_path_a_probe,
         "spice-keepalive": cmd_spice_keepalive,
         "longtest-sim": cmd_longtest_sim,
         "setup": cmd_setup,
         "status": cmd_status, "logout": cmd_logout,
         "web": cmd_web}[args.cmd](args)
    except KeyboardInterrupt:
        log.info("interrupted")
    except EcloudError as e:
        log.error("api error: %s", e)
        sys.exit(1)
    except Exception:
        log.error("unexpected error:\n%s", traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
