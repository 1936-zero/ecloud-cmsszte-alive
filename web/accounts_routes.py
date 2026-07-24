"""Multi-account card API routes (Path B per-account).

Extracted from create_app (#75fixan P1-4) — behavior unchanged.
"""
from __future__ import annotations

import logging

from flask import Flask, jsonify, request

from web.account_runtime import get_registry


def register_account_routes(app: Flask) -> None:
    """Register /api/accounts* and /api/global-logs* on app."""

    # -----------------------------------------------------------------------
    # Multi-account cards (Path B per-account; sole desktop-keepalive API surface)
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
        try:
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

        except Exception as e:
            # #75fixal: account login must return JSON 200 with failed, never 500
            logging.getLogger(__name__).exception("api_accounts_login %s: %s", account_id, e)
            return jsonify({"status": "failed", "error": f"登录异常: {type(e).__name__}: {e}", "ok": False})

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
        """Clear per-account backend log ring (backend real clear)."""
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

