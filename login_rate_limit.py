"""WebUI interactive login rate limit (NOT for CLI).

Rule: within a sliding WINDOW_SEC, a username may attempt WebUI password
login (quiet=False) at most MAX_ATTEMPTS times. Excess attempts return
locked until the oldest attempt ages out of the window.

Scope (#75fixam-fix):
  - Applies: WebUI 卡片登录 / 交互重登 (AccountRuntime.login quiet=False)
  - Does NOT apply: CLI `python main.py login` (manual ops, no auto-burst)
  - Does NOT apply: quiet keepalive relogin (Path B / AKA token refresh)

Persisted under data/ so Docker volume shares state across restarts.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

WINDOW_SEC = 600  # 10 minutes
MAX_ATTEMPTS = 3

_PROJECT_ROOT = Path(__file__).resolve().parent
_DEFAULT_PATH = Path(
    os.environ.get(
        "ECLOUD_LOGIN_RATE_LIMIT_FILE",
        str(_PROJECT_ROOT / "data" / "login_rate_limit.json"),
    )
)

_lock = threading.RLock()
_state: dict[str, list[float]] = {}
_loaded_path: Path | None = None


def _path() -> Path:
    return Path(
        os.environ.get(
            "ECLOUD_LOGIN_RATE_LIMIT_FILE",
            str(_DEFAULT_PATH),
        )
    )


def _now() -> float:
    return time.time()


def _prune(ts_list: list[float], now: float | None = None) -> list[float]:
    now = now if now is not None else _now()
    cutoff = now - WINDOW_SEC
    return [t for t in ts_list if t > cutoff]


def _load_unlocked(path: Path) -> None:
    global _state, _loaded_path
    _state = {}
    _loaded_path = path
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        return
    now = _now()
    for user, items in accounts.items():
        if not isinstance(user, str) or not user:
            continue
        ts_list: list[float] = []
        if isinstance(items, list):
            for x in items:
                try:
                    ts_list.append(float(x))
                except (TypeError, ValueError):
                    continue
        _state[user] = _prune(ts_list, now)


def _save_unlocked(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = _now()
    accounts = {
        u: _prune(ts, now)
        for u, ts in _state.items()
        if _prune(ts, now)
    }
    payload = {
        "window_sec": WINDOW_SEC,
        "max_attempts": MAX_ATTEMPTS,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "accounts": accounts,
    }
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _ensure_loaded() -> Path:
    path = _path()
    global _loaded_path
    if _loaded_path is None or _loaded_path != path:
        _load_unlocked(path)
    return path


def normalize_username(username: str) -> str:
    return (username or "").strip()


def status(username: str) -> dict[str, Any]:
    """Read-only status for a username."""
    user = normalize_username(username)
    with _lock:
        _ensure_loaded()
        now = _now()
        ts = _prune(list(_state.get(user, [])), now)
        count = len(ts)
        locked = count >= MAX_ATTEMPTS
        unlock_in = 0
        if locked and ts:
            unlock_in = max(0, int(ts[0] + WINDOW_SEC - now) + 1)
        return {
            "username": user,
            "count": count,
            "max_attempts": MAX_ATTEMPTS,
            "window_sec": WINDOW_SEC,
            "locked": locked,
            "unlock_in_sec": unlock_in,
            "remaining_attempts": max(0, MAX_ATTEMPTS - count),
        }


def check_locked(username: str) -> dict[str, Any] | None:
    """If locked, return error payload; else None."""
    st = status(username)
    if not st["locked"]:
        return None
    sec = st["unlock_in_sec"]
    mins = max(1, (sec + 59) // 60)
    return {
        "status": "locked",
        "ok": False,
        "error": (
            f"账号已锁定：10 分钟内重登不得超过 {MAX_ATTEMPTS} 次，"
            f"请约 {mins} 分钟后再试（剩余约 {sec}s）"
        ),
        "locked": True,
        "unlock_in_sec": sec,
        "max_attempts": MAX_ATTEMPTS,
        "window_sec": WINDOW_SEC,
    }


def record_attempt(username: str) -> dict[str, Any]:
    """Record one password-login attempt. Returns status after record.

    Call only when the attempt is allowed to proceed (not already locked).
    If already at max before record, does not add and returns locked status.
    """
    user = normalize_username(username)
    if not user:
        return status(user)
    with _lock:
        path = _ensure_loaded()
        now = _now()
        ts = _prune(list(_state.get(user, [])), now)
        if len(ts) >= MAX_ATTEMPTS:
            _state[user] = ts
            # refresh lock message fields
            unlock_in = max(0, int(ts[0] + WINDOW_SEC - now) + 1) if ts else 0
            return {
                "username": user,
                "count": len(ts),
                "max_attempts": MAX_ATTEMPTS,
                "window_sec": WINDOW_SEC,
                "locked": True,
                "unlock_in_sec": unlock_in,
                "remaining_attempts": 0,
            }
        ts.append(now)
        _state[user] = ts
        try:
            _save_unlocked(path)
        except Exception:
            pass
        count = len(ts)
        locked = count >= MAX_ATTEMPTS
        unlock_in = max(0, int(ts[0] + WINDOW_SEC - now) + 1) if locked else 0
        return {
            "username": user,
            "count": count,
            "max_attempts": MAX_ATTEMPTS,
            "window_sec": WINDOW_SEC,
            "locked": locked,
            "unlock_in_sec": unlock_in,
            "remaining_attempts": max(0, MAX_ATTEMPTS - count),
        }


def guard_login(username: str) -> dict[str, Any] | None:
    """Pre-login gate: if locked return error dict; else record attempt and return None.

    Usage:
        err = login_rate_limit.guard_login(user)
        if err:
            return err
        # proceed to real login
    """
    locked = check_locked(username)
    if locked:
        return locked
    st = record_attempt(username)
    if st.get("locked") and st.get("count", 0) > MAX_ATTEMPTS:
        # should not happen; defensive
        return check_locked(username)
    return None


def reset_for_tests(username: str | None = None) -> None:
    """Test helper: clear one user or all."""
    with _lock:
        path = _ensure_loaded()
        if username is None:
            _state.clear()
        else:
            _state.pop(normalize_username(username), None)
        try:
            _save_unlocked(path)
        except Exception:
            pass
