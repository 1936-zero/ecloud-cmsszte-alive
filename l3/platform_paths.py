"""Cross-platform temp + installinfo + Path B default path helpers.

Win/Mac/Linux: never assume POSIX /tmp or only Linux CMSS install tree.
Path B mint needs PublicKey.csap_id (16-char product AES key). Default Docker
stub ships the known client csap_id; empty mounts are skipped by get_csap_key.

#75 / issue#1: CLI used to hardcode ``/tmp/r26_t29_plain`` which becomes
``\\tmp\\r26_t29_plain`` on Windows and fails FileNotFound. Prefer
``tempfile.gettempdir()/ecloud-pathb/...`` and ship ``assets/templates``.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Nest capture fallback if assets missing (dev trees)
_NEST_PRE = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/pre"
_NEST_POST = _REPO_ROOT / "reports/r26_live/capture/t14_frame_templates_restored/post"


def tmp_dir() -> Path:
    """OS temp root (Windows %TEMP%, macOS/Linux /tmp or $TMPDIR)."""
    return Path(tempfile.gettempdir())


def ecloud_tmp(*parts: str) -> Path:
    """``{temp}/ecloud-pathb/...`` — writable on Win/Mac/Linux + Docker HOME=/tmp."""
    return tmp_dir().joinpath("ecloud-pathb", *parts)


def resolve_default_plain() -> str:
    """Prefer env → existing files → first writable candidate (Win/Mac/Docker-safe).

    Env: SHORT_CONNECT_PLAIN_FILE, PLAIN, ECLOUD_PLAIN.
    Never returns a bare POSIX ``/tmp/r26_t29_plain`` on Windows.
    """
    for env_key in ("SHORT_CONNECT_PLAIN_FILE", "PLAIN", "ECLOUD_PLAIN"):
        v = (os.environ.get(env_key) or "").strip()
        if v:
            return v

    candidates = [
        ecloud_tmp("connectstr.plain"),
        tmp_dir() / "r26_t29_plain",  # legacy name under real OS temp
        _REPO_ROOT / "data" / "connectstr.plain",
        Path.home() / ".cache" / "ecloud-pathb" / "connectstr.plain",
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
    return str(ecloud_tmp("connectstr.plain"))


def resolve_template_dirs() -> tuple[str, str]:
    """pre/post TLS frame template dirs: assets first, then nest capture, then OS temp."""
    pre = _REPO_ROOT / "assets" / "templates" / "pre"
    post = _REPO_ROOT / "assets" / "templates" / "post"
    if pre.is_dir() and post.is_dir():
        return str(pre), str(post)
    if _NEST_PRE.is_dir() and _NEST_POST.is_dir():
        return str(_NEST_PRE), str(_NEST_POST)
    # last resort: OS temp (legacy layout; may be empty until restore-templates)
    return str(tmp_dir() / "t14_100"), str(tmp_dir() / "t14_tls_plain")


def default_plain() -> str:
    """Alias for resolve_default_plain (stable name for importers)."""
    return resolve_default_plain()


def default_pre() -> str:
    return resolve_template_dirs()[0]


def default_post() -> str:
    return resolve_template_dirs()[1]


# Module-level defaults evaluated at import (paths are OS-local strings).
DEFAULT_PLAIN = resolve_default_plain()
DEFAULT_PRE, DEFAULT_POST = resolve_template_dirs()


def installinfo_candidates() -> list[Path]:
    """Ordered search list for CMSS ``installinfo.ini`` (PublicKey.csap_id)."""
    out: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path | str | None) -> None:
        if p is None:
            return
        path = Path(p)
        key = str(path)
        if key in seen:
            return
        seen.add(key)
        out.append(path)

    for env_key in ("INSTALLINFO_PATH", "INSTALLINFO_HOST", "ECLOUD_INSTALLINFO"):
        v = (os.environ.get(env_key) or "").strip()
        if v:
            _add(v)

    # Linux official client (Path B capable)
    _add("/opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/CMSS/config/installinfo.ini")
    _add("/opt/apps/com.cmss.saas.ecloudcomputer/files/drivers/ZTE/config/installinfo.ini")

    # Windows: common Program Files / LocalAppData layouts (best-effort)
    for base_env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = (os.environ.get(base_env) or "").strip()
        if not base:
            continue
        b = Path(base)
        for rel in (
            Path("CMSS") / "ecloudcomputer" / "drivers" / "CMSS" / "config" / "installinfo.ini",
            Path("com.cmss.saas.ecloudcomputer") / "files" / "drivers" / "CMSS" / "config" / "installinfo.ini",
            Path("ecloudcomputer") / "drivers" / "CMSS" / "config" / "installinfo.ini",
            Path("CMSS") / "config" / "installinfo.ini",
        ):
            _add(b / rel)

    # macOS Application Support (best-effort)
    mac_as = Path.home() / "Library" / "Application Support"
    for rel in (
        Path("com.cmss.saas.ecloudcomputer") / "files" / "drivers" / "CMSS" / "config" / "installinfo.ini",
        Path("ecloudcomputer") / "drivers" / "CMSS" / "config" / "installinfo.ini",
        Path("CMSS") / "config" / "installinfo.ini",
    ):
        _add(mac_as / rel)

    # Docker volume + repo data / portable stub (product csap_id; empty files skipped by get_csap_key)
    _add("/app/data/config/installinfo.ini")
    _add(_REPO_ROOT / "data" / "config" / "installinfo.ini")
    _add(_REPO_ROOT / "docker" / "stubs" / "installinfo.ini")

    return out
