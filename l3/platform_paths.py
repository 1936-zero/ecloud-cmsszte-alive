"""Cross-platform temp + installinfo path helpers (#75fixap / #75fixaq).

Win/Mac/Linux: never assume POSIX /tmp or only Linux CMSS install tree.
Path B mint needs PublicKey.csap_id (16-char product AES key). Default Docker
stub ships the known client csap_id; empty mounts are skipped by get_csap_key.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def tmp_dir() -> Path:
    """OS temp root (Windows %TEMP%, macOS/Linux /tmp or $TMPDIR)."""
    return Path(tempfile.gettempdir())


def ecloud_tmp(*parts: str) -> Path:
    """``{temp}/ecloud-pathb/...`` — writable on Win/Mac/Linux + Docker HOME=/tmp."""
    return tmp_dir().joinpath("ecloud-pathb", *parts)


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
