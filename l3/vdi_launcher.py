"""VDI launcher: CMSS argv assembly + dry-run (no live Popen by default).

Path A primary: origin CMSSZTE → VendorProfile CMSS wrapper/client paths.
Default never Popen; live_start requires allow_live=True.
No secrets in plan strings; cipher is REDACTED in dry output.

Shell-wrapper policy (P17): CMSS uSmartView_VDI_exe is an ASCII shell script
without a shebang. Direct execve → ENOEXEC. build_argv therefore prefixes
/bin/sh or /bin/bash when the wrapper is not an ELF binary so live Popen can
actually start the client via the vendor wrapper (usbredirect + Client $*).

Launch styles (P18-B):
- shell_wrapper (default): [shell, wrapper, flag, cipher] — preserves P17.
- direct_client: [client ELF, flag, cipher] + cwd=…/CMSS/bin +
  LD_LIBRARY_PATH=…/CMSS/lib (P17-C §4/§5). Skips wrapper/sudo.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .vendor_resolver import (
    VendorError,
    VendorNotImplemented,
    VendorProfile,
    resolve,
)

# argv mode flags (CMSS / Linux; path_a_15900_responder_skeleton §5.2)
MODE_JSON = "json"
MODE_DETECT = "detect"
_MODE_FLAGS = {
    MODE_JSON: "--json",
    MODE_DETECT: "--detect",
}

# Launch style: how argv0 is chosen (P18-B).
LAUNCH_SHELL_WRAPPER = "shell_wrapper"
LAUNCH_DIRECT_CLIENT = "direct_client"
_LAUNCH_STYLES = (LAUNCH_SHELL_WRAPPER, LAUNCH_DIRECT_CLIENT)

# display redaction
REDACTED = "<REDACTED_CIPHER>"
_REDACT_PREVIEW = 8  # keep short head/tail only when len large; still not full cipher

# Preferred shells for non-ELF vendor wrappers (no shebang → ENOEXEC on execve).
_SHELL_CANDIDATES = ("/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash")
_ELF_MAGIC = b"\x7fELF"


class VdiLauncherError(Exception):
    """Base launcher error."""


class LiveLaunchDenied(VdiLauncherError):
    """live_start called without allow_live=True."""


class InvalidArgvMode(VdiLauncherError):
    """Unknown argv mode (not json|detect)."""


class EmptyCipher(VdiLauncherError):
    """cipher must be non-empty string for argv assembly."""


class InvalidLaunchStyle(VdiLauncherError):
    """Unknown launch_style (not shell_wrapper|direct_client)."""


def _normalize_mode(mode: str) -> str:
    m = (mode or MODE_JSON).strip().lower()
    # allow --json / --detect aliases
    if m.startswith("--"):
        m = m[2:]
    if m not in _MODE_FLAGS:
        raise InvalidArgvMode(f"mode must be json|detect, got {mode!r}")
    return m


def is_shell_wrapper(path: str) -> bool:
    """Return True when path is not an ELF and looks like a text shell script.

    Missing/unreadable paths are treated as shell wrappers so live policy still
    prefixes a shell (exec of missing ELF would fail differently; ENOEXEC is
    the P16 residual we fix for the known CMSS ASCII wrapper).
    """
    if not path:
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        # Unreadable: still prefer shell prefix if path ends like a script name
        # or has no extension that screams ELF. Conservative: True for non-empty.
        return True
    if not head:
        return True
    if head.startswith(_ELF_MAGIC):
        return False
    # Shebang shell / text script
    if head.startswith(b"#!"):
        return True
    # No shebang but ASCII/text (CMSS uSmartView_VDI_exe case)
    # Reject if mostly binary (NUL or high non-text ratio)
    sample = head[:128]
    if b"\x00" in sample:
        return False
    textish = sum(1 for c in sample if 9 <= c <= 13 or 32 <= c <= 126)
    return textish >= max(1, int(0.85 * len(sample)))


def pick_shell(candidates: Sequence[str] = _SHELL_CANDIDATES) -> str:
    """First existing executable shell from candidates; default /bin/sh."""
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "/bin/sh"


def _cipher_index(argv: Sequence[str]) -> int:
    """Locate cipher slot: last arg after --json/--detect, else legacy index 2."""
    for i, a in enumerate(argv):
        if a in ("--json", "--detect") and i + 1 < len(argv):
            return i + 1
    # fallback: last element if len>=3 else 2
    if len(argv) >= 3:
        return len(argv) - 1
    return 2


def _normalize_launch_style(style: Optional[str]) -> str:
    s = (style or LAUNCH_SHELL_WRAPPER).strip().lower().replace("-", "_")
    # accept common aliases
    aliases = {
        "shell": LAUNCH_SHELL_WRAPPER,
        "wrapper": LAUNCH_SHELL_WRAPPER,
        "shell_wrapper": LAUNCH_SHELL_WRAPPER,
        "direct": LAUNCH_DIRECT_CLIENT,
        "client": LAUNCH_DIRECT_CLIENT,
        "direct_client": LAUNCH_DIRECT_CLIENT,
    }
    out = aliases.get(s, s)
    if out not in _LAUNCH_STYLES:
        raise InvalidLaunchStyle(
            f"unknown launch_style {style!r}; expected one of {_LAUNCH_STYLES}"
        )
    return out


def cmss_bin_dir(profile: VendorProfile) -> str:
    """…/CMSS/bin from client or wrapper path (P17-C cwd contract)."""
    for p in (profile.vdi_client_path, profile.vdi_wrapper_path):
        if p:
            d = os.path.dirname(os.path.abspath(p))
            if d:
                return d
    raise VdiLauncherError(
        f"cannot derive CMSS bin dir for vendor {profile.vendor_id}"
    )


def cmss_lib_dir(profile: VendorProfile) -> str:
    """…/CMSS/lib sibling of bin (P17-C LD_LIBRARY_PATH)."""
    return os.path.normpath(os.path.join(cmss_bin_dir(profile), "..", "lib"))


def plan_cwd(profile: VendorProfile, launch_style: str = LAUNCH_SHELL_WRAPPER) -> Optional[str]:
    """Recommended process cwd for the launch style.

    shell_wrapper: None (wrapper `cd`s to bin itself).
    direct_client: absolute …/CMSS/bin.
    """
    style = _normalize_launch_style(launch_style)
    if style == LAUNCH_DIRECT_CLIENT:
        return cmss_bin_dir(profile)
    return None


def plan_env(
    profile: VendorProfile,
    launch_style: str = LAUNCH_SHELL_WRAPPER,
    *,
    base: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Env delta (not full os.environ) for the launch style.

    direct_client sets LD_LIBRARY_PATH=…/CMSS/lib (prepend if base has it).
    shell_wrapper returns {} (optional hardening left to caller).
    """
    style = _normalize_launch_style(launch_style)
    out: Dict[str, str] = {}
    if style == LAUNCH_DIRECT_CLIENT:
        lib = cmss_lib_dir(profile)
        if base and base.get("LD_LIBRARY_PATH"):
            prev = base["LD_LIBRARY_PATH"]
            # avoid duplicate prepend
            parts = [p for p in prev.split(":") if p]
            if lib not in parts:
                out["LD_LIBRARY_PATH"] = lib + ":" + prev
            else:
                out["LD_LIBRARY_PATH"] = prev
        else:
            out["LD_LIBRARY_PATH"] = lib
    return out


def build_argv(
    profile: VendorProfile,
    cipher: str,
    mode: str = MODE_JSON,
    *,
    launch_style: str = LAUNCH_SHELL_WRAPPER,
) -> List[str]:
    """Build CMSS-style argv for Path A.

    launch_style=shell_wrapper (default, P17):
      ELF wrapper: [wrapper, --json|--detect, rsaCipher]
      Shell wrapper (or non-ELF text): [/bin/sh|/bin/bash, wrapper, flag, cipher]
      so live execve avoids ENOEXEC on the vendor ASCII wrapper without shebang.

    launch_style=direct_client (P18-B / P17-C §B):
      [vdi_client_path ELF, flag, cipher] — no shell, no wrapper, no sudo.

    Exec arg is the RSA cipher string itself (not a {params:...} shell).
    Does not inspect or write secrets to disk.
    """
    if not isinstance(profile, VendorProfile):
        raise TypeError("profile must be VendorProfile")
    if not profile.supports_path_a:
        raise VendorNotImplemented(
            f"vendor {profile.vendor_id} does not support Path A VDI launch"
        )
    style = _normalize_launch_style(launch_style)
    if cipher is None or not str(cipher):
        raise EmptyCipher("cipher must be non-empty string")
    flag = _MODE_FLAGS[_normalize_mode(mode)]

    if style == LAUNCH_DIRECT_CLIENT:
        client = (profile.vdi_client_path or "").strip()
        if not client:
            raise VdiLauncherError(
                f"empty vdi_client_path for {profile.vendor_id} (direct_client)"
            )
        if client.startswith("/opt/ZTE"):
            raise VdiLauncherError(
                "refusing /opt/ZTE client as Path A default (use CMSS profile)"
            )
        # Prefer ELF; if path missing in dry tests, still assemble shape.
        if os.path.isfile(client) and is_shell_wrapper(client):
            raise VdiLauncherError(
                f"direct_client requires ELF client, got shell/text: {client}"
            )
        return [client, flag, str(cipher)]

    # --- shell_wrapper (default) ---
    wrapper = (profile.vdi_wrapper_path or "").strip()
    if not wrapper:
        raise VdiLauncherError(f"empty vdi_wrapper_path for {profile.vendor_id}")
    # hard redline: never default argv0/wrapper to /opt/ZTE
    if wrapper.startswith("/opt/ZTE"):
        raise VdiLauncherError(
            "refusing /opt/ZTE wrapper as Path A default (use CMSS profile)"
        )
    core = [wrapper, flag, str(cipher)]
    if is_shell_wrapper(wrapper):
        shell = pick_shell()
        if shell.startswith("/opt/ZTE"):
            raise VdiLauncherError("refusing /opt/ZTE shell for Path A")
        return [shell, wrapper, flag, str(cipher)]
    return core


def redact_cipher(cipher: Optional[str], *, preview: int = 0) -> str:
    """Never print full cipher in dry-run plans."""
    if cipher is None or cipher == "":
        return REDACTED
    if preview <= 0:
        return REDACTED
    s = str(cipher)
    if len(s) <= preview * 2:
        return REDACTED
    return f"{s[:preview]}…{s[-preview:]}({len(s)}B)"


def argv_for_display(
    argv: Sequence[str],
    *,
    cipher_index: Optional[int] = None,
) -> List[str]:
    """Copy argv with cipher slot redacted (auto-detect after --json/--detect)."""
    out = list(argv)
    idx = _cipher_index(out) if cipher_index is None else cipher_index
    if 0 <= idx < len(out):
        out[idx] = REDACTED
    return out


@dataclass
class LaunchPlan:
    """Dry-run plan: paths + argv shape; no live process."""

    origin: str
    vendor_id: str
    service_name: str
    supports_path_a: bool
    wrapper_path: str
    client_path: str
    mode: str
    argv: List[str]
    argv_display: List[str]
    cipher_meta: Dict[str, Any] = field(default_factory=dict)
    dry_run: bool = True
    notes: List[str] = field(default_factory=list)
    launch_style: str = LAUNCH_SHELL_WRAPPER
    cwd: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "vendor_id": self.vendor_id,
            "service_name": self.service_name,
            "supports_path_a": self.supports_path_a,
            "wrapper_path": self.wrapper_path,
            "client_path": self.client_path,
            "mode": self.mode,
            "launch_style": self.launch_style,
            "cwd": self.cwd,
            "env": dict(self.env),
            "argv": list(self.argv_display),  # never full cipher
            "cipher_meta": dict(self.cipher_meta),
            "dry_run": self.dry_run,
            "notes": list(self.notes),
        }

    def format_text(self) -> str:
        lines = [
            "vdi_launcher dry-run plan (no Popen)",
            f"  origin={self.origin} vendor_id={self.vendor_id} service={self.service_name}",
            f"  supports_path_a={self.supports_path_a}",
            f"  launch_style={self.launch_style}",
            f"  wrapper={self.wrapper_path}",
            f"  client={self.client_path}",
            f"  mode={self.mode} flag={_MODE_FLAGS.get(self.mode, '?')}",
            f"  cwd={self.cwd!r}",
            f"  env={self.env!r}",
            f"  argv={self.argv_display!r}",
            f"  cipher_meta={self.cipher_meta}",
            f"  dry_run={self.dry_run}",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)


def dry_run_plan(
    origin_or_profile: Union[str, VendorProfile],
    cipher: str = "STUB_RSA_CIPHER",
    mode: str = MODE_JSON,
    *,
    require_binaries: bool = False,
    origin: Optional[str] = None,
    launch_style: str = LAUNCH_SHELL_WRAPPER,
) -> LaunchPlan:
    """Resolve (if needed) + build argv + return redacted plan. Never Popen."""
    if isinstance(origin_or_profile, VendorProfile):
        profile = origin_or_profile
        origin_s = origin or profile.vendor_id
    else:
        origin_s = str(origin_or_profile)
        profile = resolve(origin_s, require_binaries=require_binaries)

    mode_n = _normalize_mode(mode)
    style = _normalize_launch_style(launch_style)
    argv = build_argv(profile, cipher, mode=mode_n, launch_style=style)
    display = argv_for_display(argv)
    cwd = plan_cwd(profile, style)
    env_delta = plan_env(profile, style)
    meta = {
        "mode": "stub" if str(cipher).startswith("STUB") else "provided",
        "len": len(str(cipher)),
        "redacted": True,
    }
    notes = [
        "production live launch requires allow_live=True",
        "exec arg is RSA cipher string (not {params:...} shell)",
        f"launch_style={style}",
    ]
    if style == LAUNCH_SHELL_WRAPPER and is_shell_wrapper(
        profile.vdi_wrapper_path or ""
    ):
        notes.append(
            "shell-wrapper policy: argv prefixes /bin/sh|/bin/bash "
            "(no-shebang ASCII wrapper would ENOEXEC on direct execve)"
        )
    if style == LAUNCH_DIRECT_CLIENT:
        notes.append(
            "direct_client: argv0=ELF Client; cwd=…/CMSS/bin; "
            "LD_LIBRARY_PATH=…/CMSS/lib (P17-C §4/§5); no shell/wrapper/sudo"
        )
        if argv and not argv[0].endswith("uSmartView_VDI_Client"):
            notes.append(f"argv0 client path: {argv[0]}")
    if "/opt/ZTE" in (profile.vdi_wrapper_path or "") or "/opt/ZTE" in (
        profile.vdi_client_path or ""
    ):
        notes.append("WARNING: path contains /opt/ZTE (unexpected for Path A)")
    return LaunchPlan(
        origin=origin_s,
        vendor_id=profile.vendor_id,
        service_name=profile.service_name,
        supports_path_a=profile.supports_path_a,
        wrapper_path=profile.vdi_wrapper_path,
        client_path=profile.vdi_client_path,
        mode=mode_n,
        argv=argv,
        argv_display=display,
        cipher_meta=meta,
        dry_run=True,
        notes=notes,
        launch_style=style,
        cwd=cwd,
        env=env_delta,
    )


def dry_run_plan_text(
    origin_or_profile: Union[str, VendorProfile],
    cipher: str = "STUB_RSA_CIPHER",
    mode: str = MODE_JSON,
    **kw: Any,
) -> str:
    return dry_run_plan(origin_or_profile, cipher, mode, **kw).format_text()


@dataclass
class LiveResult:
    """Handle for an optional live start (tests may mock Popen)."""

    argv: List[str]
    pid: Optional[int]
    allow_live: bool
    popen: Any = None


def live_start(
    profile: VendorProfile,
    cipher: str,
    mode: str = MODE_JSON,
    *,
    allow_live: bool = False,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
    popen_func: Any = None,
    launch_style: str = LAUNCH_SHELL_WRAPPER,
) -> LiveResult:
    """Start VDI only when allow_live=True. Default raises LiveLaunchDenied.

    popen_func injectable for tests (default subprocess.Popen).
    Does not wait / hang on the child.

    When launch_style=direct_client and cwd/env not supplied, applies
    plan_cwd / plan_env (…/CMSS/bin + LD_LIBRARY_PATH=…/CMSS/lib).
    """
    style = _normalize_launch_style(launch_style)
    argv = build_argv(profile, cipher, mode=mode, launch_style=style)
    if not allow_live:
        raise LiveLaunchDenied(
            "live_start denied: pass allow_live=True explicitly "
            "(default is dry-run only; no VDI Popen)"
        )
    # refuse ZTE on any argv component even if allow_live
    for a in argv:
        if isinstance(a, str) and a.startswith("/opt/ZTE"):
            raise VdiLauncherError(
                f"refusing live start with /opt/ZTE path in argv: {a!r}"
            )
    launcher = popen_func or subprocess.Popen
    child_env = os.environ.copy()
    # style-derived env first; explicit env overrides
    style_env = plan_env(profile, style, base=child_env)
    if style_env:
        child_env.update(style_env)
    if env:
        child_env.update(dict(env))
    use_cwd = cwd if cwd is not None else plan_cwd(profile, style)
    proc = launcher(
        argv,
        env=child_env,
        cwd=use_cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return LiveResult(argv=argv, pid=getattr(proc, "pid", None), allow_live=True, popen=proc)


def plan_from_origin(
    origin: str,
    *,
    cipher: str = "STUB_RSA_CIPHER",
    mode: str = MODE_JSON,
    net_detect: bool = False,
    require_binaries: bool = False,
    launch_style: str = LAUNCH_SHELL_WRAPPER,
) -> LaunchPlan:
    """Convenience: origin + optional netDetect → plan."""
    m = MODE_DETECT if net_detect else mode
    return dry_run_plan(
        origin,
        cipher=cipher,
        mode=m,
        require_binaries=require_binaries,
        launch_style=launch_style,
    )
