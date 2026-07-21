"""Path A session: Local15900 + dry/live pipeline wire (no live VDI by default).

Lifecycle:
  prepare() → bind 127.0.0.1:socketPort
  dry_run_pipeline() → connect_schema → rsa(dry) → vdi_launcher(dry)
  live_pipeline(allow_live=True) → rsa(live) → live_start(allow_live=True)
  stop()

HEART (type=1) is swallowed by Local15900Server with no auto-reply.
No silent fake live: stub cipher is refused unless allow_stub_cipher=True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Union

from .connect_schema import (
    build_plain,
    build_plain_json,
    redact_plain_for_log,
)
from .local_15900 import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    Local15900Server,
    MsgType,
)
from .rsa_connect import (
    DRY_STUB_PREFIX,
    encrypt_connect_params,
    resolve_pubkey_path,
    resolve_pubkey_slot,
)
from .vdi_launcher import (
    MODE_JSON,
    LaunchPlan,
    LiveLaunchDenied,
    LiveResult,
    REDACTED,
    dry_run_plan,
    live_start,
)
from .vendor_resolver import VendorError, VendorProfile, resolve, resolve_desktop


@dataclass
class PathASession:
    """Path A control-plane session holder with dry pipeline orchestrator.

    Default path never Popen VDI. Tests use sim TCP client against socketPort.
    """

    origin_company_code: str
    machine_id: str = ""
    host: str = DEFAULT_HOST
    start_port: int = DEFAULT_PORT
    vendor: Optional[VendorProfile] = None
    server: Optional[Local15900Server] = None
    socket_port: Optional[int] = None
    _prepared: bool = False
    notes: Dict[str, Any] = field(default_factory=dict)
    last_plan: Optional[Dict[str, Any]] = None

    def prepare(self, desktop: Optional[dict] = None) -> int:
        """Resolve vendor + bind local 15900. Returns actual socketPort."""
        if desktop is not None:
            self.vendor = resolve_desktop(desktop)
            if not self.machine_id:
                self.machine_id = str(
                    desktop.get("instanceId")
                    or desktop.get("desktopId")
                    or desktop.get("id")
                    or desktop.get("machineId")
                    or ""
                )
            if not self.origin_company_code:
                self.origin_company_code = str(
                    desktop.get("originCompanyCode")
                    or desktop.get("origin_company_code")
                    or ""
                )
        else:
            self.vendor = resolve(self.origin_company_code)

        if not self.vendor.supports_path_a:
            raise VendorError(
                f"vendor {self.vendor.vendor_id} does not support Path A"
            )

        company = self.vendor.vendor_id
        # Prefer explicit origin for connect_info company tag when available
        company_tag = self.origin_company_code or company
        srv = Local15900Server(host=self.host, start_port=self.start_port)
        if self.machine_id:
            srv.init_connect_info(self.machine_id, company_tag)
        port = srv.start()
        self.server = srv
        self.socket_port = port
        self._prepared = True
        self.notes["role"] = "electron_like_server"
        self.notes["heart_auto_reply"] = False
        return port

    def connect_json_socket_fields(self) -> Dict[str, Any]:
        """Fields to merge into VDI connect JSON (no secrets)."""
        if not self._prepared or self.socket_port is None:
            raise RuntimeError("session not prepared")
        return {
            "socketPort": str(self.socket_port),
            "socketHost": self.host,
        }

    def dry_run_pipeline(
        self,
        desktop: Optional[Mapping[str, Any]] = None,
        session: Optional[Mapping[str, Any]] = None,
        *,
        mode: str = MODE_JSON,
        prepare: bool = True,
        rsa_dry_run: bool = True,
        pubkey_path: Optional[str] = None,
        require_binaries: bool = False,
    ) -> Dict[str, Any]:
        """Full dry pipeline: prepare → plain → rsa stub → launch plan.

        Returns a structured plan dict (safe for logs: redacted plain + argv).
        Never launches VDI. Never embeds PEM/secrets.
        """
        desk: Dict[str, Any] = dict(desktop or {})
        if "originCompanyCode" not in desk and "origin_company_code" not in desk:
            desk["originCompanyCode"] = self.origin_company_code
        if self.machine_id and not any(
            k in desk for k in ("machineId", "instanceId", "desktopId", "id")
        ):
            desk["machineId"] = self.machine_id

        if prepare or not self._prepared:
            self.prepare(desk if desk else None)
        assert self.vendor is not None
        assert self.socket_port is not None

        # session overlay: caller session + bound socket fields
        sess_map: Dict[str, Any] = dict(session or {})
        sess_map.update(self.connect_json_socket_fields())

        plain = build_plain(
            desk,
            sess_map,
            socket_port=self.socket_port,
            origin_company_code=self.origin_company_code or None,
        )
        plain_json = build_plain_json(
            desk,
            sess_map,
            socket_port=self.socket_port,
            origin_company_code=self.origin_company_code or None,
        )
        plain_safe = redact_plain_for_log(plain)

        slot = resolve_pubkey_slot(self.vendor)
        # Path resolution: explicit arg wins; else env ECLOUD_CMSS_PUBKEY_PEM.
        # Path string only — never PEM body. No Electron scrape, no /opt/ZTE.
        resolved_pubkey_path: Optional[str] = None
        if pubkey_path is not None and str(pubkey_path).strip():
            resolved_pubkey_path = resolve_pubkey_path(
                str(pubkey_path).strip(), must_exist=True
            )
            resolved_via = "explicit" if resolved_pubkey_path else "explicit_missing"
        else:
            resolved_pubkey_path = resolve_pubkey_path(None, must_exist=True)
            resolved_via = "env" if resolved_pubkey_path else "none"
        cipher = encrypt_connect_params(
            plain_json,
            self.vendor,
            pubkey_path=resolved_pubkey_path or pubkey_path,
            dry_run=rsa_dry_run,
        )
        cipher_is_stub = str(cipher).startswith(DRY_STUB_PREFIX)

        launch: LaunchPlan = dry_run_plan(
            self.vendor,
            cipher=cipher,
            mode=mode,
            require_binaries=require_binaries,
            origin=self.origin_company_code or None,
        )

        plan: Dict[str, Any] = {
            "stage": "dry_run_pipeline",
            "origin": self.origin_company_code,
            "vendor_id": self.vendor.vendor_id,
            "machine_id": self.machine_id,
            "socketHost": self.host,
            "socketPort": self.socket_port,
            "pubkey_slot": slot,
            "rsa": {
                "dry_run": rsa_dry_run,
                "cipher_is_stub": cipher_is_stub,
                "cipher_len": len(cipher) if cipher is not None else 0,
                "cipher_display": REDACTED,
                "stub_prefix": DRY_STUB_PREFIX if cipher_is_stub else None,
                "resolved_via": resolved_via,
                "pubkey_path_set": bool(resolved_pubkey_path),
                # path only (no PEM); useful for ops; omit body always
                "pubkey_path": resolved_pubkey_path,
            },
            "plain_redacted": plain_safe,
            "plain_key_count": len(plain),
            "launch": launch.to_dict(),
            "argv_display": list(launch.argv_display),
            "live_vdi": False,
            "heart_auto_reply": False,
            "notes": list(launch.notes)
            + [
                "pipeline: prepare→connect_schema→rsa→vdi_launcher(dry)",
                "no live Popen; HEART swallow via Local15900Server",
            ],
        }
        self.last_plan = plan
        self.notes["last_pipeline"] = "dry_run"
        self.notes["socketPort"] = self.socket_port
        return plan

    def live_pipeline(
        self,
        desktop: Optional[Mapping[str, Any]] = None,
        session: Optional[Mapping[str, Any]] = None,
        *,
        allow_live: bool = False,
        mode: str = MODE_JSON,
        prepare: bool = True,
        pubkey_path: Optional[str] = None,
        require_binaries: bool = True,
        allow_stub_cipher: bool = False,
        popen: Any = None,
    ) -> Dict[str, Any]:
        """Live pipeline: prepare → plain → RSA (live) → live_start(allow_live=True).

        Safety:
          - Default allow_live=False → LiveLaunchDenied (no Popen).
          - Stub cipher (no PEM) → RuntimeError unless allow_stub_cipher=True.
          - Never embeds PEM/secrets; cipher_display always REDACTED.
          - Does not claim HEART observation.

        Returns structured plan including live_result (pid/argv_display) when launched.
        """
        if not allow_live:
            raise LiveLaunchDenied(
                "live_pipeline requires allow_live=True "
                "(default is dry-only; refuse silent live)"
            )

        desk: Dict[str, Any] = dict(desktop or {})
        if "originCompanyCode" not in desk and "origin_company_code" not in desk:
            desk["originCompanyCode"] = self.origin_company_code
        if self.machine_id and not any(
            k in desk for k in ("machineId", "instanceId", "desktopId", "id")
        ):
            desk["machineId"] = self.machine_id

        if prepare or not self._prepared:
            self.prepare(desk if desk else None)
        assert self.vendor is not None
        assert self.socket_port is not None

        sess_map: Dict[str, Any] = dict(session or {})
        sess_map.update(self.connect_json_socket_fields())

        plain = build_plain(
            desk,
            sess_map,
            socket_port=self.socket_port,
            origin_company_code=self.origin_company_code or None,
        )
        plain_json = build_plain_json(
            desk,
            sess_map,
            socket_port=self.socket_port,
            origin_company_code=self.origin_company_code or None,
        )
        plain_safe = redact_plain_for_log(plain)

        slot = resolve_pubkey_slot(self.vendor)
        resolved_pubkey_path: Optional[str] = None
        if pubkey_path is not None and str(pubkey_path).strip():
            resolved_pubkey_path = resolve_pubkey_path(
                str(pubkey_path).strip(), must_exist=True
            )
            resolved_via = "explicit" if resolved_pubkey_path else "explicit_missing"
        else:
            resolved_pubkey_path = resolve_pubkey_path(None, must_exist=True)
            resolved_via = "env" if resolved_pubkey_path else "none"

        # Live RSA: dry_run=False. encrypt_connect_params may still stub if no PEM.
        cipher = encrypt_connect_params(
            plain_json,
            self.vendor,
            pubkey_path=resolved_pubkey_path or pubkey_path,
            dry_run=False,
        )
        cipher_is_stub = str(cipher).startswith(DRY_STUB_PREFIX)
        if cipher_is_stub and not allow_stub_cipher:
            raise RuntimeError(
                "live_pipeline refused: RSA cipher is stub "
                f"(prefix={DRY_STUB_PREFIX!r}); set ECLOUD_CMSS_PUBKEY_PEM "
                "to a PEM path, pass pubkey_path=, or allow_stub_cipher=True "
                "for explicit stub-only experiments (not production live)"
            )

        # Dry plan for argv_display / notes (no Popen here)
        launch: LaunchPlan = dry_run_plan(
            self.vendor,
            cipher=cipher,
            mode=mode,
            require_binaries=require_binaries,
            origin=self.origin_company_code or None,
        )

        live_res: LiveResult = live_start(
            self.vendor,
            cipher,
            mode=mode,
            allow_live=True,
            popen_func=popen,
        )
        # Retain handle so caller/stop can manage lifecycle if needed
        self._live_result = live_res  # type: ignore[attr-defined]

        plan: Dict[str, Any] = {
            "stage": "live_pipeline",
            "origin": self.origin_company_code,
            "vendor_id": self.vendor.vendor_id,
            "machine_id": self.machine_id,
            "socketHost": self.host,
            "socketPort": self.socket_port,
            "pubkey_slot": slot,
            "rsa": {
                "dry_run": False,
                "cipher_is_stub": cipher_is_stub,
                "cipher_len": len(cipher) if cipher is not None else 0,
                "cipher_display": REDACTED,
                "stub_prefix": DRY_STUB_PREFIX if cipher_is_stub else None,
                "resolved_via": resolved_via,
                "pubkey_path_set": bool(resolved_pubkey_path),
                "pubkey_path": resolved_pubkey_path,
                "allow_stub_cipher": allow_stub_cipher,
            },
            "plain_redacted": plain_safe,
            "plain_key_count": len(plain),
            "launch": launch.to_dict(),
            "argv_display": list(launch.argv_display),
            "live_vdi": True,
            "live_result": {
                "pid": live_res.pid,
                "allow_live": live_res.allow_live,
                "argv_display": list(launch.argv_display),
                # raw argv kept only as display-redacted form
            },
            "heart_auto_reply": False,
            "heart_observed": False,  # never claim; evidence is external
            "notes": list(launch.notes)
            + [
                "pipeline: prepare→connect_schema→rsa(live)→live_start(allow_live=True)",
                "argv form: VDI_exe --json <cipher> (cipher redacted in logs)",
                "no HEART claim from this module; dual-evidence is caller's job",
            ],
        }
        self.last_plan = plan
        self.notes["last_pipeline"] = "live"
        self.notes["socketPort"] = self.socket_port
        if live_res.pid is not None:
            self.notes["live_pid"] = live_res.pid
        return plan

    def send_heartbeat_probe(
        self,
        machine_id: Optional[str] = None,
        data: Any = None,
    ) -> bool:
        """Pseudo-VDI style: send type=1; do not expect reply."""
        if not self.server:
            return False
        mid = machine_id or self.machine_id
        if not mid:
            return False
        if mid not in self.server.machine_list and self.vendor:
            self.server.init_connect_info(mid, self.vendor.vendor_id)
        return self.server.send_data(MsgType.COMMAND_HEART_BEAT, mid, data)

    def stop(self) -> None:
        # Best-effort: terminate live VDI if we still hold the handle
        live_res = getattr(self, "_live_result", None)
        if live_res is not None and getattr(live_res, "popen", None) is not None:
            proc = live_res.popen
            try:
                if getattr(proc, "poll", lambda: 0)() is None:
                    proc.terminate()
            except Exception:
                pass
            self._live_result = None  # type: ignore[attr-defined]
        if self.server is not None:
            self.server.stop()
            self.server = None
        self._prepared = False


def dry_run_pipeline(
    origin_company_code: str = "CMSSZTE",
    desktop: Optional[Mapping[str, Any]] = None,
    *,
    machine_id: str = "",
    start_port: int = DEFAULT_PORT,
    host: str = DEFAULT_HOST,
    mode: str = MODE_JSON,
    stop_after: bool = True,
    **kw: Any,
) -> Dict[str, Any]:
    """Module-level convenience: one-shot dry pipeline (always stops server unless stop_after=False)."""
    mid = machine_id
    if not mid and desktop:
        mid = str(
            desktop.get("machineId")
            or desktop.get("instanceId")
            or desktop.get("id")
            or ""
        )
    sess = PathASession(
        origin_company_code=origin_company_code,
        machine_id=mid,
        host=host,
        start_port=start_port,
    )
    try:
        return sess.dry_run_pipeline(desktop=desktop, mode=mode, **kw)
    finally:
        if stop_after:
            sess.stop()


def live_pipeline(
    origin_company_code: str = "CMSSZTE",
    desktop: Optional[Mapping[str, Any]] = None,
    *,
    machine_id: str = "",
    start_port: int = DEFAULT_PORT,
    host: str = DEFAULT_HOST,
    mode: str = MODE_JSON,
    allow_live: bool = False,
    stop_after: bool = False,
    **kw: Any,
) -> Dict[str, Any]:
    """Module-level convenience for live pipeline.

    Default allow_live=False → LiveLaunchDenied.
    stop_after=False by default so caller can observe socket while VDI runs.
    """
    mid = machine_id
    if not mid and desktop:
        mid = str(
            desktop.get("machineId")
            or desktop.get("instanceId")
            or desktop.get("id")
            or ""
        )
    sess = PathASession(
        origin_company_code=origin_company_code,
        machine_id=mid,
        host=host,
        start_port=start_port,
    )
    try:
        return sess.live_pipeline(
            desktop=desktop, mode=mode, allow_live=allow_live, **kw
        )
    finally:
        if stop_after:
            sess.stop()


__all__ = [
    "PathASession",
    "dry_run_pipeline",
    "live_pipeline",
]
