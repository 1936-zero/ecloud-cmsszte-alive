#!/usr/bin/env python3
"""Resolve public-ecloud CAG/csap endpoints for connectStr mint (claim=false).

Priority (highest first):
  1. explicit kwargs / CLI
  2. env: CAG_HOST, CAG_PORT, CSAPIP / ECLOUD_CSAPIP
  3. cloud_pc.json keys: cag_host, cag_port, csapip
  4. optional local client config discovery (path-only; best-effort)
  5. stock defaults (public ecloud known-good; overridable)

PIN: public_ecloud only · ban jtydn/爱家 · production_claim=false
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

log = logging.getLogger(__name__)

# Stock defaults (public path; customer MUST override if their CAG differs)
DEFAULT_CAG_HOST = "36.212.224.105"
DEFAULT_CAG_PORT = 8899
DEFAULT_CSAPIP = "192.168.1.200:30087"

PIN_PRODUCT_LINE = "public_ecloud_9222"
BAN_LINES = ("jtydn", "爱家", "cmcc-jtydn:9223", ":9223")
PRODUCTION_CLAIM = False

# Common client config locations (Linux); never required for product path.
_CLIENT_CONFIG_CANDIDATES = (
    Path.home() / ".config/Ecloud-Cloud-Computer-Application/config.json",
    Path.home() / ".config/ecloudcomputer/config.json",
    Path.home() / ".config/cmss/ecloudcomputer/config.json",
)

_HOST_RE = re.compile(
    r"(?:cag[_-]?host|gateway[_-]?host|cs[_-]?host|sHost|shost)",
    re.I,
)
_CSAP_RE = re.compile(r"(?:csapip|csap[_-]?ip|x-ap-shost|ap[_-]?shost)", re.I)
_IP_PORT_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b"
)
_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


@dataclass
class GatewayEndpoints:
    """Resolved mint endpoints (never log secrets; hosts are non-secret)."""

    cag_host: str = DEFAULT_CAG_HOST
    cag_port: int = DEFAULT_CAG_PORT
    csapip: str = DEFAULT_CSAPIP
    source: str = "default"
    notes: list[str] = field(default_factory=list)

    def as_public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["production_claim"] = PRODUCTION_CLAIM
        d["pin_product_line"] = PIN_PRODUCT_LINE
        return d


def _ban_check(text: str) -> Optional[str]:
    low = (text or "").lower()
    for b in BAN_LINES:
        if b.lower() in low:
            return b
    return None


def _as_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _from_mapping(m: Mapping[str, Any], source: str) -> Optional[GatewayEndpoints]:
    if not m:
        return None
    host = (
        m.get("cag_host")
        or m.get("cagHost")
        or m.get("gateway_host")
        or m.get("host")
        or ""
    )
    port = m.get("cag_port") or m.get("cagPort") or m.get("gateway_port") or m.get("port")
    csap = m.get("csapip") or m.get("csap_ip") or m.get("csapIp") or m.get("X-Ap-sHost") or ""
    host = str(host).strip() if host else ""
    csap = str(csap).strip() if csap else ""
    if not host and not csap:
        return None
    notes: list[str] = []
    ban = _ban_check(f"{host}:{port}:{csap}")
    if ban:
        notes.append(f"ban_hit:{ban} (ignored; use public defaults)")
        return None
    return GatewayEndpoints(
        cag_host=host or DEFAULT_CAG_HOST,
        cag_port=_as_int(port, DEFAULT_CAG_PORT),
        csapip=csap or DEFAULT_CSAPIP,
        source=source,
        notes=notes,
    )


def _from_env() -> Optional[GatewayEndpoints]:
    host = os.environ.get("CAG_HOST") or os.environ.get("ECLOUD_CAG_HOST") or ""
    port = os.environ.get("CAG_PORT") or os.environ.get("ECLOUD_CAG_PORT")
    csap = (
        os.environ.get("CSAPIP")
        or os.environ.get("ECLOUD_CSAPIP")
        or os.environ.get("X_AP_SHOST")
        or ""
    )
    if not host and not csap and port is None:
        return None
    ban = _ban_check(f"{host}:{port}:{csap}")
    if ban:
        log.warning("gateway env ban_hit=%s; ignore env", ban)
        return None
    return GatewayEndpoints(
        cag_host=(host or DEFAULT_CAG_HOST).strip(),
        cag_port=_as_int(port, DEFAULT_CAG_PORT),
        csapip=(csap or DEFAULT_CSAPIP).strip(),
        source="env",
    )


def load_cloud_pc(path: Path | str = "cloud_pc.json") -> dict:
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log.warning("cloud_pc read failed path=%s err=%s", p, e)
        return {}


def merge_gateway_into_cloud_pc(
    cfg: dict,
    gw: GatewayEndpoints,
    *,
    only_missing: bool = True,
) -> dict:
    """Write resolved gateway into cfg (in-memory). Caller saves if needed.

    only_missing=False force-overwrites cag_host/port/csapip + gateway_source
    (used when device customLoginParams corrects a stale default region CAG).
    """
    out = dict(cfg)
    mapping = {
        "cag_host": gw.cag_host,
        "cag_port": gw.cag_port,
        "csapip": gw.csapip,
    }
    for k, v in mapping.items():
        if only_missing and out.get(k):
            continue
        out[k] = v
    if only_missing:
        out.setdefault("gateway_source", gw.source)
    else:
        out["gateway_source"] = gw.source
    out.setdefault("production_claim", False)
    out.setdefault("pin_product_line", PIN_PRODUCT_LINE)
    return out


def gateway_source_is_weak(
    source: str | None = None,
    host: str | None = None,
) -> bool:
    """True when cfg gateway is missing/default/non-device (must re-read CLP).

    Shared by WebUI account_runtime, CLI desktop-keepalive resolve, remint.
    Device/customLogin sources are strong; default/empty/env/account_weak are not.
    Stock DEFAULT_CAG_HOST alone is also weak (GZ4 pin must not stick).
    """
    src = str(source or "").strip().lower()
    h = str(host or "").strip()
    if not h or h == DEFAULT_CAG_HOST:
        return True
    if not src or src in {"default", "account_weak", "fallback", "env"}:
        return True
    # device_customLoginParams / device_* / customlogin*
    compact = src.replace("_", "").replace("-", "")
    if "device" in src or "customlogin" in compact:
        return False
    # explicit CLI / manual / user overrides are strong
    if src in {"cli", "manual", "user"} or src.startswith("explicit"):
        return False
    # cloud_pc / client_config without device clp → treat weak for region refresh
    return True


def apply_device_gateway_from_clp(
    cfg: dict,
    clp: Any,
    *,
    only_missing: bool = False,
    force: bool = False,
) -> tuple[dict, Optional[GatewayEndpoints]]:
    """Parse desktop customLoginParams and merge into cfg when useful.

    Returns (cfg, gw_or_None). only_missing=False overwrites weak/default CAG
    (device clp is authoritative for this desktop). If force=False and current
    source is strong (explicit/cli/manual), skip overwrite even when clp present.
    """
    if not clp:
        return cfg, None
    try:
        gw = gateway_from_custom_login_params(clp)
    except Exception as e:  # noqa: BLE001
        log.debug("apply_device_gateway_from_clp parse skip: %s", e)
        return cfg, None
    if gw is None:
        return cfg, None
    if not force:
        src = str(cfg.get("gateway_source") or "")
        # preserve explicit CLI/env-style strong sources
        if src.startswith("explicit") or src in {"cli", "manual", "user"}:
            return cfg, None
        # env is weak for region CAG (operator may still set CAG_HOST intentionally;
        # only skip when env is strong AND host is non-default — rare)
        if src.startswith("env") and not gateway_source_is_weak(src, str(cfg.get("cag_host") or "")):
            return cfg, None
    cfg2 = merge_gateway_into_cloud_pc(cfg, gw, only_missing=only_missing)
    return cfg2, gw


def gateway_from_custom_login_params(
    clp: Any,
    *,
    source: str = "device_customLoginParams",
) -> Optional[GatewayEndpoints]:
    """Parse machineList[].customLoginParams → region CAG (#75fixx).

    Prefer first IPv4 entry in cagList + csapip. Skip IPv6 (URL needs brackets).
    ``clp`` may be a dict or a JSON string. Returns None if unusable.
    """
    if clp is None or clp == "":
        return None
    if isinstance(clp, str):
        s = clp.strip()
        if not s:
            return None
        try:
            clp = json.loads(s)
        except json.JSONDecodeError:
            return None
    if not isinstance(clp, Mapping):
        return None

    # ban-line hard gate (never accept 爱家/jtydn hosts)
    try:
        ban = _ban_check(json.dumps(dict(clp), ensure_ascii=False)[:800])
    except Exception:
        ban = _ban_check(str(clp)[:800])
    if ban:
        log.warning("customLoginParams ban_hit=%s; ignore", ban)
        return None

    host = ""
    port = DEFAULT_CAG_PORT
    cag_list = clp.get("cagList") or clp.get("cag_list") or []
    if isinstance(cag_list, list):
        for item in cag_list:
            if not isinstance(item, Mapping):
                continue
            addr = str(item.get("addr") or item.get("ip") or item.get("host") or "").strip()
            if not addr:
                continue
            # skip IPv6 literals (contain ':' beyond nothing; v4 never has ':')
            if ":" in addr:
                continue
            if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", addr):
                continue
            host = addr
            port = _as_int(item.get("port"), DEFAULT_CAG_PORT)
            break

    csap = str(clp.get("csapip") or clp.get("csapIp") or clp.get("csap_ip") or "").strip()
    # skip pure IPv6 csap forms
    if csap and csap.count(":") > 1:
        csap = ""

    if not host and not csap:
        return None

    notes = ["from machine customLoginParams cagList"]
    if host:
        notes.append(f"cag={host}:{port}")
    return GatewayEndpoints(
        cag_host=host or DEFAULT_CAG_HOST,
        cag_port=port if host else DEFAULT_CAG_PORT,
        csapip=csap or DEFAULT_CSAPIP,
        source=source,
        notes=notes,
    )


def _walk_strings(obj: Any, limit: int = 400) -> Iterable[tuple[str, str]]:
    """Yield (path, string_value) from nested JSON-like structures."""
    n = 0
    stack: list[tuple[str, Any]] = [("", obj)]
    while stack and n < limit:
        path, cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                kp = f"{path}.{k}" if path else str(k)
                stack.append((kp, v))
        elif isinstance(cur, list):
            for i, v in enumerate(cur[:20]):
                stack.append((f"{path}[{i}]", v))
        elif isinstance(cur, str):
            n += 1
            yield path, cur
        elif isinstance(cur, (int, float)):
            n += 1
            yield path, str(cur)


def discover_from_client_config(
    paths: Optional[Iterable[Path]] = None,
) -> Optional[GatewayEndpoints]:
    """Best-effort parse of local official client config (optional).

    Electron config is often encrypted/opaque; success is not required.
    Never logs file contents — only discovered host:port pairs.
    """
    candidates = list(paths) if paths is not None else list(_CLIENT_CONFIG_CANDIDATES)
    for p in candidates:
        if not p.is_file():
            continue
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
            # Try JSON first
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = None
            host = ""
            port: Optional[int] = None
            csap = ""
            if isinstance(data, dict):
                # Key-path heuristics
                for path, val in _walk_strings(data):
                    if _CSAP_RE.search(path) and _IP_PORT_RE.search(val):
                        csap = _IP_PORT_RE.search(val).group(0)  # type: ignore[union-attr]
                    elif _HOST_RE.search(path):
                        m = _IP_PORT_RE.search(val) or _IP_RE.search(val)
                        if m:
                            if ":" in m.group(0):
                                host, ps = m.group(0).split(":", 1)
                                port = _as_int(ps, DEFAULT_CAG_PORT)
                            else:
                                host = m.group(1)
                    # Value-only: csap-looking host:port inside private ranges often 30087
                    m2 = _IP_PORT_RE.search(val)
                    if m2 and m2.group(2) in ("30087", "8899"):
                        if m2.group(2) == "30087" and not csap:
                            csap = m2.group(0)
                        if m2.group(2) == "8899" and not host:
                            host, port = m2.group(1), 8899
            # Plaintext fallback scan (logs/config dumps)
            if not host or not csap:
                for m in _IP_PORT_RE.finditer(raw):
                    ip, ps = m.group(1), m.group(2)
                    if ps == "8899" and not host:
                        host, port = ip, 8899
                    elif ps == "30087" and not csap:
                        csap = f"{ip}:{ps}"
            if host or csap:
                ban = _ban_check(f"{host}:{port}:{csap}:{p}")
                if ban:
                    log.info("client config ban_hit=%s path=%s", ban, p)
                    continue
                return GatewayEndpoints(
                    cag_host=host or DEFAULT_CAG_HOST,
                    cag_port=port if port is not None else DEFAULT_CAG_PORT,
                    csapip=csap or DEFAULT_CSAPIP,
                    source=f"client_config:{p}",
                    notes=["best_effort_discovery"],
                )
            log.info("client config present but no cag/csap keys path=%s", p)
        except Exception as e:
            log.info("client config skip path=%s err=%s", p, e)
    return None


def resolve_gateway(
    *,
    cag_host: Optional[str] = None,
    cag_port: Optional[int] = None,
    csapip: Optional[str] = None,
    cloud_pc_path: Path | str = "cloud_pc.json",
    cfg: Optional[Mapping[str, Any]] = None,
    try_client_discovery: bool = True,
    allow_default: bool = True,
) -> GatewayEndpoints:
    """Resolve endpoints with documented priority. Never raises on missing file."""
    # 1) explicit
    if cag_host or csapip or cag_port is not None:
        ban = _ban_check(f"{cag_host}:{cag_port}:{csapip}")
        if ban:
            log.warning("explicit gateway ban_hit=%s; falling through", ban)
        else:
            return GatewayEndpoints(
                cag_host=(cag_host or DEFAULT_CAG_HOST).strip(),
                cag_port=_as_int(cag_port, DEFAULT_CAG_PORT),
                csapip=(csapip or DEFAULT_CSAPIP).strip(),
                source="explicit",
            )

    # 2) env
    env_gw = _from_env()
    if env_gw:
        return env_gw

    # 3) cloud_pc / cfg
    data = dict(cfg) if cfg else load_cloud_pc(cloud_pc_path)
    file_gw = _from_mapping(data, source=f"cloud_pc:{cloud_pc_path}")
    if file_gw:
        return file_gw

    # 4) optional client discovery
    if try_client_discovery:
        disc = discover_from_client_config()
        if disc:
            return disc

    # 5) defaults
    if not allow_default:
        raise RuntimeError(
            "gateway unresolved: set cag_host/csapip in cloud_pc.json or CAG_HOST/CSAPIP env"
        )
    return GatewayEndpoints(
        cag_host=DEFAULT_CAG_HOST,
        cag_port=DEFAULT_CAG_PORT,
        csapip=DEFAULT_CSAPIP,
        source="default",
        notes=["using stock public defaults; override via cloud_pc.json or env"],
    )


def selfcheck() -> dict[str, Any]:
    """Offline policy selfcheck (no network)."""
    gw = resolve_gateway(try_client_discovery=False)
    assert gw.cag_host and gw.csapip
    assert PRODUCTION_CLAIM is False
    assert PIN_PRODUCT_LINE.startswith("public_ecloud")
    # ban paths must not win
    bad = _from_mapping(
        {"cag_host": "x", "csapip": "jtydn.example:9223"}, source="test"
    )
    assert bad is None
    # #75fixx: customLoginParams → first IPv4 cagList; skip IPv6; ban gate
    hhht = gateway_from_custom_login_params(
        {
            "csapip": "192.168.1.200:30087",
            "cagList": [
                {"addr": "2409:8c85::1", "port": 8899, "name": "v6"},
                {"addr": "36.139.178.146", "port": 8899, "name": "gateway_hhht3_cag1_v4"},
                {"addr": "36.139.178.189", "port": 8899, "name": "gateway_hhht3_cag2_v4"},
            ],
        }
    )
    assert hhht is not None
    assert hhht.cag_host == "36.139.178.146"
    assert hhht.cag_port == 8899
    assert hhht.csapip == "192.168.1.200:30087"
    assert hhht.source == "device_customLoginParams"
    ban_clp = gateway_from_custom_login_params(
        {"csapip": "jtydn.example:9223", "cagList": [{"addr": "1.2.3.4", "port": 8899}]}
    )
    assert ban_clp is None
    empty = gateway_from_custom_login_params(None)
    assert empty is None
    return {
        "ok": True,
        "gateway": gw.as_public_dict(),
        "production_claim": PRODUCTION_CLAIM,
        "pin": PIN_PRODUCT_LINE,
        "fixx_device_cag": hhht.as_public_dict(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(json.dumps(selfcheck(), indent=2, ensure_ascii=False))
    g = resolve_gateway()
    print(json.dumps(g.as_public_dict(), indent=2, ensure_ascii=False))
