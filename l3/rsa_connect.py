"""RSA connect shell for Path A — encrypt plain connect JSON via pubkey slot.

Slot path strings only (e.g. privateSetting.SDKSecretKey.publicKey.CMSSZTE).
PEM material is never embedded here; runtime may pass a filesystem path to a
PEM file or enable dry-run stub cipher when the slot/path is unavailable.

Live encrypt path resolution (P10-A):
  resolve_pubkey_path(explicit) → explicit arg → env ECLOUD_CMSS_PUBKEY_PEM.
  Never scrapes Electron config blobs; never defaults to /opt/ZTE; never embeds PEM.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# RSA-1024 PKCS#1 v1.5 encrypt block (modulus/8 - 11); matches cryptoUtil.js.
RSA_ENCRYPT_CHUNK = 117

# Prefix for dry-run / missing-slot stub so callers can detect non-production cipher.
DRY_STUB_PREFIX = "DRY_RSA_STUB:"

# Operator contract: absolute/relative path to a PUBLIC KEY PEM file on disk.
# Set by host/keychain export — never committed; value is a path string only.
ENV_CMSS_PUBKEY_PEM = "ECLOUD_CMSS_PUBKEY_PEM"

PlainInput = Union[str, bytes, bytearray, memoryview]


class RsaConnectError(ValueError):
    """Invalid profile slot or encrypt inputs."""


def resolve_pubkey_slot(profile: Any) -> str:
    """Return the logical pubkey slot path string from a VendorProfile / mapping.

    Does not load or return any PEM material.
    """
    if profile is None:
        raise RsaConnectError("profile is required")
    slot: Optional[str]
    if isinstance(profile, Mapping):
        slot = profile.get("pubkey_slot") or profile.get("pubkeySlot")
    else:
        slot = getattr(profile, "pubkey_slot", None)
        if slot is None:
            slot = getattr(profile, "pubkeySlot", None)
    if not slot or not str(slot).strip():
        raise RsaConnectError("profile.pubkey_slot empty")
    return str(slot).strip()


def resolve_pubkey_path(
    explicit: Optional[str] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    must_exist: bool = True,
) -> Optional[str]:
    """Resolve filesystem path to CMSS RSA public-key PEM (path string only).

    Priority:
      1. non-empty ``explicit`` argument
      2. environment variable ``ECLOUD_CMSS_PUBKEY_PEM`` (path to PEM file)

    Does **not**:
      - read or decrypt Electron ``~/.config/Ecloud-Cloud-Computer-Application/``
      - fall back to ``/opt/ZTE`` or any vendor default PEM
      - return or log PEM body

    Parameters
    ----------
    explicit:
        Caller-supplied path (CLI / session / test fixture).
    env:
        Optional mapping for tests; defaults to ``os.environ``.
    must_exist:
        If True (default), only return a path that is an existing file.
        If False, return the resolved path string even when the file is absent
        (useful for diagnostics / error messages).

    Returns
    -------
    Absolute path string when resolved (and existing if must_exist), else None.
    """
    environ = env if env is not None else os.environ
    candidates = []
    if explicit is not None and str(explicit).strip():
        candidates.append(str(explicit).strip())
    env_val = environ.get(ENV_CMSS_PUBKEY_PEM) if environ is not None else None
    if env_val is not None and str(env_val).strip():
        candidates.append(str(env_val).strip())

    for raw in candidates:
        path = Path(raw).expanduser()
        # Prefer absolute form for stable logs (path only — never open here for body).
        try:
            abs_path = path if path.is_absolute() else (Path.cwd() / path)
            abs_s = str(abs_path.resolve(strict=False))
        except (OSError, RuntimeError):
            abs_s = str(path)
        if must_exist:
            if os.path.isfile(abs_s):
                return abs_s
            # also accept the raw string if it is already a file (relative)
            if os.path.isfile(raw):
                return str(Path(raw).resolve())
            continue
        return abs_s
    return None


def _plain_to_bytes(plain: PlainInput) -> bytes:
    if isinstance(plain, (bytes, bytearray, memoryview)):
        return bytes(plain)
    if isinstance(plain, str):
        return plain.encode("utf-8")
    raise RsaConnectError(f"plain must be str or bytes, got {type(plain).__name__}")


def _stub_cipher(plain: PlainInput) -> str:
    """Deterministic non-empty stub; does not read PEM or log secrets."""
    data = _plain_to_bytes(plain)
    digest = hashlib.sha256(data).hexdigest()[:32]
    return f"{DRY_STUB_PREFIX}{digest}"


def _load_pem_from_path(pubkey_path: str) -> str:
    path = Path(pubkey_path)
    if not path.is_file():
        raise RsaConnectError(f"pubkey path not found: {pubkey_path}")
    # Read PEM for encrypt only; caller must not log return of this helper.
    text = path.read_text(encoding="utf-8")
    if "BEGIN" not in text or "PUBLIC KEY" not in text:
        raise RsaConnectError("pubkey file does not look like a PUBLIC KEY PEM")
    return text


def rsa_encrypt_with_pem(plain: PlainInput, public_key_pem: str) -> str:
    """PKCS1 v1.5 chunked RSA encrypt → base64 (cryptoUtil / staticRsaEncrypt).

    public_key_pem must be supplied by the caller at runtime; never stored in repo.
    """
    if not public_key_pem or "BEGIN" not in public_key_pem:
        raise RsaConnectError("public_key_pem missing or invalid")
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(key)
    data = _plain_to_bytes(plain)
    out = bytearray()
    for i in range(0, len(data), RSA_ENCRYPT_CHUNK):
        out += cipher.encrypt(data[i : i + RSA_ENCRYPT_CHUNK])
    return base64.b64encode(bytes(out)).decode("ascii")


def encrypt_plain(
    plain: PlainInput,
    pubkey_path: Optional[str] = None,
    *,
    dry_run: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Encrypt plain connect payload to a cipher string.

    - dry_run=True: return stub cipher without reading any key material.
    - pubkey_path empty/None: try ``resolve_pubkey_path`` (env ECLOUD_CMSS_PUBKEY_PEM).
    - still missing file: return stub (slot unavailable) — never raise for ops.
    - otherwise: read PEM from resolved path and RSA-encrypt (base64).

    Never logs PEM, password, token, or ticket.
    """
    if dry_run:
        return _stub_cipher(plain)
    # Priority: explicit arg → env ECLOUD_CMSS_PUBKEY_PEM (path only).
    path = resolve_pubkey_path(pubkey_path, env=env, must_exist=True)
    if not path or not os.path.isfile(path):
        return _stub_cipher(plain)
    pem = _load_pem_from_path(path)
    return rsa_encrypt_with_pem(plain, pem)


def encrypt_connect_params(
    plain_json: PlainInput,
    profile: Any = None,
    *,
    pubkey_path: Optional[str] = None,
    dry_run: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """High-level helper: resolve slot from profile (for call sites) then encrypt.

    When ``pubkey_path`` is None and not dry_run, path is resolved via
    :func:`resolve_pubkey_path` (explicit none → env ``ECLOUD_CMSS_PUBKEY_PEM``).
    Slot resolution remains side-effect free (name only).
    """
    if profile is not None:
        # Validate slot is present; value is not used for file I/O here.
        resolve_pubkey_slot(profile)
    return encrypt_plain(plain_json, pubkey_path, dry_run=dry_run, env=env)
