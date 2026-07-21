#!/usr/bin/env python3
"""Injectable key material provider for pure-Python SPICE L-proto (N5).

production_claim=false

Design goals (N5 hard accept):
  - No hard dependency on vendor SDK / uSmartView
  - No secrets embedded in repo; callers inject via KeyProvider
  - Missing keys fail with an *explainable* error (which slot, why)

Slots (string names, intentionally opaque bytes — N1 may later seal derives):
  - ticket          : SPICE link ticket / RSA ciphertext blob (if any)
  - session_key     : main-channel session key material (if any)
  - prop0x14        : vendor prop 0x14 blob (≠ EncryptWithKey guest path; P3)
  - password        : legacy password slot (prefer ticket; avoid LIVE secrets)
  - ztec_c2s        : optional ZTEC C2S preamble bytes for :8899
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Mapping, Optional, Sequence


# Canonical slot names used by handshake state machine.
SLOT_TICKET = "ticket"
SLOT_SESSION_KEY = "session_key"
SLOT_PROP0X14 = "prop0x14"
SLOT_PASSWORD = "password"
SLOT_ZTEC_C2S = "ztec_c2s"

ALL_SLOTS: Sequence[str] = (
    SLOT_TICKET,
    SLOT_SESSION_KEY,
    SLOT_PROP0X14,
    SLOT_PASSWORD,
    SLOT_ZTEC_C2S,
)


class MissingKeyError(Exception):
    """Raised when a required key slot is absent — always explainable."""

    def __init__(
        self,
        slot: str,
        *,
        stage: str = "",
        reason: str = "",
        available: Optional[Iterable[str]] = None,
    ) -> None:
        self.slot = slot
        self.stage = stage
        self.reason = reason or f"key slot '{slot}' not provided by key_provider"
        self.available = sorted(set(available or []))
        parts = [f"MissingKeyError(slot={slot!r}"]
        if stage:
            parts.append(f"stage={stage!r}")
        parts.append(f"reason={self.reason!r}")
        if self.available:
            parts.append(f"available={self.available!r}")
        else:
            parts.append("available=[]")
        parts.append("production_claim=False)")
        super().__init__(", ".join(parts))

    def as_dict(self) -> dict:
        return {
            "error": "MissingKeyError",
            "slot": self.slot,
            "stage": self.stage,
            "reason": self.reason,
            "available": list(self.available),
            "production_claim": False,
        }


class KeyProvider(ABC):
    """Injection surface for secrets / derived blobs.

    Implementations MUST NOT read real production vaults by default.
    Offline / CI should use NullKeyProvider or DictKeyProvider(fixtures).
    """

    @abstractmethod
    def get(self, slot: str) -> Optional[bytes]:
        """Return key bytes for *slot*, or None if unavailable."""

    def require(self, slot: str, *, stage: str = "") -> bytes:
        """get() or raise MissingKeyError with explainable context."""
        val = self.get(slot)
        if val is None:
            raise MissingKeyError(
                slot,
                stage=stage,
                reason=(
                    f"required key slot '{slot}' is missing "
                    f"(inject via KeyProvider; no SDK fallback)"
                ),
                available=self.available_slots(),
            )
        if not isinstance(val, (bytes, bytearray)):
            raise TypeError(f"key slot {slot!r} must be bytes, got {type(val)}")
        return bytes(val)

    def has(self, slot: str) -> bool:
        return self.get(slot) is not None

    def available_slots(self) -> Sequence[str]:
        return [s for s in ALL_SLOTS if self.has(s)]

    def describe(self) -> dict:
        """Non-secret inventory (lengths only). Safe to log / report."""
        inv = {}
        for s in ALL_SLOTS:
            v = self.get(s)
            inv[s] = None if v is None else {"present": True, "len": len(v)}
        return {
            "provider": type(self).__name__,
            "slots": inv,
            "available": list(self.available_slots()),
            "production_claim": False,
        }


class NullKeyProvider(KeyProvider):
    """Always empty — default for offline skeleton / dry-run."""

    def get(self, slot: str) -> Optional[bytes]:
        return None


class DictKeyProvider(KeyProvider):
    """Fixture / test provider. Values must be bytes (no str passwords in repo)."""

    def __init__(self, mapping: Optional[Mapping[str, bytes]] = None) -> None:
        self._map: Dict[str, bytes] = {}
        if mapping:
            for k, v in mapping.items():
                if v is None:
                    continue
                if not isinstance(v, (bytes, bytearray)):
                    raise TypeError(f"DictKeyProvider[{k!r}] must be bytes")
                self._map[str(k)] = bytes(v)

    def get(self, slot: str) -> Optional[bytes]:
        return self._map.get(slot)

    def set(self, slot: str, value: bytes) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
        self._map[slot] = bytes(value)

    def clear(self, slot: Optional[str] = None) -> None:
        if slot is None:
            self._map.clear()
        else:
            self._map.pop(slot, None)


class CallableKeyProvider(KeyProvider):
    """Adapter: slot -> Optional[bytes] callable (lazy inject / vault shim)."""

    def __init__(self, fn: Callable[[str], Optional[bytes]]) -> None:
        if not callable(fn):
            raise TypeError("fn must be callable")
        self._fn = fn

    def get(self, slot: str) -> Optional[bytes]:
        val = self._fn(slot)
        if val is None:
            return None
        if not isinstance(val, (bytes, bytearray)):
            raise TypeError(f"callable returned non-bytes for {slot!r}")
        return bytes(val)


@dataclass
class CompositeKeyProvider(KeyProvider):
    """First non-None wins. Useful for layering fixture over optional live inject."""

    providers: Sequence[KeyProvider] = field(default_factory=tuple)

    def get(self, slot: str) -> Optional[bytes]:
        for p in self.providers:
            v = p.get(slot)
            if v is not None:
                return v
        return None


def make_key_provider(
    source: Optional[KeyProvider | Mapping[str, bytes] | Callable[[str], Optional[bytes]]] = None,
) -> KeyProvider:
    """Normalize various inject styles into a KeyProvider."""
    if source is None:
        return NullKeyProvider()
    if isinstance(source, KeyProvider):
        return source
    if callable(source) and not isinstance(source, Mapping):
        return CallableKeyProvider(source)  # type: ignore[arg-type]
    if isinstance(source, Mapping):
        return DictKeyProvider(source)
    raise TypeError(f"unsupported key_provider source: {type(source)}")


def selftest() -> None:
    n = NullKeyProvider()
    assert n.get(SLOT_TICKET) is None
    assert n.available_slots() == []
    try:
        n.require(SLOT_TICKET, stage="AUTH")
        raise AssertionError("expected MissingKeyError")
    except MissingKeyError as e:
        assert e.slot == SLOT_TICKET and e.stage == "AUTH"
        d = e.as_dict()
        assert d["production_claim"] is False

    d = DictKeyProvider({SLOT_TICKET: b"\x01\x02", SLOT_SESSION_KEY: b"x" * 16})
    assert d.require(SLOT_TICKET) == b"\x01\x02"
    assert d.has(SLOT_SESSION_KEY)
    assert not d.has(SLOT_PROP0X14)
    desc = d.describe()
    assert desc["slots"][SLOT_TICKET]["len"] == 2
    assert desc["production_claim"] is False

    c = CallableKeyProvider(lambda s: b"zz" if s == SLOT_ZTEC_C2S else None)
    assert c.get(SLOT_ZTEC_C2S) == b"zz"
    assert make_key_provider(None).get(SLOT_TICKET) is None
    assert make_key_provider({SLOT_PASSWORD: b"no"}).has(SLOT_PASSWORD)
    print("key_provider selftest OK")


if __name__ == "__main__":
    selftest()
