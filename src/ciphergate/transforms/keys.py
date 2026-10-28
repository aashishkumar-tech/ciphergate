"""Key material lookup for keyed transforms.

* Keys come only from named environment variables (never CLI flags, never policy files).
* Encoding: ``hex:<hex>`` or ``base64:<b64>`` are decoded; anything else is used as raw UTF-8 bytes.
* Minimum effective length: 32 bytes after decoding, and at least 8 distinct byte values.
* There is no fallback key. A missing/invalid key raises ``MissingKeyError`` naming only
  the variable.
* Key bytes are never included in ``repr``, logs, reports or exception messages.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from enum import StrEnum

from ciphergate.constants import MIN_KEY_BYTES
from ciphergate.errors import MissingKeyError


class KeyStatus(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    TOO_SHORT = "too_short"
    INVALID_ENCODING = "invalid_encoding"
    LOW_DIVERSITY = "low_diversity"


def _decode(raw: str) -> bytes | None:
    if raw.startswith("hex:"):
        try:
            return bytes.fromhex(raw[4:].strip())
        except ValueError:
            return None
    if raw.startswith("base64:"):
        try:
            return base64.b64decode(raw[7:].strip(), validate=True)
        except (binascii.Error, ValueError):
            return None
    return raw.encode("utf-8")


class KeyProvider:
    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ
        self._cache: dict[str, bytes] = {}

    def __repr__(self) -> str:
        return "KeyProvider(<keys not shown>)"

    def status(self, name: str) -> KeyStatus:
        raw = self._environ.get(name)
        if raw is None or raw == "":
            return KeyStatus.MISSING
        key = _decode(raw)
        if key is None:
            return KeyStatus.INVALID_ENCODING
        if len(key) < MIN_KEY_BYTES:
            return KeyStatus.TOO_SHORT
        if len(set(key)) < 8:
            return KeyStatus.LOW_DIVERSITY
        return KeyStatus.AVAILABLE

    def get(self, name: str) -> bytes:
        if name in self._cache:
            return self._cache[name]
        status = self.status(name)
        if status != KeyStatus.AVAILABLE:
            raise MissingKeyError(
                f"key environment variable {name} is {status.value.replace('_', ' ')} "
                f"(need at least {MIN_KEY_BYTES} bytes; see docs/security-and-privacy.md)",
                code="key_missing" if status == KeyStatus.MISSING else "key_invalid",
            )
        key = _decode(self._environ[name])
        if key is None:  # pragma: no cover - status() already validated the encoding
            raise MissingKeyError(f"key environment variable {name} is invalid", code="key_invalid")
        self._cache[name] = key
        return key
