"""Key material lookup for keyed transforms.

* Keys come only from the environment: the variable named by the policy (``key_env``), or a
  file whose path is in ``<key_env>_FILE`` (the Docker/Kubernetes secrets convention). Never CLI
  flags, never policy files. Setting both is refused as ambiguous.
* Key files must be regular files of at most ``MAX_KEY_FILE_BYTES``. On POSIX they must also be
  owned by the current user and not readable or writable by group/others (``0400``/``0600``);
  symlinks are followed (Kubernetes mounts secrets through them) and the target is checked.
  Windows ACLs are not inspected: a warning says so. One trailing newline is removed.
* Encoding: ``hex:<hex>`` or ``base64:<b64>`` are decoded; anything else is used as raw UTF-8 bytes.
* Minimum effective length: 32 bytes after decoding, and at least 8 distinct byte values.
* There is no fallback key. A missing/invalid key raises ``MissingKeyError`` naming only
  the variable.
* Key bytes are never included in ``repr``, logs, reports or exception messages.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import stat
import sys
from collections.abc import Mapping
from enum import StrEnum

from ciphergate.constants import MIN_KEY_BYTES
from ciphergate.errors import MissingKeyError

logger = logging.getLogger("ciphergate")

FILE_SUFFIX = "_FILE"
MAX_KEY_FILE_BYTES = 4096


class KeyStatus(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    TOO_SHORT = "too_short"
    INVALID_ENCODING = "invalid_encoding"
    LOW_DIVERSITY = "low_diversity"
    AMBIGUOUS_SOURCE = "ambiguous_source"
    FILE_UNREADABLE = "file_unreadable"
    FILE_NOT_REGULAR = "file_not_regular"
    FILE_TOO_LARGE = "file_too_large"
    FILE_INSECURE = "file_permissions_insecure"


_FILE_STATUSES = {
    KeyStatus.AMBIGUOUS_SOURCE,
    KeyStatus.FILE_UNREADABLE,
    KeyStatus.FILE_NOT_REGULAR,
    KeyStatus.FILE_TOO_LARGE,
    KeyStatus.FILE_INSECURE,
}


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


def _read_key_file(path: str) -> tuple[str | None, KeyStatus | None]:
    """Return (raw key text, None) or (None, failure status). Never raises for file problems."""
    try:
        st = os.stat(path)
    except OSError:
        return None, KeyStatus.FILE_UNREADABLE
    if not stat.S_ISREG(st.st_mode):
        return None, KeyStatus.FILE_NOT_REGULAR
    if st.st_size > MAX_KEY_FILE_BYTES:
        return None, KeyStatus.FILE_TOO_LARGE
    if sys.platform != "win32" and (st.st_mode & 0o077 or st.st_uid != os.geteuid()):
        return None, KeyStatus.FILE_INSECURE
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_KEY_FILE_BYTES + 1)
    except OSError:
        return None, KeyStatus.FILE_UNREADABLE
    if len(data) > MAX_KEY_FILE_BYTES:
        return None, KeyStatus.FILE_TOO_LARGE
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, KeyStatus.INVALID_ENCODING
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if sys.platform == "win32":
        logger.warning(
            "key file permissions are not verified on Windows; restrict its ACL to your account"
        )
    return text, None


class KeyProvider:
    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ
        self._cache: dict[str, bytes] = {}
        self._raw: dict[str, tuple[str | None, KeyStatus | None, str]] = {}

    def __repr__(self) -> str:
        return "KeyProvider(<keys not shown>)"

    def _lookup(self, name: str) -> tuple[str | None, KeyStatus | None, str]:
        """(raw key text, failure status, source) — the file is read at most once per run."""
        if name not in self._raw:
            value = self._environ.get(name) or None
            file_path = self._environ.get(name + FILE_SUFFIX) or None
            if value is not None and file_path is not None:
                self._raw[name] = (None, KeyStatus.AMBIGUOUS_SOURCE, "ambiguous")
            elif file_path is not None:
                text, failure = _read_key_file(file_path)
                self._raw[name] = (text, failure, "file")
            else:
                self._raw[name] = (value, None, "env")
        return self._raw[name]

    def source(self, name: str) -> str:
        """Where the key comes from: ``env``, ``file`` or ``ambiguous`` (never the path)."""
        return self._lookup(name)[2]

    def status(self, name: str) -> KeyStatus:
        raw, failure, _ = self._lookup(name)
        if failure is not None:
            return failure
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
            where = (
                f"key file {name}{FILE_SUFFIX}"
                if self.source(name) == "file"
                else f"key environment variable {name}"
            )
            if status == KeyStatus.AMBIGUOUS_SOURCE:
                message = f"both {name} and {name}{FILE_SUFFIX} are set; set only one"
            else:
                message = (
                    f"{where} is {status.value.replace('_', ' ')} "
                    f"(need at least {MIN_KEY_BYTES} bytes; see docs/security-and-privacy.md)"
                )
            raise MissingKeyError(
                message,
                code="key_missing"
                if status == KeyStatus.MISSING
                else ("key_file_invalid" if status in _FILE_STATUSES else "key_invalid"),
            )
        raw = self._lookup(name)[0]
        key = _decode(raw) if raw is not None else None
        if key is None:  # pragma: no cover - status() already validated the encoding
            raise MissingKeyError(f"key {name} is invalid", code="key_invalid")
        self._cache[name] = key
        return key
