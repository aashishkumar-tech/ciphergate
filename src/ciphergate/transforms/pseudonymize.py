"""Keyed, domain-separated, versioned pseudonyms (HMAC-SHA-256). Never plain hashes.

Token format: ``<prefix>pz1_<32 lowercase base32 chars>`` (160 bits of the HMAC output).

Derivation (version ``pz1``)::

    subkey  = HMAC-SHA256(key, "ciphergate:pz1:subkey")
    domain  = "ciphergate:pz1:<namespace>:<scope label>"
    message = len(domain) || domain || type_tag || len(canonical) || canonical   (4-byte lengths)
    token   = base32(HMAC-SHA256(subkey, message))[:32]

Scope labels: ``field:<path with array indices replaced by *>``, ``category:<category>`` or
``entity:<name>``. The namespace defaults to the policy name. Canonical values are UTF-8 with a type
tag (``s`` string, ``i`` integer, ``f`` float, ``b`` boolean) so ``"123"`` and ``123`` differ.
Strings are NFC-normalised by default (``casefold_nfc`` also case-folds; ``none`` disables).

This is pseudonymization, not anonymization: equal inputs under the same key/scope link together.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import unicodedata
from typing import Any

from ciphergate.constants import PSEUDONYM_VERSION
from ciphergate.errors import TransformError
from ciphergate.models.policy import PseudonymizeParams

_INDEX_SEGMENT = re.compile(r"/\d+(?=/|$)")


def generic_field_path(path: str) -> str:
    return _INDEX_SEGMENT.sub("/*", path) or "text"


def canonical_value(value: Any, normalize: str) -> tuple[bytes, bytes]:
    if isinstance(value, bool):
        return b"b", b"1" if value else b"0"
    if isinstance(value, int):
        return b"i", str(value).encode()
    if isinstance(value, float):
        return b"f", repr(value).encode()
    if isinstance(value, str):
        text = value
        if normalize in ("nfc", "casefold_nfc"):
            text = unicodedata.normalize("NFC", text)
        if normalize == "casefold_nfc":
            text = text.casefold()
        return b"s", text.encode("utf-8")
    raise TransformError(
        "pseudonymize supports strings, numbers and booleans only", code="unsupported_value_type"
    )


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def derive_token(key: bytes, domain: str, value: Any, normalize: str) -> tuple[str, bytes]:
    subkey = hmac.new(
        key, f"ciphergate:{PSEUDONYM_VERSION}:subkey".encode(), hashlib.sha256
    ).digest()
    tag, canonical = canonical_value(value, normalize)
    message = _lp(domain.encode("utf-8")) + tag + _lp(canonical)
    digest = hmac.new(subkey, message, hashlib.sha256).digest()
    token = base64.b32encode(digest).decode("ascii").lower().rstrip("=")[:32]
    return token, digest


class CollisionTracker:
    """Detects two different inputs producing the same token within a run (no values stored)."""

    def __init__(self) -> None:
        self._seen: dict[str, bytes] = {}

    def check(self, token: str, digest: bytes) -> None:
        previous = self._seen.setdefault(token, digest)
        if previous != digest:
            raise TransformError(
                "pseudonym collision detected; refusing to continue", code="pseudonym_collision"
            )


def scope_label(params: PseudonymizeParams, category: str, field_path: str) -> str:
    if params.scope == "field":
        return f"field:{generic_field_path(field_path)}"
    if params.scope == "category":
        return f"category:{category}"
    return f"entity:{params.entity}"


def pseudonymize(
    value: Any,
    params: PseudonymizeParams,
    *,
    key: bytes,
    namespace: str,
    category: str,
    field_path: str,
    collisions: CollisionTracker | None = None,
) -> str:
    domain = f"ciphergate:{PSEUDONYM_VERSION}:{params.namespace or namespace}:" + scope_label(
        params, category, field_path
    )
    token, digest = derive_token(key, domain, value, params.normalize)
    if collisions is not None:
        collisions.check(f"{domain}|{token}", digest)
    return f"{params.prefix}{PSEUDONYM_VERSION}_{token}"
