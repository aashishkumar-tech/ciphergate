"""Keyed date shifting that preserves intervals within a scope.

Offsets are derived with HMAC-SHA-256 from the key and a scope value, in ``[-max_days, -1]`` or
``[1, max_days]`` (never zero):

* ``scope: dataset`` — one offset for the whole run (all relationships preserved).
* ``scope: entity`` — one offset per value of ``entity_field`` in the same record (per-subject
  consistency; structured formats only).

Supported inputs: ``iso`` (``YYYY-MM-DD``, ``YYYY-MM-DD[T ]HH:MM[:SS[.ffffff]][Z|±HH:MM]``) or
explicit ``strptime`` patterns. Fixed UTC offsets are preserved as written; named time zones and
epoch integers are not supported. Leap days are handled by calendar arithmetic (Feb 29 + 1 day =
Mar 1). Unparseable or out-of-range values raise ``TransformError``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
from typing import Any

from ciphergate.errors import TransformError
from ciphergate.models.policy import DateShiftParams
from ciphergate.transforms.pseudonymize import canonical_value

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?$"
)


def derive_offset_days(key: bytes, namespace: str, scope_value: Any, max_days: int) -> int:
    tag, canonical = canonical_value(scope_value, "nfc")
    message = f"ciphergate:dateshift:v1:{namespace}".encode() + b"\x00" + tag + b"\x00" + canonical
    digest = hmac.new(key, message, hashlib.sha256).digest()
    n = int.from_bytes(digest[:8], "big") % (2 * max_days)
    return n - max_days if n < max_days else n - max_days + 1


def _fail() -> TransformError:
    return TransformError(
        "date_shift cannot parse a value with the configured formats", code="date_shift_unparseable"
    )


def shift_date_text(text: str, offset_days: int, formats: list[str]) -> str:
    delta = dt.timedelta(days=offset_days)
    stripped = text.strip()
    for fmt in formats:
        try:
            if fmt == "iso":
                if _ISO_DATE.match(stripped):
                    return (dt.date.fromisoformat(stripped) + delta).isoformat()
                if _ISO_DATETIME.match(stripped):
                    parsed = dt.datetime.fromisoformat(stripped.replace("Z", "+00:00"))
                    sep = "T" if "T" in stripped else " "
                    out = (parsed + delta).isoformat(sep=sep)
                    if stripped.endswith("Z"):
                        out = out.removesuffix("+00:00") + "Z"
                    return out
                continue
            parsed = dt.datetime.strptime(stripped, fmt)
            return (parsed + delta).strftime(fmt)
        except ValueError:
            continue
        except OverflowError:
            raise TransformError(
                "date_shift result is outside the supported date range",
                code="date_shift_out_of_range",
            ) from None
    raise _fail()


def date_shift(value: Any, params: DateShiftParams, *, offset_days: int) -> str:
    if not isinstance(value, str):
        raise _fail()
    return shift_date_text(value, offset_days, params.formats)
