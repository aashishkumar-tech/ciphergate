"""Make user-controlled strings (field paths, header names, file names) safe to display/store.

* Control characters (including ANSI escape introducers) are escaped as ``\\xNN``/``\\uNNNN``.
* Path segments that themselves look like sensitive values (emails, secrets, card numbers, phone
  numbers, IP addresses) are replaced with ``<redacted-key>`` — JSON keys and CSV headers can carry
  data too.
"""

from __future__ import annotations

from functools import lru_cache

from ciphergate.detectors.email import EmailDetector
from ciphergate.detectors.ip_address import IPAddressDetector
from ciphergate.detectors.payment_card import PaymentCardDetector
from ciphergate.detectors.phone import PhoneDetector
from ciphergate.detectors.secrets import SecretDetector
from ciphergate.models.finding import ScanItem

MAX_DISPLAY = 200
# Line/paragraph separators and bidi overrides can disguise terminal output.
_INVISIBLE = frozenset(
    chr(c)
    for c in (
        0x2028,
        0x2029,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    )
)
_PROBES = (EmailDetector(), SecretDetector(), PaymentCardDetector(), IPAddressDetector())
_PHONE = PhoneDetector()


def escape_control(text: str) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0 or ch in _INVISIBLE:
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    result = "".join(out)
    return result if len(result) <= MAX_DISPLAY else result[: MAX_DISPLAY - 3] + "..."


def _segment_is_sensitive(segment: str) -> bool:
    if not segment or segment.isdigit() or segment.startswith("#"):
        return False
    probe = ScanItem(0, None, "", None, segment)
    if any(detector.detect(probe) for detector in _PROBES):
        return True
    return any(f.confidence >= 0.5 for f in _PHONE.detect(probe))


@lru_cache(maxsize=4096)
def safe_field_path(path: str) -> str:
    if not path:
        return path
    if path.startswith("/"):
        segments = path.split("/")[1:]
        cleaned = ["<redacted-key>" if _segment_is_sensitive(s) else s for s in segments]
        return escape_control("/" + "/".join(cleaned))
    return escape_control("<redacted-key>" if _segment_is_sensitive(path) else path)
