"""MAC address detector: six hex pairs with one separator, or Cisco dotted form.

All-digit forms are medium confidence because they can be other identifiers. The all-zero and
broadcast addresses identify no device and are skipped.
"""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding
from ciphergate.models.finding import Finding, ScanItem

_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.-])"
    r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2})"
    r"(?![0-9A-Za-z:.-])"
)
_NON_DEVICE = frozenset({"0" * 12, "f" * 12})


class MacAddressDetector:
    id = "mac_address"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or len(text) < 14:
            return []
        out: list[Finding] = []
        for m in _MAC_RE.finditer(text):
            raw = m.group(1)
            if len({c for c in raw if c in ":-."}) > 1:
                continue
            compact = re.sub(r"[:.-]", "", raw).lower()
            if compact in _NON_DEVICE:
                continue
            out.append(
                make_finding(
                    item,
                    category="pii.device_identifier",
                    detector=self.id,
                    confidence=0.85 if not compact.isdigit() else 0.6,
                    evidence=("pattern_match",),
                    span=(m.start(1), m.end(1)),
                )
            )
        return out
