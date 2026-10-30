"""US Social Security number detector: dashed form, with the never-issued ranges excluded.

Bare nine-digit runs are not matched because they are indistinguishable from other identifiers.
Other countries' identifiers are not covered.
"""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding, preceding_context
from ciphergate.models.finding import Finding, ScanItem

_SSN_RE = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
_KEYWORDS = ("ssn", "social", "tax", "tin")


class SsnDetector:
    id = "ssn_pattern"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or len(text) < 11:
            return []
        out: list[Finding] = []
        for m in _SSN_RE.finditer(text):
            area, group, serial = m.groups()
            if area in ("000", "666") or area[0] == "9" or group == "00" or serial == "0000":
                continue
            evidence = ["pattern_match"]
            confidence = 0.8
            if preceding_context(text, m.start(), _KEYWORDS):
                confidence = 0.95
                evidence.append("context_keyword")
            out.append(
                make_finding(
                    item,
                    category="pii.government_id",
                    detector=self.id,
                    confidence=confidence,
                    evidence=tuple(evidence),
                    span=(m.start(), m.end()),
                )
            )
        return out
