"""User-configured regex detectors (validated by ``regex_safety`` at policy load time)."""

from __future__ import annotations

import re

from ciphergate.detectors.base import is_ciphergate_token, make_finding
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.models.policy import CustomDetector


class CustomRegexDetector:
    def __init__(self, spec: CustomDetector) -> None:
        self.id = f"custom:{spec.id}"
        self.category = spec.category
        self.confidence = spec.confidence
        self._regex = re.compile(spec.pattern, re.IGNORECASE if spec.ignore_case else 0)

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text:
            return []
        out: list[Finding] = []
        for m in self._regex.finditer(text):
            if m.end() == m.start() or is_ciphergate_token(m.group(0)):
                continue
            out.append(
                make_finding(
                    item,
                    category=self.category,
                    detector=self.id,
                    confidence=self.confidence,
                    evidence=("pattern_match", "custom_regex"),
                    span=(m.start(), m.end()),
                )
            )
        return out
