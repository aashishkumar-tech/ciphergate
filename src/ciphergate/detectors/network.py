"""Internal hostname detector (configurable suffixes such as ``.internal`` / ``.corp``)."""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding
from ciphergate.models.finding import Finding, ScanItem


class InternalHostDetector:
    id = "internal_host"

    def __init__(self, suffixes: list[str]) -> None:
        alternatives = "|".join(
            re.escape(s.lstrip(".")) for s in sorted(suffixes, key=len, reverse=True)
        )
        label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        self._regex = (
            re.compile(
                rf"(?<![\w.-])((?:{label}\.){{1,10}}(?:{alternatives})|localhost)(?![\w-]|\.\w)",
                re.IGNORECASE,
            )
            if alternatives
            else re.compile(r"(?<![\w.-])(localhost)(?![\w-]|\.\w)", re.IGNORECASE)
        )

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or not isinstance(item.value, str):
            return []
        return [
            make_finding(
                item,
                category="network.telemetry",
                detector=self.id,
                confidence=0.75,
                evidence=("pattern_match", "internal_host_suffix"),
                span=(m.start(1), m.end(1)),
            )
            for m in self._regex.finditer(text)
        ]
