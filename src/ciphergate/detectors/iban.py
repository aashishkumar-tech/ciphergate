"""IBAN detector: compact or space-grouped, uppercase, validated with the ISO 7064 mod-97 check.

Country-specific lengths and national formats are not checked. Lowercase forms are not matched.
"""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding
from ciphergate.models.finding import Finding, ScanItem

_IBAN_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?))"
    r"(?![0-9A-Za-z])"
)


def iban_valid(compact: str) -> bool:
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


class IbanDetector:
    id = "iban"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or len(text) < 15:
            return []
        out: list[Finding] = []
        for m in _IBAN_RE.finditer(text):
            # A following uppercase word can join a spaced match, so retry without trailing groups.
            groups = m.group(1).split(" ")
            while groups:
                if iban_valid("".join(groups)):
                    end = m.start(1) + len(" ".join(groups))
                    out.append(
                        make_finding(
                            item,
                            category="pii.bank_account",
                            detector=self.id,
                            confidence=0.9,
                            evidence=("pattern_match", "checksum_valid"),
                            span=(m.start(1), end),
                        )
                    )
                    break
                groups.pop()
        return out
