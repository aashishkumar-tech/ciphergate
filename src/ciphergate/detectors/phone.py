"""Phone-like number detector with conservative, context-dependent confidence.

Locale ambiguity is high: this detector does not validate numbering plans. A leading ``+`` with
7-15 digits (E.164 length) or a common separator layout gives medium/high confidence; a bare digit
run is low confidence unless a context keyword (``phone``, ``tel``, ...) precedes it. Spans that
look like dates, IP addresses or payment cards are suppressed by the registry.
"""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding, preceding_context
from ciphergate.models.finding import Finding, ScanItem

_PHONE_RE = re.compile(
    r"(?<![\w+./:-])"
    r"(\+?\(?\d{1,4}\)?(?:[ .-]?\(?\d{1,5}\)?){1,6})"
    r"(?:\s?(?:x|ext\.?)\s?\d{1,6})?"
    r"(?![\w/:-]|\.\d)"
)
_DATE_LIKE = re.compile(r"^\d{4}[-./]\d{1,2}[-./]\d{1,2}$|^\d{1,2}[-./]\d{1,2}[-./]\d{2,4}$")
_SEPARATED = re.compile(r"^\(?\d{2,4}\)?[ .-]\d{2,5}[ .-]\d{2,5}(?:[ .-]\d{2,5})?$")
_KEYWORDS = ("phone", "tel", "mobile", "cell", "call", "fax", "sms", "whatsapp", "contact")


class PhoneDetector:
    id = "phone_pattern"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or sum(c.isdigit() for c in text) < 7:
            return []
        out: list[Finding] = []
        for m in _PHONE_RE.finditer(text):
            candidate = m.group(0)
            core = m.group(1)
            digits = re.sub(r"\D", "", core)
            if not 7 <= len(digits) <= 15 or len(set(digits)) == 1:
                continue
            if _DATE_LIKE.match(core.strip()):
                continue
            evidence = ["pattern_match"]
            if core.startswith("+"):
                confidence = 0.8 if len(digits) >= 8 else 0.55
                evidence.append("international_prefix")
            elif _SEPARATED.match(core.strip()):
                confidence = 0.6
                evidence.append("separator_layout")
            else:
                confidence = 0.3
            if preceding_context(text, m.start(), _KEYWORDS):
                confidence += 0.2
                evidence.append("context_keyword")
            if "x" in candidate.lower() or "ext" in candidate.lower():
                evidence.append("extension")
            out.append(
                make_finding(
                    item,
                    category="pii.phone",
                    detector=self.id,
                    confidence=min(confidence, 0.95),
                    evidence=tuple(evidence),
                    span=(m.start(), m.end()),
                )
            )
        return out
