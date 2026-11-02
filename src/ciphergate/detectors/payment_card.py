"""Payment-card-like detector: 13-19 digits, Luhn-valid, scored by issuer prefix and context.

Long numeric identifiers pass Luhn roughly 10% of the time by chance, so a Luhn-valid run is
reported only with a known issuer prefix or a card keyword nearby. An issuer-prefixed run right
after an identifier word such as "invoice" or "batch id" is also skipped unless a card keyword
is present. Cards with other prefixes (for example Maestro) and no keyword are missed.
"""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding, preceding_context
from ciphergate.models.finding import Finding, ScanItem

_CARD_RE = re.compile(r"(?<![0-9A-Za-z_])(\d(?:[ -]?\d){12,18})(?![0-9A-Za-z_])")
_CVV_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:cvv2?|cvc2?)(?:\\?[\"'])?\s{0,3}[:=]\s{0,3}(?:\\?[\"'])?(\d{3,4})(?!\d)"
)
_KEYWORDS = ("card", "visa", "mastercard", "amex", "pan", "cc", "credit", "debit", "payment")
# Words that label a number as some other identifier.
_ID_WORDS = (
    "id", "invoice", "order", "batch", "total", "trace", "request", "ref", "seq", "sequence",
    "ticket", "build", "job", "txn", "transaction",
)  # fmt: skip


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def known_issuer_prefix(digits: str) -> bool:
    if digits[0] == "4" and len(digits) in (13, 16, 19):
        return True
    two, four = int(digits[:2]), int(digits[:4])
    if 51 <= two <= 55 or 2221 <= four <= 2720:
        return len(digits) == 16
    if two in (34, 37):
        return len(digits) == 15
    three = int(digits[:3])
    if digits.startswith("6011") or two == 65 or 644 <= three <= 649:
        return len(digits) in (16, 19)
    if 3528 <= four <= 3589 or two == 62:  # JCB, UnionPay
        return 16 <= len(digits) <= 19
    if 300 <= three <= 305 or two in (36, 38, 39):  # Diners Club
        return 14 <= len(digits) <= 19
    if 2200 <= four <= 2204:  # Mir
        return 16 <= len(digits) <= 19
    return False


class PaymentCardDetector:
    id = "luhn_card"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text:
            return []
        out = [
            make_finding(
                item,
                category="pii.payment_card",
                detector=self.id,
                confidence=0.85,
                evidence=("pattern_match", "context_keyword"),
                span=(m.start(1), m.end(1)),
            )
            for m in _CVV_RE.finditer(text)
        ]
        if sum(c.isdigit() for c in text) < 13:
            return out
        for m in _CARD_RE.finditer(text):
            raw = m.group(1)
            digits = raw.replace(" ", "").replace("-", "")
            if not 13 <= len(digits) <= 19 or len(set(digits)) == 1 or not luhn_valid(digits):
                continue
            seps = {c for c in raw if c in " -"}
            if len(seps) > 1:
                continue
            issuer = known_issuer_prefix(digits)
            keyword = preceding_context(text, m.start(), _KEYWORDS, window=32)
            if not keyword and (
                not issuer or preceding_context(text, m.start(), _ID_WORDS, window=16)
            ):
                continue
            evidence = ["pattern_match", "checksum_valid"]
            confidence = 0.4
            if issuer:
                confidence = 0.8
                evidence.append("issuer_prefix")
            if keyword:
                confidence += 0.15
                evidence.append("context_keyword")
            out.append(
                make_finding(
                    item,
                    category="pii.payment_card",
                    detector=self.id,
                    confidence=min(confidence, 0.95),
                    evidence=tuple(evidence),
                    span=(m.start(1), m.end(1)),
                )
            )
        return out
