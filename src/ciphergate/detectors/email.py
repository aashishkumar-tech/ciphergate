"""Email-like address detector (ASCII local parts and domains; bounded regex)."""

from __future__ import annotations

import re

from ciphergate.detectors.base import make_finding
from ciphergate.models.finding import Finding, ScanItem

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]{1,64})@((?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9-])"
)
# Percent-encoded form in URLs and query strings: the "@" is written as %40.
_ENCODED_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]{1,64})%40((?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9-])"
)

RESERVED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
RESERVED_EMAIL_TLDS = (".invalid", ".example", ".test", ".localhost")


def is_reserved_email_domain(domain: str) -> bool:
    d = domain.lower()
    return (
        d in RESERVED_EMAIL_DOMAINS
        or any(d.endswith(t) or d == t[1:] for t in RESERVED_EMAIL_TLDS)
        or any(d.endswith("." + r) for r in RESERVED_EMAIL_DOMAINS)
    )


class EmailDetector:
    id = "email_regex"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or ("@" not in text and "%40" not in text):
            return []
        out: list[Finding] = []
        for m in (*_EMAIL_RE.finditer(text), *_ENCODED_EMAIL_RE.finditer(text)):
            local, domain = m.group(1), m.group(2)
            if local.startswith(".") or local.endswith(".") or ".." in local or ".." in domain:
                continue
            if any(label.startswith("-") or label.endswith("-") for label in domain.split(".")):
                continue
            evidence = ["pattern_match"]
            if is_reserved_email_domain(domain):
                evidence.append("reserved_domain")
            out.append(
                make_finding(
                    item,
                    category="pii.email",
                    detector=self.id,
                    confidence=0.9,
                    evidence=tuple(evidence),
                    span=(m.start(), m.end()),
                )
            )
        return out
