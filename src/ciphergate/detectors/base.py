"""Detector interface and shared helpers.

Detectors only produce candidate findings (category, evidence, confidence, location). They never
decide what happens to a value; that is the policy engine's job.
"""

from __future__ import annotations

import re
from typing import Protocol

from ciphergate.models.finding import Finding, ScanItem, value_type_name

# Output shapes CipherGate itself produces. Detectors skip them so a sanitized file is not
# re-flagged by its own markers/pseudonyms.
MARKER_TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]{0,31}(?::[a-z0-9_.]{1,48})?\]")
PSEUDONYM_TOKEN_RE = re.compile(r"(?:[a-z][a-z0-9_]{0,31})?pz1_[a-z2-7]{32}")


def is_ciphergate_token(text: str) -> bool:
    return bool(MARKER_TOKEN_RE.fullmatch(text) or PSEUDONYM_TOKEN_RE.fullmatch(text))


class Detector(Protocol):
    id: str

    def detect(self, item: ScanItem) -> list[Finding]: ...


def make_finding(
    item: ScanItem,
    *,
    category: str,
    detector: str,
    confidence: float,
    evidence: tuple[str, ...],
    span: tuple[int, int] | None = None,
) -> Finding:
    return Finding(
        category=category,
        detector=detector,
        confidence=round(max(0.0, min(1.0, confidence)), 3),
        evidence=evidence,
        location=item.location(span),
        field_name=item.field_name,
        value_type=value_type_name(item.value),
    )


def preceding_context(text: str, start: int, keywords: tuple[str, ...], window: int = 24) -> bool:
    """True if a keyword occurs in the ``window`` chars before ``start`` (case-insensitive)."""
    snippet = text[max(0, start - window) : start].lower()
    return any(k in snippet for k in keywords)
