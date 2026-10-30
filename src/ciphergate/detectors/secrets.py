"""Credential and secret detector.

Pattern families: PEM private keys (including multi-line blocks inside one value), bearer/basic
authorization values, common token formats (AWS access key IDs, GitHub, Slack, Stripe-style,
Google API keys, JWTs), URL userinfo passwords, connection-string passwords and assignment-style
``password=...`` / ``api_key: ...`` values. Spans cover the secret part only, so surrounding debug
context can be kept. Pattern detection has false negatives (e.g. base64-wrapped, split or
custom-format secrets); it is never proof that content is credential-free.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ciphergate.detectors.base import MARKER_TOKEN_RE, PSEUDONYM_TOKEN_RE, make_finding
from ciphergate.models.finding import Finding, ScanItem

PEM_BEGIN_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----")
PEM_END_RE = re.compile(r"-----END (?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?-----")


@dataclass(frozen=True, slots=True)
class _Pattern:
    name: str
    regex: re.Pattern[str]
    group: int
    confidence: float


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("bearer_token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{8,2048}=*)"), 1, 0.9),
    _Pattern(
        "basic_auth", re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{8,1024}={0,2})(?![\w])"), 1, 0.8
    ),
    _Pattern("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), 1, 0.95),
    _Pattern("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1, 0.95),
    _Pattern("github_pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"), 1, 0.95),
    _Pattern("slack_token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,200})"), 1, 0.95),
    _Pattern(
        "stripe_style_key", re.compile(r"\b([sr]k_(?:live|test)_[A-Za-z0-9]{16,128})\b"), 1, 0.9
    ),
    _Pattern("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})(?![\w-])"), 1, 0.9),
    _Pattern(
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{5,2048}\.eyJ[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{5,2048})"
        ),
        1,
        0.85,
    ),
    _Pattern(
        "url_userinfo_password",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@]{1,128}:([^\s@/]{1,256})@"),
        1,
        0.9,
    ),
    _Pattern(
        "connection_string_password",
        re.compile(r"(?i)(?<![a-z0-9_])(?:password|pwd)\s*=\s*([^;\s\"']{1,256})"),
        1,
        0.85,
    ),
    _Pattern(
        "assignment",
        re.compile(
            r"(?i)(?<![a-z0-9])"
            r"(?:(?:pg|db|mysql|admin|root|user)?password|mysql_pwd|passwd|passphrase|secret|"
            r"api[_-]?key|apikey|access[_-]?token|"
            r"refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|"
            r"access[_-]?key|token|credentials?)"
            r"(?:\\?[\"'])?\s{0,3}[:=]\s{0,3}(?:\\?[\"'])?"
            r"([^\s\"'\\,;&}]{1,512})"
        ),
        1,
        0.8,
    ),
)

_PLACEHOLDER_VALUES = frozenset(
    {"", "null", "none", "nil", "undefined", "true", "false", "redacted", "***", "******", "xxx"}
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return (
        v in _PLACEHOLDER_VALUES
        or bool(MARKER_TOKEN_RE.fullmatch(value))
        or bool(PSEUDONYM_TOKEN_RE.fullmatch(value))
        or set(v) <= {"*"}
    )


class SecretDetector:
    id = "secret_pattern"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or len(text) < 6:
            return []
        out: list[Finding] = []
        covered: list[tuple[int, int]] = []
        for begin in PEM_BEGIN_RE.finditer(text):
            closing = PEM_END_RE.search(text, begin.end())
            span = (begin.start(), closing.end() if closing else len(text))
            covered.append(span)
            out.append(self._finding(item, span, "private_key_header", 0.99))
        for pattern in _PATTERNS:
            for m in pattern.regex.finditer(text):
                start, end = m.start(pattern.group), m.end(pattern.group)
                value = m.group(pattern.group)
                if _is_placeholder(value):
                    continue
                if any(s <= start and end <= e for s, e in covered):
                    continue
                covered.append((start, end))
                out.append(self._finding(item, (start, end), pattern.name, pattern.confidence))
        return out

    def _finding(
        self, item: ScanItem, span: tuple[int, int], family: str, confidence: float
    ) -> Finding:
        return make_finding(
            item,
            category="credential.secret",
            detector=self.id,
            confidence=confidence,
            evidence=("pattern_match", f"family:{family}"),
            span=span,
        )
