"""Date detector. Dates are classified as date of birth only with field or context evidence.

Supported shapes: ISO ``YYYY-MM-DD`` (optionally with time and offset), ``YYYY/MM/DD``,
``DD/MM/YYYY`` or ``MM/DD/YYYY`` (flagged ``ambiguous_locale``) and ``DD.MM.YYYY``. Without DOB
evidence, a date is only reported (as ``date.generic``) when ``dates_emit_generic`` is enabled.
"""

from __future__ import annotations

import datetime as dt
import re

from ciphergate.detectors.base import make_finding, preceding_context
from ciphergate.detectors.field_names import classify_field_name
from ciphergate.models.finding import Finding, ScanItem

_DATE_RE = re.compile(
    r"(?<![\d/.-])"
    r"(?:"
    r"(?P<iso>(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?)"
    r"|(?P<ymd>(?P<y2>\d{4})/(?P<m2>\d{2})/(?P<d2>\d{2}))"
    r"|(?P<amb>(?P<a1>\d{1,2})[/.](?P<a2>\d{1,2})[/.](?P<y3>\d{4}))"
    r")"
    r"(?![\d/-])"
)
_DOB_KEYWORDS = ("dob", "born", "birth", "d.o.b")


def _valid(year: int, month: int, day: int) -> bool:
    try:
        dt.date(year, month, day)
    except ValueError:
        return False
    return True


class DateDetector:
    id = "date_pattern"

    def __init__(self, emit_generic: bool = False) -> None:
        self.emit_generic = emit_generic

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or not isinstance(item.value, str) or sum(c.isdigit() for c in text) < 6:
            return []
        field_term = classify_field_name(item.field_name) if item.field_name else None
        field_is_dob = field_term is not None and field_term.category == "pii.date_of_birth"
        out: list[Finding] = []
        for m in _DATE_RE.finditer(text):
            evidence = ["pattern_match"]
            if m.group("iso"):
                ok = _valid(int(m.group("y")), int(m.group("m")), int(m.group("d")))
            elif m.group("ymd"):
                ok = _valid(int(m.group("y2")), int(m.group("m2")), int(m.group("d2")))
            else:
                a, b, y = int(m.group("a1")), int(m.group("a2")), int(m.group("y3"))
                ok = _valid(y, b, a) or _valid(y, a, b)
                if _valid(y, b, a) and _valid(y, a, b) and a != b:
                    evidence.append("ambiguous_locale")
            if not ok:
                continue
            span = (m.start(), m.end())
            if field_is_dob:
                evidence.append("field_name_context")
            elif preceding_context(text, m.start(), _DOB_KEYWORDS):
                evidence.append("context_keyword")
            else:
                if self.emit_generic:
                    out.append(
                        make_finding(
                            item,
                            category="date.generic",
                            detector=self.id,
                            confidence=0.6,
                            evidence=tuple(evidence),
                            span=span,
                        )
                    )
                continue
            out.append(
                make_finding(
                    item,
                    category="pii.date_of_birth",
                    detector=self.id,
                    confidence=0.85,
                    evidence=tuple(evidence),
                    span=span,
                )
            )
        return out
