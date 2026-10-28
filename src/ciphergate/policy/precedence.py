"""Deterministic precedence levels and static rule-overlap analysis.

Levels (lower number wins; the level is computed from the rule, not chosen freely):

1. Engine hard constraints (missing/invalid context, credential never allowed) — not rules.
2. ``hard: true`` rules (must not be ``allow``).
3. ``guardrail: true`` rules — environment-boundary rules (must name environments and a target
   environment or destination; must not be ``allow``).
4. Field rules — any of ``field_names`` / ``field_paths`` / ``field_regex``.
5. Context rules — any of ``environments`` / ``target_environments`` / ``destinations`` /
   ``domain_profiles`` / ``use_cases`` (and no field selector).
6. Category rules — ``categories`` / ``detectors`` / ``formats`` only.
7. Confidence-only rules — only ``min_confidence`` / ``max_confidence``.
8. Profile defaults (``defaults:`` mapping by category).
9. Engine fallback — ``settings.unknown_sensitive_behavior`` (``review`` or ``block``), never allow.

Within a level the highest ``priority`` wins. Two matching rules at the same level and priority are
only allowed when they choose the same action and parameters; otherwise validation rejects the
policy as a conflict (declaration order is never used to break a real disagreement).
"""

from __future__ import annotations

import fnmatch

from ciphergate.detectors.field_names import normalize_field_name
from ciphergate.models.policy import Rule, RuleMatch

LEVEL_HARD_CONSTRAINT = 1
LEVEL_HARD_RULE = 2
LEVEL_GUARDRAIL = 3
LEVEL_FIELD = 4
LEVEL_CONTEXT = 5
LEVEL_CATEGORY = 6
LEVEL_CONFIDENCE = 7
LEVEL_DEFAULT = 8
LEVEL_FALLBACK = 9

LEVEL_NAMES = {
    LEVEL_HARD_CONSTRAINT: "hard_constraint",
    LEVEL_HARD_RULE: "hard_rule",
    LEVEL_GUARDRAIL: "guardrail",
    LEVEL_FIELD: "field",
    LEVEL_CONTEXT: "context",
    LEVEL_CATEGORY: "category",
    LEVEL_CONFIDENCE: "confidence",
    LEVEL_DEFAULT: "profile_default",
    LEVEL_FALLBACK: "engine_fallback",
}

_FIELD_SELECTORS = ("field_names", "field_paths", "field_regex")
_CONTEXT_SELECTORS = (
    "environments",
    "target_environments",
    "destinations",
    "domain_profiles",
    "use_cases",
)
_CATEGORY_SELECTORS = ("categories", "detectors", "formats")


def rule_level(rule: Rule) -> int:
    m = rule.match
    if rule.hard:
        return LEVEL_HARD_RULE
    if rule.guardrail:
        return LEVEL_GUARDRAIL
    if any(getattr(m, s) is not None for s in _FIELD_SELECTORS):
        return LEVEL_FIELD
    if any(getattr(m, s) is not None for s in _CONTEXT_SELECTORS):
        return LEVEL_CONTEXT
    if any(getattr(m, s) is not None for s in _CATEGORY_SELECTORS):
        return LEVEL_CATEGORY
    return LEVEL_CONFIDENCE


def category_selector_matches(selector: str, category: str) -> bool:
    if selector == "*":
        return True
    if selector.endswith(".*"):
        return category.startswith(selector[:-1])
    return selector == category


def category_selectors_overlap(a: str, b: str) -> bool:
    if a == "*" or b == "*":
        return True
    if a.endswith(".*") and b.endswith(".*"):
        return a == b
    if a.endswith(".*"):
        return category_selector_matches(a, b)
    if b.endswith(".*"):
        return category_selector_matches(b, a)
    return a == b


def _sets_overlap(a: list[str] | None, b: list[str] | None) -> bool:
    if a is None or b is None:
        return True
    return bool({str(x) for x in a} & {str(x) for x in b})


def _globs_overlap(a: list[str] | None, b: list[str] | None) -> bool:
    if a is None or b is None:
        return True
    for x in a:
        for y in b:
            if x == y or fnmatch.fnmatchcase(x, y) or fnmatch.fnmatchcase(y, x):
                return True
            if any(c in x + y for c in "*?["):
                return True  # cannot prove disjoint; treat as overlapping
    return False


def matches_may_overlap(a: RuleMatch, b: RuleMatch) -> bool:
    """Conservative: returns False only when the two selectors provably cannot match together."""
    if (
        a.categories is not None
        and b.categories is not None
        and not any(category_selectors_overlap(x, y) for x in a.categories for y in b.categories)
    ):
        return False
    for name in (
        "detectors",
        "environments",
        "target_environments",
        "destinations",
        "domain_profiles",
        "use_cases",
        "formats",
    ):
        if not _sets_overlap(getattr(a, name), getattr(b, name)):
            return False
    if a.field_names is not None and b.field_names is not None:
        an = {normalize_field_name(n) for n in a.field_names}
        bn = {normalize_field_name(n) for n in b.field_names}
        no_other_field_selectors = (
            a.field_paths is None
            and b.field_paths is None
            and a.field_regex is None
            and b.field_regex is None
        )
        if not an & bn and no_other_field_selectors:
            return False
    if not _globs_overlap(a.field_paths, b.field_paths):
        return False
    lo_a, hi_a = a.min_confidence or 0.0, 1.0 if a.max_confidence is None else a.max_confidence
    lo_b, hi_b = b.min_confidence or 0.0, 1.0 if b.max_confidence is None else b.max_confidence
    return not (hi_a < lo_b or hi_b < lo_a)
