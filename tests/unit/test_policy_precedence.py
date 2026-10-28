"""Static overlap analysis, rule levels and remaining validator/loader branches."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate.errors import PolicyValidationError
from ciphergate.models.policy import Rule, RuleMatch
from ciphergate.policy.loader import MAX_POLICY_BYTES, parse_policy_yaml, read_policy_bytes
from ciphergate.policy.precedence import (
    LEVEL_CATEGORY,
    LEVEL_CONFIDENCE,
    LEVEL_CONTEXT,
    LEVEL_FIELD,
    LEVEL_GUARDRAIL,
    LEVEL_HARD_RULE,
    category_selector_matches,
    category_selectors_overlap,
    matches_may_overlap,
    rule_level,
)
from ciphergate.policy.validator import Policy, validate_policy


def m(**kw: object) -> RuleMatch:
    return RuleMatch(**kw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("match", "extra", "level"),
    [
        ({"categories": ["pii.email"]}, {"hard": True}, LEVEL_HARD_RULE),
        (
            {"categories": ["pii.email"], "environments": ["prd"], "destinations": ["external_ai"]},
            {"guardrail": True},
            LEVEL_GUARDRAIL,
        ),
        ({"field_paths": ["/a"]}, {}, LEVEL_FIELD),
        ({"field_regex": "^/a"}, {}, LEVEL_FIELD),
        ({"use_cases": ["debugging"]}, {}, LEVEL_CONTEXT),
        ({"formats": ["csv"]}, {}, LEVEL_CATEGORY),
        ({"detectors": ["email_regex"]}, {}, LEVEL_CATEGORY),
        ({"min_confidence": 0.5}, {}, LEVEL_CONFIDENCE),
    ],
)
def test_rule_levels(match: dict, extra: dict, level: int) -> None:
    rule = Rule(id="r", match=m(**match), action="redact", **extra)  # type: ignore[arg-type]
    assert rule_level(rule) == level


@pytest.mark.parametrize(
    ("a", "b", "overlap"),
    [
        ("*", "pii.email", True),
        ("pii.*", "pii.*", True),
        ("pii.*", "health.*", False),
        ("pii.*", "pii.email", True),
        ("pii.email", "pii.*", True),
        ("health.phi", "pii.*", False),
        ("pii.email", "pii.phone", False),
    ],
)
def test_category_overlap(a: str, b: str, overlap: bool) -> None:
    assert category_selectors_overlap(a, b) is overlap


def test_category_selector_matches() -> None:
    assert category_selector_matches("*", "x.y")
    assert category_selector_matches("pii.*", "pii.email")
    assert not category_selector_matches("pii.*", "piiz.email")


@pytest.mark.parametrize(
    ("a", "b", "overlap"),
    [
        ({"categories": ["pii.email"]}, {"categories": ["pii.phone"]}, False),
        ({"environments": ["dev"]}, {"environments": ["prd"]}, False),
        ({"environments": ["dev"]}, {"categories": ["pii.email"]}, True),
        ({"field_names": ["email"]}, {"field_names": ["phone"]}, False),
        ({"field_names": ["eMail"]}, {"field_names": ["e_mail"]}, True),
        ({"field_names": ["email"], "field_regex": "x"}, {"field_names": ["phone"]}, True),
        ({"field_paths": ["/a"]}, {"field_paths": ["/b"]}, False),
        ({"field_paths": ["/a/*"]}, {"field_paths": ["/b"]}, True),
        ({"field_paths": ["/a"]}, {"field_paths": ["/a"]}, True),
        ({"min_confidence": 0.8}, {"max_confidence": 0.5}, False),
        ({"min_confidence": 0.4}, {"max_confidence": 0.5}, True),
    ],
)
def test_matches_may_overlap(a: dict, b: dict, overlap: bool) -> None:
    assert matches_may_overlap(m(**a), m(**b)) is overlap


HEAD = "policy_version: 1\nname: t\n"


def bad(policy_text: Callable[[str], Policy], text: str) -> set[str]:
    with pytest.raises(PolicyValidationError) as info:
        policy_text(HEAD + text)
    return {i.code for i in info.value.issues}


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("custom_categories: [Bad]\n", "invalid_value"),
        ("custom_categories: [pii.email]\n", "invalid_value"),
        (
            "rules:\n  - id: r\n    match: {categories: ['pii.']}\n    action: redact\n",
            "invalid_selector",
        ),
        (
            "rules:\n  - id: r\n    match: {categories: ['zzz.*']}\n    action: redact\n",
            "unknown_category",
        ),
        (
            "rules:\n  - id: r\n    match: {detectors: [nope]}\n    action: redact\n",
            "unknown_detector",
        ),
        (
            "rules:\n  - id: r\n    match: {field_regex: '(a+)+'}\n    action: redact\n",
            "unsafe_regex",
        ),
        ("detectors: {disabled: [nope]}\n", "unknown_detector"),
        (
            "detectors:\n  custom:\n"
            "    - {id: a, category: identifier.generic, pattern: 'A-[0-9]{3}'}"
            "\n    - {id: a, category: identifier.generic, pattern: 'B-[0-9]{3}'}\n",
            "duplicate_id",
        ),
        ("classifications:\n  - {id: c, field_names: [x], category: nope.x}\n", "unknown_category"),
        (
            "classifications:\n  - {id: c, field_names: [x], category: pii.email}\n"
            "  - {id: c, field_names: [y], category: pii.email}\n",
            "duplicate_id",
        ),
        ("defaults:\n  pii.email: {action: allow}\n", "unsafe_allow"),
        (
            "defaults:\n  credential.secret: {action: generalize, params: {strategy: year}}\n",
            "credential_unsafe_action",
        ),
        (
            "defaults:\n  pii.email: {action: replace, params: {value: 'a@gmail.com'}}\n",
            "unsafe_replacement",
        ),
        ("settings: {rescan: {fail_on_categories: [nope.x]}}\n", "unknown_category"),
        (
            "context: {destination: external_ai}\nsettings: {rescan: {enabled: false}}\n",
            "rescan_required",
        ),
        (
            "rules:\n  - id: r\n    hard: true\n    guardrail: true\n    match: {categories: "
            "[pii.email], environments: [prd], destinations: [external_ai]}\n    action: block\n",
            "invalid_value",
        ),
        (
            "transfers:\n  - id: t\n    from_environments: [prd]\n"
            "    to_destinations: [local_dev]\n"
            "    approval: {reviewed_by: r, reference: x, approved_on: 2026-01-01}\n"
            "  - id: t\n    from_environments: [prd]\n    to_destinations: [local_dev]\n"
            "    approval: {reviewed_by: r, reference: x, approved_on: 2026-01-01}\n",
            "duplicate_id",
        ),
    ],
)
def test_semantic_rejections(policy_text: Callable[[str], Policy], text: str, code: str) -> None:
    assert code in bad(policy_text, text)


def test_warnings(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "settings: {strict: false}\ndetectors: {disabled: [secret_pattern]}\n"
        "rules:\n  - id: r\n    match: {categories: [pii.email]}\n    action: redact\n"
        "    acknowledge_risk: true\n"
    )
    text = " ".join(p.warnings)
    assert "strict is false" in text and "disabled" in text and "no effect" in text


def test_default_specificity_order(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "defaults:\n  '*': {action: review}\n  pii.*: {action: redact}\n"
        "  pii.email: {action: replace, params: {value: 'u@example.invalid'}}\n"
    )
    assert [d.selector for d in p.defaults] == ["pii.email", "pii.*", "*"]
    assert p.default_for("pii.email").selector == "pii.email"  # type: ignore[union-attr]
    assert p.default_for("health.phi").selector == "*"  # type: ignore[union-attr]
    assert "u@example.invalid" in p.replacement_values


def test_loader_limits(tmp_path: Path) -> None:
    big = tmp_path / "big.yml"
    big.write_bytes(b"#" * (MAX_POLICY_BYTES + 1))
    with pytest.raises(PolicyValidationError) as info:
        read_policy_bytes(big)
    assert info.value.code == "policy_too_large"
    with pytest.raises(PolicyValidationError):
        read_policy_bytes(tmp_path)  # directory
    with pytest.raises(PolicyValidationError) as info:
        parse_policy_yaml(b"\xff\xfe")
    assert info.value.code == "policy_encoding"
    with pytest.raises(PolicyValidationError):
        parse_policy_yaml(b"{[1, 2]: x}")
    with pytest.raises(PolicyValidationError):
        parse_policy_yaml(b"a" * (MAX_POLICY_BYTES + 1))


def test_validate_policy_on_compiled(policy_file: Callable[[str], Policy]) -> None:
    p = policy_file("dev_local.yml")
    assert validate_policy(p).valid
