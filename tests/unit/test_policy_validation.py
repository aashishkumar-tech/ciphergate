"""Schema and semantic validation: unsafe policies must be rejected with safe, specific codes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate.errors import PolicyValidationError
from ciphergate.policy.validator import Policy, validate_policy
from tests.conftest import MINIMAL_POLICY, POLICIES

HEAD = "policy_version: 1\nname: t\n"


def codes(exc: PolicyValidationError) -> set[str]:
    return {i.code for i in exc.issues}


def rejects(policy_text: Callable[[str], Policy], text: str) -> PolicyValidationError:
    with pytest.raises(PolicyValidationError) as info:
        policy_text(text)
    return info.value


def test_all_shipped_policies_validate() -> None:
    files = sorted(POLICIES.glob("*.yml"))
    assert len(files) >= 9
    for path in files:
        result = validate_policy(path)
        assert result.valid, (path.name, [e.render() for e in result.errors])


def test_minimal_valid(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(MINIMAL_POLICY)
    assert p.name == "minimal" and p.digest.startswith("sha256:")


@pytest.mark.parametrize("version", ["2", "0", '"1"', "1.5"])
def test_unsupported_version(policy_text: Callable[[str], Policy], version: str) -> None:
    rejects(policy_text, f"policy_version: {version}\nname: t\n")


def test_unknown_keys_rejected(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(policy_text, HEAD + "setings: {strict: true}\n")
    assert "extra_forbidden" in codes(e)
    e = rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {categoris: [pii.email]}\n    action: redact\n",
    )
    assert "extra_forbidden" in codes(e)


def test_metadata_namespace_allows_extensions(policy_text: Callable[[str], Policy]) -> None:
    policy_text(HEAD + "metadata: {owner: team-x, anything: {nested: true}}\n")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment", "prod"),
        ("target_environment", "internet"),
        ("destination", "chatgpt"),
        ("domain_profile", "medical"),
    ],
)
def test_invalid_context_values(
    policy_text: Callable[[str], Policy], field: str, value: str
) -> None:
    rejects(policy_text, HEAD + f"context: {{{field}: {value}}}\n")


def test_invalid_selector_environment(policy_text: Callable[[str], Policy]) -> None:
    rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {environments: [production]}\n    action: redact\n",
    )


def test_tokenize_rejected_with_actionable_message(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {categories: [pii.email]}\n    action: tokenize\n",
    )
    assert any("token vault" in i.message for i in e.issues)


def test_unknown_action_and_category(policy_text: Callable[[str], Policy]) -> None:
    rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {categories: [pii.email]}\n    action: obliterate\n",
    )
    e = rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {categories: [pii.emial]}\n    action: redact\n",
    )
    assert "unknown_category" in codes(e)


def test_custom_category_must_be_declared(policy_text: Callable[[str], Policy]) -> None:
    rule = "rules:\n  - id: r\n    match: {categories: [acme.order]}\n    action: redact\n"
    rejects(policy_text, HEAD + rule)
    policy_text(HEAD + "custom_categories: [acme.order]\n" + rule)


def test_empty_match_rejected(policy_text: Callable[[str], Policy]) -> None:
    rejects(policy_text, HEAD + "rules:\n  - id: r\n    match: {}\n    action: redact\n")
    rejects(
        policy_text, HEAD + "rules:\n  - id: r\n    match: {categories: []}\n    action: redact\n"
    )


@pytest.mark.parametrize("conf", ["1.5", "-0.1"])
def test_invalid_confidence(policy_text: Callable[[str], Policy], conf: str) -> None:
    rejects(
        policy_text,
        HEAD + f"rules:\n  - id: r\n    match: {{min_confidence: {conf}}}\n    action: redact\n",
    )


@pytest.mark.parametrize("selector", ["'*'", "credential.*", "credential.secret"])
def test_credential_allow_rejected(policy_text: Callable[[str], Policy], selector: str) -> None:
    e = rejects(
        policy_text,
        HEAD + f"rules:\n  - id: r\n    match: {{categories: [{selector}]}}\n"
        "    action: allow\n    acknowledge_risk: true\n",
    )
    assert "credential_unsafe_action" in codes(e)


def test_credential_generalize_rejected(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {categories: [credential.secret]}"
        "\n    action: generalize\n    params: {strategy: year}\n",
    )
    assert "credential_unsafe_action" in codes(e)


def test_high_risk_allow_needs_acknowledgement(policy_text: Callable[[str], Policy]) -> None:
    rule = "rules:\n  - id: r\n    match: {categories: [pii.email]}\n    action: allow\n"
    e = rejects(policy_text, HEAD + rule)
    assert "high_risk_allow_unacknowledged" in codes(e)
    p = policy_text(HEAD + rule + "    acknowledge_risk: true\n")
    assert any("allows high-risk" in w for w in p.warnings)
    # Restricting to trusted destinations is fine without acknowledgement.
    policy_text(
        HEAD + "rules:\n  - id: r\n    match: {categories: [pii.email], destinations: "
        "[local_dev]}\n    action: allow\n"
    )
    # A pinned, non-overridable trusted destination counts as restriction.
    policy_text(HEAD + "context: {destination: local_dev}\n" + rule)


def test_field_only_allow_needs_scope(policy_text: Callable[[str], Policy]) -> None:
    rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    match: {field_names: [trace_id]}\n    action: allow\n",
    )


def test_hard_and_guardrail_cannot_allow(policy_text: Callable[[str], Policy]) -> None:
    rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    hard: true\n    match: {categories: "
        "[location.coarse]}\n    action: allow\n",
    )
    e = rejects(
        policy_text,
        HEAD + "rules:\n  - id: r\n    guardrail: true\n    match: "
        "{categories: [pii.email]}\n    action: redact\n",
    )
    assert "invalid_guardrail" in codes(e)


def test_equal_rank_conflict_rejected_with_rule_ids(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(
        policy_text,
        HEAD
        + """rules:
  - id: one
    priority: 100
    match: {categories: [pii.email]}
    action: redact
  - id: two
    priority: 100
    match: {categories: ["pii.*"]}
    action: pseudonymize
    params: {scope: field}
""",
    )
    conflict = [i for i in e.issues if i.code == "policy_conflict"]
    assert conflict and "'one'" in conflict[0].message and "'two'" in conflict[0].message


def test_equal_rank_disjoint_rules_allowed(policy_text: Callable[[str], Policy]) -> None:
    policy_text(
        HEAD
        + """rules:
  - id: one
    priority: 100
    match: {categories: [pii.email], destinations: [local_dev]}
    action: redact
  - id: two
    priority: 100
    match: {categories: [pii.email], destinations: [external_ai]}
    action: replace
    params: {value: "user@example.invalid"}
"""
    )


@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("redact", "{marker: 'removed'}"),
        ("redact", "{unknown: 1}"),
        ("replace", "{}"),
        ("replace", "{value: 'someone@gmail.com'}"),
        ("pseudonymize", "{}"),
        ("pseudonymize", "{scope: entity}"),
        ("pseudonymize", "{scope: field, key_env: 'lower-case'}"),
        ("pseudonymize", "{scope: field, prefix: 'Bad Prefix'}"),
        ("generalize", "{strategy: decade}"),
        ("generalize", "{strategy: numeric_bin, bins: [10, 5]}"),
        ("date_shift", "{max_days: 0}"),
        ("date_shift", "{max_days: 10, scope: entity}"),
        ("date_shift", "{max_days: 10, formats: ['dd-mm']}"),
        ("block", "{reason: x}"),
    ],
)
def test_invalid_action_params(
    policy_text: Callable[[str], Policy], action: str, params: str
) -> None:
    rejects(
        policy_text,
        HEAD + f"rules:\n  - id: r\n    match: {{categories: [pii.email], "
        f"destinations: [local_dev]}}\n    action: {action}\n    params: {params}\n",
    )


def test_custom_detector_regex_safety(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(
        policy_text,
        HEAD + "detectors:\n  custom:\n    - id: bad\n      category: "
        "identifier.generic\n      pattern: '(a+)+$'\n",
    )
    assert "unsafe_regex" in codes(e)


def test_report_raw_values_cannot_be_enabled(policy_text: Callable[[str], Policy]) -> None:
    rejects(policy_text, HEAD + "settings: {report_raw_values: true}\n")


def test_parse_error_tolerance_requires_explicit_action(
    policy_text: Callable[[str], Policy],
) -> None:
    rejects(policy_text, HEAD + "settings: {fail_on_parse_error: false}\n")
    policy_text(
        HEAD + "settings: {fail_on_parse_error: false, malformed_record_action: drop_record}\n"
    )


def test_external_pinned_policy_must_be_strict(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(
        policy_text, HEAD + "context: {destination: external_ai}\nsettings: {strict: false}\n"
    )
    assert "strict_required" in codes(e)


def test_transfers_require_strict_and_rescan(policy_text: Callable[[str], Policy]) -> None:
    transfer = (
        "transfers:\n  - id: t\n    from_environments: [prd]\n    to_destinations: "
        "[staging_test]\n    approval: {reviewed_by: reviewer, reference: REF-1, "
        "approved_on: 2026-01-01}\n"
    )
    rejects(policy_text, HEAD + "settings: {strict: false}\n" + transfer)
    p = policy_text(HEAD + transfer)
    assert any("transfer approval" in w for w in p.warnings)


def test_duplicate_rule_ids(policy_text: Callable[[str], Policy]) -> None:
    rule = (
        "  - id: r\n    priority: {p}\n    match: {{categories: [pii.email]}}\n    action: redact\n"
    )
    e = rejects(policy_text, HEAD + "rules:\n" + rule.format(p=1) + rule.format(p=2))
    assert "duplicate_id" in codes(e)


def test_yaml_duplicate_keys_and_aliases_rejected(policy_text: Callable[[str], Policy]) -> None:
    e = rejects(policy_text, HEAD + "name: again\n")
    assert e.code == "policy_duplicate_key"
    e = rejects(policy_text, HEAD + "metadata: &a {x: 1}\ncontext_copy: *a\n")
    assert e.code == "policy_yaml_alias"


def test_yaml_tags_cannot_construct_objects(policy_text: Callable[[str], Policy]) -> None:
    with pytest.raises(PolicyValidationError):
        policy_text(HEAD + "metadata: !!python/object/apply:os.system ['echo pwned']\n")


def test_non_mapping_and_syntax_errors(policy_text: Callable[[str], Policy]) -> None:
    with pytest.raises(PolicyValidationError):
        policy_text("- a\n- b\n")
    with pytest.raises(PolicyValidationError) as info:
        policy_text("policy_version: 1\nname: [unclosed\n")
    assert info.value.code == "policy_yaml_syntax"


def test_validation_does_not_read_datasets(tmp_path: Path) -> None:
    result = validate_policy(tmp_path / "missing.yml")
    assert not result.valid and result.errors[0].code == "policy_not_found"


def test_policy_load_is_deterministic(policy_file: Callable[[str], Policy]) -> None:
    a, b = policy_file("multi_environment.yml"), policy_file("multi_environment.yml")
    assert a.digest == b.digest
    assert [r.id for r in a.rules] == [r.id for r in b.rules]
    assert [r.level for r in a.rules] == [r.level for r in b.rules]
