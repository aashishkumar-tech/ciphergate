"""Precedence, hard constraints, fallback and context handling of the decision engine."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ciphergate.constants import Action, InputFormat, ReasonCode
from ciphergate.errors import ContextError
from ciphergate.models.finding import Finding, Location
from ciphergate.policy.context import evaluate_gates, resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.validator import Policy
from tests.conftest import ctx

HEAD = "policy_version: 1\nname: t\nrequirements: {environment: false, destination: false}\n"


def finding(
    category: str,
    *,
    field: str | None = None,
    path: str = "",
    conf: float = 0.9,
    detector: str = "field_name",
    span: tuple[int, int] | None = None,
    in_key: bool = False,
) -> Finding:
    return Finding(
        category=category,
        detector=detector,
        confidence=conf,
        evidence=("x",),
        location=Location(0, 1, path or (f"/{field}" if field else ""), span=span, in_key=in_key),
        field_name=field,
        value_type="string",
    )


def decide(
    policy: Policy,
    f: Finding,
    env: str | None = None,
    target: str | None = None,
    dest: str | None = None,
    fmt: InputFormat = InputFormat.JSON,
):
    c = resolve_context(policy, ctx(env, target, dest))
    return PolicyEngine(policy).decide(f, c, fmt)


PRECEDENCE = (
    HEAD
    + """
rules:
  - id: hard-block-cred
    hard: true
    priority: 1
    match: {categories: [credential.secret]}
    action: block
  - id: guard-prd-external
    guardrail: true
    priority: 1
    match: {environments: [prd], destinations: [external_ai], categories: ["pii.*"]}
    action: redact
  - id: field-email-allow
    priority: 1
    match:
      field_names: [contact_email]
      categories: [pii.email]
      destinations: [local_dev, external_ai]
    action: allow
    acknowledge_risk: true
  - id: context-email
    priority: 1
    match: {categories: [pii.email], destinations: [local_dev, external_ai]}
    action: replace
    params: {value: "user@example.invalid"}
  - id: category-email-low
    priority: 1
    match: {categories: [pii.email]}
    action: pseudonymize
    params: {scope: field}
  - id: category-email-high
    priority: 50
    match: {categories: [pii.email]}
    action: redact
  - id: confidence-only
    priority: 1
    match: {max_confidence: 0.3}
    action: review
  - id: broad-allow-telemetry
    priority: 9999
    match: {categories: [network.telemetry]}
    action: allow
defaults:
  pii.phone: {action: redact}
  "pii.*": {action: review}
  location.coarse: {action: allow}
"""
)


def test_hard_rule_beats_everything(policy_text: Callable[[str], Policy]) -> None:
    d = decide(policy_text(PRECEDENCE), finding("credential.secret", field="contact_email"))
    assert (d.action, d.rule_id, d.reason_code) == (
        Action.BLOCK,
        "hard-block-cred",
        ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK,
    )


def test_guardrail_beats_specific_field_allow(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PRECEDENCE)
    f = finding("pii.email", field="contact_email")
    assert decide(p, f, "prd", dest="external_ai").rule_id == "guard-prd-external"
    assert decide(p, f, "prd", dest="external_ai").reason_code == ReasonCode.ENVIRONMENT_GUARDRAIL
    # Same field, same destination, different environment -> guardrail does not apply.
    assert decide(p, f, "dev", dest="external_ai").rule_id == "field-email-allow"


def test_field_beats_context_beats_category(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PRECEDENCE)
    assert decide(p, finding("pii.email", field="contact_email"), dest="local_dev").rule_id == (
        "field-email-allow"
    )
    assert decide(p, finding("pii.email", field="email"), dest="local_dev").rule_id == (
        "context-email"
    )
    # No destination -> context rule cannot match -> category level; higher priority wins.
    d = decide(p, finding("pii.email", field="email"))
    assert d.rule_id == "category-email-high" and d.action == Action.REDACT


def test_defaults_exact_before_glob_and_fallback(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PRECEDENCE)
    assert decide(p, finding("pii.phone")).rule_id == "defaults:pii.phone"
    assert decide(p, finding("pii.address")).action == Action.REVIEW
    d = decide(p, finding("health.phi"))
    assert (
        d.action == Action.REVIEW
        and d.reason_code == (ReasonCode.NO_APPLICABLE_RULE_REQUIRES_REVIEW)
        and d.level_name == "engine_fallback"
    )


def test_confidence_only_rule(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PRECEDENCE)
    assert decide(p, finding("health.phi", conf=0.2)).rule_id == "confidence-only"


def test_confidence_threshold_reason(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "rules:\n  - id: r\n    match: {categories: [pii.email], "
        "min_confidence: 0.95}\n    action: redact\n"
    )
    d = decide(p, finding("pii.email", conf=0.5))
    assert d.action == Action.REVIEW and d.reason_code == (
        ReasonCode.CONFIDENCE_BELOW_RULE_THRESHOLD
    )


def test_fallback_block_setting(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(HEAD + "settings: {unknown_sensitive_behavior: block}\n")
    d = decide(p, finding("pii.email"))
    assert d.action == Action.BLOCK and d.reason_code == ReasonCode.NO_APPLICABLE_RULE_BLOCKS


def test_broad_allow_cannot_override_credential_constraint(
    policy_text: Callable[[str], Policy],
) -> None:
    # A field-scoped allow without categories could match credentials; engine forces block.
    p = policy_text(
        HEAD + "rules:\n  - id: allow-notes\n    priority: 10000\n    match: "
        "{field_names: [notes], destinations: [local_dev]}\n    action: allow\n"
    )
    d = decide(p, finding("credential.secret", field="notes"), dest="local_dev")
    assert d.action == Action.BLOCK
    assert d.reason_code == ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK
    assert d.overridden_rule_id == "allow-notes"


def test_high_risk_allow_to_missing_destination_becomes_review(
    policy_text: Callable[[str], Policy],
) -> None:
    p = policy_text(
        HEAD + "rules:\n  - id: r\n    match: {field_names: [email], destinations: "
        "[local_dev, approved_internal]}\n    action: allow\n"
    )
    assert decide(p, finding("pii.email", field="email"), dest="local_dev").action == Action.ALLOW


def test_unsupported_transform_locations(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "rules:\n  - id: d\n    match: {categories: [pii.email]}\n"
        "    action: drop_field\n  - id: k\n    match: {categories: [pii.phone]}\n"
        "    action: redact\n"
    )
    assert decide(p, finding("pii.email"), fmt=InputFormat.TEXT).reason_code == (
        ReasonCode.UNSUPPORTED_TRANSFORM
    )
    assert decide(p, finding("pii.phone", in_key=True)).action == Action.REVIEW


def test_missing_context_never_matches_context_rules(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "rules:\n  - id: r\n    match: {categories: [network.telemetry], "
        "environments: [dev]}\n    action: allow\n"
    )
    assert decide(p, finding("network.telemetry")).action == Action.REVIEW
    assert decide(p, finding("network.telemetry"), "dev").action == Action.ALLOW


def test_determinism(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PRECEDENCE)
    results = {
        decide(p, finding("pii.email", field="email"), dest="local_dev").rule_id for _ in range(20)
    }
    assert results == {"context-email"}


# ----------------------------------------------------------------------------- context


PINNED = """
policy_version: 1
name: pinned
context: {environment: prd, destination: external_ai, target_environment: external}
settings: {scan_json_keys: true}
"""


def test_cli_conflict_with_pinned_context_fails(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(PINNED)
    with pytest.raises(ContextError) as info:
        resolve_context(p, ctx("dev"))
    assert info.value.code == "environment_context_conflict"
    assert resolve_context(p, ctx("prd")).sources["environment"] == "policy"


def test_explicit_override_permitted_and_recorded(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        PINNED.replace(
            "target_environment: external}",
            "target_environment: external, allow_cli_override: [destination]}",
        )
    )
    c = resolve_context(p, ctx(dest="external_vendor"))
    assert str(c.destination) == "external_vendor" and c.sources["destination"] == "cli_override"
    assert any("allow_cli_override" in w for w in p.warnings)


def test_environment_does_not_imply_destination(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text("policy_version: 1\nname: t\n")
    c = resolve_context(p, ctx("prd"))
    assert c.destination is None
    gates, _ = evaluate_gates(p, c)
    assert ReasonCode.DESTINATION_REQUIRED_BUT_MISSING in {g.reason_code for g in gates}


def test_missing_required_context_gates(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text("policy_version: 1\nname: t\nrequirements: {target_environment: true}\n")
    gates, _ = evaluate_gates(p, resolve_context(p, ctx()))
    reasons = {g.reason_code for g in gates}
    assert reasons >= {
        ReasonCode.ENVIRONMENT_REQUIRED_BUT_MISSING,
        ReasonCode.TARGET_ENVIRONMENT_REQUIRED_BUT_MISSING,
        ReasonCode.DESTINATION_REQUIRED_BUT_MISSING,
    }
    assert all(g.severity == "block" for g in gates)


def test_unknown_context_requires_review_when_strict(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text("policy_version: 1\nname: t\n")
    gates, _ = evaluate_gates(p, resolve_context(p, ctx("unknown", dest="local_dev")))
    assert [(g.reason_code, g.severity) for g in gates] == [
        (ReasonCode.UNKNOWN_CONTEXT_REQUIRES_REVIEW, "review")
    ]


def test_unknown_destination_nonstrict_still_blocked(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text("policy_version: 1\nname: t\nsettings: {strict: false}\n")
    gates, _ = evaluate_gates(p, resolve_context(p, ctx("dev", dest="unknown")))
    assert ReasonCode.STRICT_POLICY_REQUIRED in {g.reason_code for g in gates}


@pytest.mark.parametrize(
    ("env", "target", "dest", "blocked"),
    [
        ("prd", "stg", "staging_test", True),
        ("prd", None, "local_dev", True),
        ("prd", "dev", "approved_internal", True),
        ("prd", "prd", "production_monitoring", False),
        ("stg", "stg", "staging_test", False),
        ("dev", "stg", "staging_test", False),
    ],
)
def test_prd_to_nonproduction_guardrail(
    policy_text: Callable[[str], Policy], env: str, target: str | None, dest: str, blocked: bool
) -> None:
    p = policy_text("policy_version: 1\nname: t\n")
    gates, _ = evaluate_gates(p, resolve_context(p, ctx(env, target, dest)))
    assert (ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED in {g.reason_code for g in gates}) is blocked


def test_transfer_approval_lifts_only_matching_context(
    policy_text: Callable[[str], Policy],
) -> None:
    p = policy_text("""
policy_version: 1
name: t
transfers:
  - id: masked-prd-to-stg
    from_environments: [prd]
    to_target_environments: [stg]
    to_destinations: [staging_test]
    approval: {reviewed_by: data-review, reference: REF-0001, approved_on: 2026-01-01}
""")
    gates, approvals = evaluate_gates(p, resolve_context(p, ctx("prd", "stg", "staging_test")))
    assert not gates and approvals == ["masked-prd-to-stg"]
    gates, approvals = evaluate_gates(p, resolve_context(p, ctx("prd", "dev", "local_dev")))
    assert ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED in {g.reason_code for g in gates}
    assert not approvals


@pytest.mark.parametrize(
    ("policy_name", "env", "target", "dest", "detector", "action", "rule_id"),
    [
        ("dev_local.yml", "dev", "dev", "local_dev", "stack_trace", Action.ALLOW,
         "keep-stack-frames"),
        # Only structural frames are kept: other proprietary.source findings still need review.
        ("dev_local.yml", "dev", "dev", "local_dev", "custom:internal", Action.REVIEW, None),
        ("developer_logs.yml", "prd", None, "production_monitoring", "stack_trace",
         Action.ALLOW, "keep-stack-frames-trusted"),
        ("developer_logs.yml", "dev", None, "approved_internal", "stack_trace", Action.ALLOW,
         "keep-stack-frames-trusted"),
        ("developer_logs.yml", "dev", None, "staging_test", "stack_trace", Action.REDACT,
         "redact-stack-frames-elsewhere"),
        ("developer_logs.yml", "prd", None, "external_ai", "stack_trace", Action.REDACT,
         "redact-stack-frames-elsewhere"),
        ("developer_logs.yml", "dev", None, "unknown", "stack_trace", Action.REDACT,
         "redact-stack-frames-elsewhere"),
        ("developer_logs.yml", "dev", None, "local_dev", "custom:internal", Action.REVIEW, None),
    ],
)  # fmt: skip
def test_starter_policy_stack_frame_rules(
    policy_file: Callable[[str], Policy],
    policy_name: str,
    env: str,
    target: str | None,
    dest: str,
    detector: str,
    action: Action,
    rule_id: str | None,
) -> None:
    p = policy_file(policy_name)
    f = finding("proprietary.source", path="/stack/frames/0", detector=detector, span=(2, 30))
    d = decide(p, f, env, target, dest, fmt=InputFormat.STACKTRACE)
    assert (d.action, d.rule_id) == (action, rule_id)


def test_stack_frame_rules_never_need_missing_destination(
    policy_file: Callable[[str], Policy],
) -> None:
    p = policy_file("developer_logs.yml")
    f = finding("proprietary.source", path="/stack/frames/0", detector="stack_trace", span=(2, 9))
    # No destination: neither destination-scoped rule may match; the run is gated anyway.
    assert decide(p, f, "dev", fmt=InputFormat.STACKTRACE).action == Action.REVIEW
