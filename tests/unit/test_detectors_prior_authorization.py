"""Healthcare prior authorization numbers are health data, not credentials (regression)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.detectors.field_names import classify_field_name
from ciphergate.models.context import ContextInput
from ciphergate.pipeline.sanitizer import sanitize_file
from ciphergate.policy.validator import load_policy_text


@pytest.mark.parametrize(
    "name",
    [
        "prior_authorization",
        "priorAuthorization",
        "preAuthorization",
        "pre-authorization",
        "preauthorization",
        "claim_prior_authorization",
        "prior_auth",
    ],
)
def test_prior_authorization_is_health_data(name: str) -> None:
    term = classify_field_name(name)
    assert term is not None
    # Not pii.customer_identifier: shipped templates allow that category (local_debug).
    assert term.category == "health.phi"


@pytest.mark.parametrize(
    "name", ["requires_prior_auth", "needsPreAuth", "skip-pre-auth", "prior_auth_required"]
)
def test_prior_auth_flags_are_not_matched(name: str) -> None:
    assert classify_field_name(name) is None


@pytest.mark.parametrize(
    "name",
    ["authorization", "Authorization", "http_authorization", "proxyAuthorization", "x_api_key"],
)
def test_authorization_headers_stay_credentials(name: str) -> None:
    term = classify_field_name(name)
    assert term is not None
    assert term.category == "credential.secret"


POLICY = """
policy_version: 1
name: claims
context: {environment: prd, target_environment: external, destination: external_ai}
settings: {scan_json_keys: true}
rules:
  - id: block-secrets
    hard: true
    priority: 1000
    match: {categories: [credential.secret]}
    action: block
    reason: no_secrets
  - id: redact-ids
    priority: 200
    match: {categories: ["pii.*", health.phi]}
    action: redact
    reason: remove_identifier
"""


def run(tmp_path: Path, value: str) -> tuple[str, Path]:
    source = tmp_path / "claim.json"
    source.write_text(json.dumps({"claim": {"prior_authorization": value}}), encoding="utf-8")
    out = tmp_path / "out.json"
    report = sanitize_file(source, out, load_policy_text(POLICY))
    return str(report.status), out


def test_prior_authorization_number_is_redacted_not_blocked(tmp_path: Path) -> None:
    status, out = run(tmp_path, "PA-TEST-0001")
    assert status == "sanitized"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["claim"]["prior_authorization"] == "[REDACTED:health.phi]"


def test_token_inside_prior_authorization_still_blocks(tmp_path: Path) -> None:
    token = "Bearer " + "TESTONLYNOTACREDENTIAL0123456789abcdef"
    status, out = run(tmp_path, token)
    assert status == "blocked"
    assert not out.exists()


REPO = Path(__file__).resolve().parents[2]


def test_local_debug_does_not_keep_opaque_value_in_pre_authorization(tmp_path: Path) -> None:
    # local_debug allows customer identifiers; a pre authorization field must not reach that rule.
    opaque = "TESTONLYOPAQUEVALUE7f3a9c2e"  # no recognised secret shape
    source = tmp_path / "events.json"
    source.write_text(json.dumps({"payment": {"x_pre_authorization": opaque}}), encoding="utf-8")
    out = tmp_path / "out.json"
    policy = load_policy(REPO / "policies" / "local_debug.yml")
    report = sanitize_file(source, out, policy, ContextInput(environment="dev"))
    assert str(report.status) == "sanitized"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["payment"]["x_pre_authorization"] == "[REDACTED:health.phi]"
    assert opaque not in out.read_text(encoding="utf-8")
