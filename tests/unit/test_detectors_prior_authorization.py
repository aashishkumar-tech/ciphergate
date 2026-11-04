"""Healthcare prior authorization numbers are identifiers, not credentials (regression)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ciphergate.detectors.field_names import classify_field_name
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
def test_prior_authorization_is_an_identifier(name: str) -> None:
    term = classify_field_name(name)
    assert term is not None
    assert term.category == "pii.customer_identifier"


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
    match: {categories: ["pii.*"]}
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
    assert data["claim"]["prior_authorization"] == "[REDACTED:pii.customer_identifier]"


def test_token_inside_prior_authorization_still_blocks(tmp_path: Path) -> None:
    token = "Bearer " + "TESTONLYNOTACREDENTIAL0123456789abcdef"
    status, out = run(tmp_path, token)
    assert status == "blocked"
    assert not out.exists()
