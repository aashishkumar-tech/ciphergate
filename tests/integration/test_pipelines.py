"""End-to-end pipeline behaviour per format via the Python API."""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import (
    RunStatus,
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.errors import InputFormatError, OutputWriteError, TransformError
from ciphergate.policy.validator import Policy
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import EXAMPLES, MINIMAL_POLICY, ctx

Write = Callable[[str, str | bytes], Path]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_inspect_and_plan_never_write(tmp_path: Path, policy_file: Callable[[str], Policy]) -> None:
    src = EXAMPLES / "sample.csv"
    before = digest(src)
    listing = set(tmp_path.iterdir())
    p = policy_file("developer_logs.yml")
    r1 = inspect_file(src, p, ctx("dev", dest="local_dev"))
    r2 = plan_file(src, p, ctx("dev", dest="local_dev"))
    assert digest(src) == before and set(tmp_path.iterdir()) == listing
    assert r1.status == r2.status == RunStatus.READY
    assert r1.summary["by_action"] == r2.summary["by_action"]


def test_plan_matches_apply(
    tmp_path: Path, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    p = policy_file("prd_external_ai.yml")
    src = EXAMPLES / "sample.csv"
    plan = plan_file(src, p, keys=keys)
    out = tmp_path / "o.csv"
    result = sanitize_file(src, out, p, options=SanitizeOptions(keys=keys))
    assert result.status == RunStatus.SANITIZED and out.exists()
    assert plan.summary["by_action"] == result.summary["by_action"]
    assert result.rescan is not None and not result.rescan.failed


def test_no_apply_writes_nothing(tmp_path: Path, policy_file: Callable[[str], Policy]) -> None:
    out = tmp_path / "o.csv"
    r = sanitize_file(
        EXAMPLES / "sample.csv",
        out,
        policy_file("developer_logs.yml"),
        ctx("dev", dest="local_dev"),
        SanitizeOptions(apply=False),
    )
    assert not out.exists() and r.output["withheld_reason"] == "apply_not_set"


def test_csv_pipeline(
    tmp_path: Path, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    src = EXAMPLES / "sample.csv"
    before = digest(src)
    out = tmp_path / "o.csv"
    sanitize_file(src, out, policy_file("prd_external_ai.yml"), options=SanitizeOptions(keys=keys))
    assert digest(src) == before
    rows = list(csv.DictReader(out.open(encoding="utf-8", newline="")))
    original = list(csv.DictReader(src.open(encoding="utf-8", newline="")))
    assert list(rows[0].keys()) == list(original[0].keys())
    assert len(rows) == len(original)
    assert rows[0]["email"].startswith("email_pz1_")
    assert rows[0]["full_name"] == "[REDACTED:pii.person_name]"
    assert rows[0]["birth_date"] == "1990"
    assert rows[0]["created_at"] == original[0]["created_at"]  # untouched
    assert rows[2]["phone"] == ""  # empty stays empty
    # Same email inside message gets the same pseudonym (category scope): joins preserved.
    assert rows[0]["email"] in rows[0]["message"]
    assert rows[2]["message"] == original[2]["message"]


def test_csv_drop_field_and_record(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: drop-ssn\n    priority: 500\n    match: {field_names: [ssn], "
            "categories: [pii.government_id]}\n    action: drop_field\n  - id: drop-card\n    "
            "priority: 500\n    match: {categories: [pii.payment_card]}\n    action: drop_record\n",
        )
    )
    src = write("in.csv", "id,ssn,note\n1,000-00-0000,ok\n2,,card 4111 1111 1111 1111\n3,x,ok\n")
    out = tmp_path / "o.csv"
    r = sanitize_file(src, out, p)
    assert out.read_text(encoding="utf-8").splitlines() == ["id,note", "1,ok", "3,ok"]
    assert r.changes["dropped_columns"] == ["ssn"] and r.changes["records_dropped"] == 1
    assert r.changes["schema_changed"]


def test_json_pipeline_types_preserved(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    src = EXAMPLES / "sample.json"
    out = tmp_path / "o.json"
    r = sanitize_file(src, out, policy_file("developer_logs.yml"), ctx("dev", dest="external_ai"))
    assert r.status == RunStatus.SANITIZED
    data = json.loads(out.read_text(encoding="utf-8"))
    original = json.loads(src.read_text(encoding="utf-8"))
    u = data["users"][0]
    assert u["email"] == "[REDACTED:pii.email]"
    assert u["orders"] == 3 and u["active"] is True and u["notes"] is None
    assert data["users"][1]["orders"] == 0 and data["users"][1]["notes"] == ""
    assert data["service"] == original["service"]
    assert "[REDACTED:network.telemetry]" in data["message"]


def test_json_drop_field_and_keys(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "settings: {strict: false}", "settings: {strict: false, scan_json_keys: true}"
        ).replace(
            "rules:\n",
            "rules:\n  - id: drop-email\n    priority: 500\n    "
            "match: {categories: [pii.email]}\n    action: drop_field\n",
        )
    )
    src = write(
        "in.json",
        json.dumps({"a": {"emails": ["x@example.com"], "keep": 1}, "alice@example.com": {"n": 1}}),
    )
    out = tmp_path / "o.json"
    r = sanitize_file(src, out, p)
    assert json.loads(out.read_text(encoding="utf-8")) == {"a": {"keep": 1}}
    assert all("alice" not in str(i) for i in r.items)


def test_json_single_document_drop_record_requires_review(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: d\n    priority: 500\n"
            "    match: {categories: [pii.email]}\n"
            "    action: drop_record\n",
        )
    )
    out = tmp_path / "o.json"
    r = sanitize_file(write("in.json", '{"email": "x@example.com"}'), out, p)
    assert r.status == RunStatus.REVIEW_REQUIRED and not out.exists()


def test_jsonl_pipeline(tmp_path: Path, policy_file: Callable[[str], Policy]) -> None:
    out = tmp_path / "o.jsonl"
    r = sanitize_file(EXAMPLES / "sample.jsonl", out, policy_file("external_ai.yml"), ctx("prd"))
    assert r.status == RunStatus.SANITIZED
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 3
    assert lines[0]["msg"] == "Payment declined for [REDACTED:pii.email]"
    assert lines[1]["latency_ms"] == 1532 and lines[2]["retry"] is False


def test_jsonl_malformed_fails_or_drops(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    src = write("in.jsonl", '{"a": 1}\n{oops\n{"a": 2}\n')
    with pytest.raises(InputFormatError):
        sanitize_file(src, tmp_path / "o.jsonl", policy_text(MINIMAL_POLICY))
    assert not (tmp_path / "o.jsonl").exists()
    tolerant = policy_text(
        MINIMAL_POLICY.replace(
            "settings: {strict: false}",
            "settings: {strict: false, fail_on_parse_error: false, malformed_record_action: "
            "drop_record}",
        )
    )
    r = sanitize_file(src, tmp_path / "o.jsonl", tolerant)
    assert (tmp_path / "o.jsonl").read_text(encoding="utf-8") == '{"a": 1}\n{"a": 2}\n'
    assert r.changes["malformed_records_dropped"] == 1
    assert r.parse_errors == [{"line": 2, "code": "json_syntax"}]


def test_text_pipeline_keeps_context(tmp_path: Path, policy_file: Callable[[str], Policy]) -> None:
    out = tmp_path / "o.log"
    src = EXAMPLES / "sample.log"
    r = sanitize_file(src, out, policy_file("developer_logs.yml"), ctx("dev", dest="local_dev"))
    assert r.status == RunStatus.SANITIZED
    text = out.read_text(encoding="utf-8")
    assert "db_password=[REDACTED:credential.secret]" in text
    assert "Bearer [REDACTED:credential.secret]" in text
    assert "TEST_ONLY" not in text and "alice.test" not in text
    assert "10.0.12.7" in text  # allowed for local debugging
    assert text.count("\n") == src.read_text(encoding="utf-8").count("\n")


def test_text_private_key_block(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    src = write(
        "k.log",
        "start\n-----BEGIN PRIVATE KEY-----\nTESTONLYBODY1\nTESTONLYBODY2\n"
        "-----END PRIVATE KEY-----\nend\n",
    )
    out = tmp_path / "o.log"
    sanitize_file(src, out, policy_text(MINIMAL_POLICY))
    assert out.read_text(encoding="utf-8").splitlines() == ["start"] + [
        "[REDACTED:credential.secret]"
    ] * 4 + ["end"]


def test_missing_key_fails_without_output(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    out = tmp_path / "o.csv"
    p = policy_file("prd_external_ai.yml")
    r = plan_file(EXAMPLES / "sample.csv", p, keys=KeyProvider({}))
    assert r.status == RunStatus.CONFIGURATION_REQUIRED and r.exit_code == 6
    assert r.keys == [
        {"key_env": "CIPHERGATE_HMAC_KEY", "status": "missing", "transform_version": "pz1"}
    ]
    r = sanitize_file(
        EXAMPLES / "sample.csv", out, p, options=SanitizeOptions(keys=KeyProvider({}))
    )
    assert r.status == RunStatus.CONFIGURATION_REQUIRED and not out.exists()


def test_key_change_changes_pseudonyms(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    import secrets

    p = policy_file("prd_external_ai.yml")
    outputs = []
    for i, key in enumerate(
        ["hex:" + secrets.token_hex(32)] * 2 + ["hex:" + secrets.token_hex(32)]
    ):
        out = tmp_path / f"o{i}.csv"
        sanitize_file(
            EXAMPLES / "sample.csv",
            out,
            p,
            options=SanitizeOptions(keys=KeyProvider({"CIPHERGATE_HMAC_KEY": key})),
        )
        outputs.append(out.read_text(encoding="utf-8"))
        assert key[4:] not in outputs[-1]
    assert outputs[0] == outputs[1] != outputs[2]


def test_existing_output_not_overwritten(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    out = tmp_path / "o.csv"
    out.write_text("previous", encoding="utf-8")
    p = policy_file("developer_logs.yml")
    with pytest.raises(OutputWriteError):
        sanitize_file(EXAMPLES / "sample.csv", out, p, ctx("dev", dest="local_dev"))
    assert out.read_text(encoding="utf-8") == "previous"
    sanitize_file(
        EXAMPLES / "sample.csv", out, p, ctx("dev", dest="local_dev"), SanitizeOptions(force=True)
    )
    assert out.read_text(encoding="utf-8").startswith("user_id,")


def test_transform_error_leaves_no_output(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: g\n    priority: 500\n"
            "    match: {categories: [pii.date_of_birth]}\n"
            "    action: generalize\n    params: {strategy: "
            "age_band}\n",
        )
    )
    out = tmp_path / "o.csv"
    with pytest.raises(TransformError):
        sanitize_file(write("in.csv", "dob\n1990-01-01\n"), out, p)
    assert not out.exists() and not list(tmp_path.glob(".ciphergate-*"))


def test_rescan_strict_fails_on_raw_input(policy_file: Callable[[str], Policy]) -> None:
    p = policy_file("prd_external_ai.yml")
    r = rescan_file(EXAMPLES / "sample.csv", p)
    assert r.status == RunStatus.RESCAN_FAILED and r.exit_code == 7
    assert r.rescan is not None and r.rescan.gating_by_category.get("pii.email")
    r = rescan_file(EXAMPLES / "sample.csv", p, strict=False)
    assert r.status == RunStatus.PASSED and r.warnings


def test_rescan_gate_withholds_output(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    # The replacement constant contains text a custom detector flags; the rescan of the temp
    # output finds a gating residual that is not exactly a recognised output -> withheld.
    p = policy_text("""
policy_version: 1
name: residual
requirements: {environment: false, destination: false}
settings: {rescan: {fail_on_categories: [identifier.generic]}}
detectors:
  custom:
    - id: order
      category: identifier.generic
      pattern: "ORD-[0-9]{6}"
rules:
  - id: replace-email
    match: {categories: [pii.email]}
    action: replace
    params: {value: "see ORD-123456"}
  - id: redact-orders
    match: {categories: [identifier.generic]}
    action: redact
""")
    out = tmp_path / "o.txt"
    r = sanitize_file(write("in.txt", "mail alice.test@example.com\n"), out, p)
    assert r.status == RunStatus.RESCAN_FAILED and r.exit_code == 7
    assert not out.exists() and not list(tmp_path.glob(".ciphergate-*"))
    assert r.rescan is not None and r.rescan.gating_by_category == {"identifier.generic": 1}
