"""Regression tests for findings of the independent security review (synthetic data only)."""

from __future__ import annotations

import csv
import io
import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate import cli
from ciphergate.constants import CREDENTIAL_CATEGORY, HIGH_RISK_CATEGORIES, Action, ReasonCode
from ciphergate.errors import OutputWriteError, PolicyValidationError
from ciphergate.models.report import RunStatus
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.pipeline.sanitizer import inspect_file, rescan_file, sanitize_file
from ciphergate.policy.context import evaluate_gates, resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.validator import Policy
from ciphergate.readers import ReaderOptions, make_writer, open_reader
from ciphergate.readers.base import Record
from ciphergate.reporting.serializer import report_to_json
from tests.conftest import MINIMAL_POLICY, POLICIES, ctx

Write = Callable[[str, str | bytes], Path]
HEADER_EMAIL = "header.person@example.com"
HEAD = "policy_version: 1\nname: t\n"


def codes(policy_text: Callable[[str], Policy], text: str) -> set[str]:
    with pytest.raises(PolicyValidationError) as info:
        policy_text(HEAD + text)
    return {i.code for i in info.value.issues}


# ----------------------------------------------------------------------------- 1. CSV header


def test_csv_header_value_is_scanned_and_withheld(
    tmp_path: Path, write: Write, policy_file: Callable[[str], Policy]
) -> None:
    src = write("in.csv", f"id,{HEADER_EMAIL}\n1,x\n")
    out = tmp_path / "o.csv"
    report = sanitize_file(src, out, policy_file("prd_external_ai.yml"))
    # A value transform cannot apply to a header cell: review, never a silent pass-through.
    assert report.status == RunStatus.REVIEW_REQUIRED and not out.exists()
    blob = report_to_json(report)
    assert HEADER_EMAIL not in blob and "header.person" not in blob
    item = next(i for i in report.items if i["location"].get("in_key"))
    assert item["location"]["field_path"] == "<redacted-key>"
    assert item["decision"]["reason_code"] == str(ReasonCode.UNSUPPORTED_TRANSFORM)


def test_csv_header_credential_blocks(
    write: Write, tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    src = write("in.csv", "id,Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123\n1,x\n")
    report = sanitize_file(src, tmp_path / "o.csv", policy_text(MINIMAL_POLICY))
    assert report.status == RunStatus.BLOCKED and not (tmp_path / "o.csv").exists()


def test_csv_header_drop_field_drops_column(
    write: Write, tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: drop-email\n    priority: 200\n    match: {categories: [pii.email]}\n"
            "    action: drop_field\n",
        )
    )
    src = write("in.csv", f"id,{HEADER_EMAIL},note\n1,x,keep\n")
    out = tmp_path / "o.csv"
    report = sanitize_file(src, out, p)
    assert report.status == RunStatus.SANITIZED
    assert list(csv.reader(io.StringIO(out.read_text(encoding="utf-8")))) == [
        ["id", "note"],
        ["1", "keep"],
    ]
    assert HEADER_EMAIL not in report_to_json(report)
    assert report.changes["dropped_columns"] == ["<redacted-key>"]


def test_csv_header_drop_record_requires_review(
    write: Write, tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: drop-email-rows\n    priority: 200\n    match: {categories: "
            "[pii.email]}\n    action: drop_record\n",
        )
    )
    report = sanitize_file(write("in.csv", f"{HEADER_EMAIL}\n1\n"), tmp_path / "o.csv", p)
    assert report.status == RunStatus.REVIEW_REQUIRED


def test_csv_header_residual_fails_rescan(
    write: Write, policy_file: Callable[[str], Policy]
) -> None:
    src = write("out.csv", f"id,{HEADER_EMAIL}\n1,x\n")
    report = rescan_file(src, policy_file("prd_external_ai.yml"))
    assert report.status == RunStatus.RESCAN_FAILED
    assert HEADER_EMAIL not in report_to_json(report)


def test_csv_benign_header_values_in_sensitive_column_hide_label(
    write: Write, policy_text: Callable[[str], Policy]
) -> None:
    report = inspect_file(
        write("in.csv", f"{HEADER_EMAIL}\nother.person@example.com\n"), policy_text(MINIMAL_POLICY)
    )
    paths = {i["location"].get("field_path") for i in report.items}
    assert paths == {"<redacted-key>"}


def test_csv_lone_carriage_return_is_quoted(write: Write) -> None:
    from ciphergate.config import RuntimeSettings
    from ciphergate.constants import InputFormat
    from ciphergate.models.policy import PolicySettings

    src = write("in.csv", "a,b\n1,2\n")
    reader = open_reader(src, InputFormat.CSV, ReaderOptions(RuntimeSettings(), PolicySettings()))
    list(reader.records())
    buf = io.StringIO()
    writer = make_writer(buf, reader, set())
    writer.write_record(Record(0, 2, ["", "\r"]), ["", "\r"])
    writer.close()
    assert list(csv.reader(io.StringIO(buf.getvalue(), newline=""))) == [["a", "b"], ["", "\r"]]


# ----------------------------------------------------------------------------- 2. rescan set


def test_empty_rescan_fail_set_rejected(policy_text: Callable[[str], Policy]) -> None:
    assert "invalid_value" in codes(policy_text, "settings: {rescan: {fail_on_categories: []}}\n")


def test_rescan_fail_set_floor(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(HEAD + "settings: {rescan: {fail_on_categories: [pii.phone]}}\n")
    assert any("omits high-risk" in w for w in p.warnings)
    assert p.rescan_fail_categories() == {"pii.phone", CREDENTIAL_CATEGORY}
    assert p.rescan_fail_categories(untrusted=True) >= HIGH_RISK_CATEGORIES


def test_narrow_fail_set_still_gates_email_to_external(
    write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(
        HEAD + "settings: {strict: true, rescan: {fail_on_categories: [pii.phone]}}\n"
        "rules:\n  - id: r\n    match: {categories: ['*']}\n    action: redact\n"
    )
    report = rescan_file(
        write("o.txt", "contact alice.test@example.com\n"), p, ctx("prd", "external", "external_ai")
    )
    assert report.status == RunStatus.RESCAN_FAILED


# ----------------------------------------------------------------------------- 3. detectors


@pytest.mark.parametrize("detector", ["secret_pattern", "field_name"])
def test_credential_detectors_cannot_be_disabled_when_strict(
    policy_text: Callable[[str], Policy], detector: str
) -> None:
    assert "credential_detection_required" in codes(
        policy_text, f"settings: {{strict: true}}\ndetectors: {{disabled: [{detector}]}}\n"
    )


def test_disabled_credential_detector_blocks_untrusted_run(
    policy_text: Callable[[str], Policy],
) -> None:
    p = policy_text(HEAD + "settings: {strict: false}\ndetectors: {disabled: [secret_pattern]}\n")
    gates, _ = evaluate_gates(p, resolve_context(p, ctx("dev", dest="external_ai")))
    assert ReasonCode.CREDENTIAL_DETECTION_REQUIRED in {g.reason_code for g in gates}


# ----------------------------------------------------------------------------- 4. no destination


def test_missing_destination_is_untrusted_for_gates(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(
        HEAD + "requirements: {environment: false, destination: false}\n"
        "settings: {strict: false, rescan: {enabled: false}}\n"
    )
    assert any("requirements.destination is false" in w for w in p.warnings)
    gates, _ = evaluate_gates(p, resolve_context(p, ctx("dev")))
    found = {g.reason_code for g in gates}
    assert {ReasonCode.STRICT_POLICY_REQUIRED, ReasonCode.RESCAN_REQUIRED} <= found
    trusted, _ = evaluate_gates(p, resolve_context(p, ctx("dev", dest="local_dev")))
    assert not trusted


# ----------------------------------------------------------------------------- 5. JSON keys


def test_pinned_untrusted_policy_must_scan_keys(policy_text: Callable[[str], Policy]) -> None:
    assert "key_scan_required" in codes(
        policy_text, "context: {destination: external_ai}\nsettings: {strict: true}\n"
    )


def test_unscanned_json_keys_block_untrusted_run(
    tmp_path: Path, write: Write, policy_text: Callable[[str], Policy]
) -> None:
    p = policy_text(HEAD + "settings: {strict: true}\n")
    src = write("in.json", json.dumps({"alice.test@example.com": 1}))
    out = tmp_path / "o.json"
    report = sanitize_file(src, out, p, ctx("dev", "external", "external_ai"))
    assert report.status == RunStatus.BLOCKED and not out.exists()
    assert str(ReasonCode.KEY_SCAN_REQUIRED) in {g["reason_code"] for g in report.gates}
    # Text input has no keys: the gate does not apply.
    text = sanitize_file(
        write("in.txt", "ok\n"), tmp_path / "o.txt", p, ctx("dev", "external", "external_ai")
    )
    assert str(ReasonCode.KEY_SCAN_REQUIRED) not in {g["reason_code"] for g in text.gates}


def test_shipped_templates_scan_json_keys(policy_file: Callable[[str], Policy]) -> None:
    for path in sorted(POLICIES.glob("*.yml")):
        assert policy_file(path.name).document.settings.scan_json_keys, path.name


# ----------------------------------------------------------------------------- 6. custom high-risk


def test_custom_pii_category_is_high_risk(policy_text: Callable[[str], Policy]) -> None:
    text = (
        "custom_categories: [pii.member_number, internal.order_ref]\n"
        "rules:\n  - id: r\n    match: {categories: [pii.member_number], "
        "destinations: [external_ai]}\n    action: allow\n"
    )
    assert "high_risk_allow_unacknowledged" in codes(policy_text, text)
    p = policy_text(HEAD + text.replace("[pii.member_number],", "[internal.order_ref],"))
    assert "pii.member_number" in p.high_risk and "internal.order_ref" not in p.high_risk


# ----------------------------------------------------------------------------- 7. cleanup failure


def test_cleanup_failure_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(self: Path, missing_ok: bool = False) -> None:
        raise OSError("locked")

    with caplog.at_level(logging.WARNING, logger="ciphergate"):
        out = AtomicOutput(tmp_path / "o.txt", force=False)
        with out:
            out.stream.write("x")
            monkeypatch.setattr(Path, "unlink", refuse)
        monkeypatch.undo()
    assert out.cleanup_failed_path is not None
    assert "could not remove temporary output" in caplog.text and "locked" not in caplog.text
    out.cleanup_failed_path.unlink()


# ----------------------------------------------------------------- 8. report after publish


def test_report_failure_after_publish_says_output_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_: object, **__: object) -> None:
        raise OutputWriteError("cannot write report", code="report_write_failed")

    monkeypatch.setattr(cli, "write_report_file", fail)
    src = tmp_path / "in.log"
    src.write_text("hello\n", encoding="utf-8")
    out = tmp_path / "o.log"
    r = CliRunner().invoke(
        cli.app,
        [
            "sanitize",
            str(src),
            "--policy",
            str(POLICIES / "developer_logs.yml"),
            "--environment",
            "dev",
            "--destination",
            "local_dev",
            "--output",
            str(out),
            "--report",
            str(tmp_path / "r.json"),
            "--apply",
        ],
    )
    assert r.exit_code == 5 and out.exists()
    assert "WAS published" in r.stderr


# ----------------------------------------------------------------------------- 9. transfers


TRANSFER = (
    "settings: {strict: true}\ntransfers:\n  - id: t\n    from_environments: [prd]\n"
    "    to_target_environments: [stg]\n    approval: {reviewed_by: r, reference: REF-1, "
    "approved_on: 2026-01-01}\n"
)


def test_transfer_must_name_every_supplied_dimension(policy_text: Callable[[str], Policy]) -> None:
    p = policy_text(HEAD + TRANSFER)
    gates, approvals = evaluate_gates(p, resolve_context(p, ctx("prd", "stg", "local_dev")))
    assert not approvals
    assert ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED in {g.reason_code for g in gates}
    _, approvals = evaluate_gates(p, resolve_context(p, ctx("prd", "stg")))
    assert approvals == ["t"]


def test_future_transfer_approval_rejected(policy_text: Callable[[str], Policy]) -> None:
    assert "invalid_value" in codes(policy_text, TRANSFER.replace("2026-01-01", "2999-01-01"))


# ----------------------------------------------------------------------------- engine: target


def test_allow_high_risk_with_external_target_requires_ack(
    policy_text: Callable[[str], Policy],
) -> None:
    from ciphergate.constants import InputFormat
    from ciphergate.detectors.registry import DetectorSet
    from ciphergate.models.finding import ScanItem

    p = policy_text(
        HEAD + "rules:\n  - id: keep\n    match: {categories: [pii.email], destinations: "
        "[approved_internal]}\n    action: allow\n"
    )
    c = resolve_context(p, ctx("dev", "external", "approved_internal"))
    finding = DetectorSet(p.document.detectors, p.document).scan(
        ScanItem(0, 1, "/m", "notes", "alice.test@example.com")
    )[0]
    decision = PolicyEngine(p).decide(finding, c, InputFormat.JSON)
    assert decision.action == Action.REVIEW
    assert decision.reason_code == ReasonCode.HIGH_RISK_ALLOW_REQUIRES_ACKNOWLEDGEMENT
