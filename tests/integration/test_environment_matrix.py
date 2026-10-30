"""CLAUDE.md section 16.9: the same synthetic data under different source environments and
destinations must produce different, context-appropriate outcomes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import RunStatus, SanitizeOptions, plan_file, sanitize_file
from ciphergate.constants import Action, InputFormat, ReasonCode
from ciphergate.errors import ContextError
from ciphergate.models.finding import Finding, Location
from ciphergate.policy.context import resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.validator import Policy
from tests.conftest import ctx

# Identical synthetic content for every scenario.
LOG = (
    '{"trace_id": "trc-0001-aaaa", "email": "alice.test@example.com", '
    '"msg": "login from 10.0.12.7 via api-1.prod.internal"}\n'
)
LOG_WITH_SECRET = LOG + '{"msg": "db_password=TEST_ONLY_NOT_A_CREDENTIAL"}\n'


def actions_for(
    policy: Policy, category: str, field: str, env: str, target: str, dest: str
) -> Action:
    f = Finding(category, "field_name", 0.9, ("x",), Location(0, 1, f"/{field}"), field, "string")
    c = resolve_context(policy, ctx(env, target, dest))
    return PolicyEngine(policy).decide(f, c, InputFormat.JSONL).action


@pytest.fixture
def multi(policy_file: Callable[[str], Policy]) -> Policy:
    return policy_file("multi_environment.yml")


def test_changing_only_environment_changes_outcome(multi: Policy) -> None:
    dev = actions_for(multi, "pii.email", "email", "dev", "dev", "approved_internal")
    prd = actions_for(multi, "pii.email", "email", "prd", "prd", "approved_internal")
    assert (dev, prd) == (Action.REPLACE, Action.REDACT)


def test_changing_only_destination_changes_outcome(multi: Policy) -> None:
    local = actions_for(multi, "network.telemetry", "host", "dev", "dev", "local_dev")
    external = actions_for(multi, "network.telemetry", "host", "dev", "external", "external_ai")
    assert (local, external) == (Action.ALLOW, Action.REDACT)


def test_prd_monitoring_allowlist_only(multi: Policy) -> None:
    assert (
        actions_for(multi, "network.telemetry", "trace_id", "prd", "prd", "production_monitoring")
        == Action.ALLOW
    )
    assert (
        actions_for(multi, "network.telemetry", "host", "prd", "prd", "production_monitoring")
        == Action.REDACT
    )
    assert (
        actions_for(multi, "credential.secret", "password", "prd", "prd", "production_monitoring")
        == Action.BLOCK
    )


def test_credentials_blocked_external_from_every_environment(multi: Policy) -> None:
    for env in ("dev", "stg", "prd"):
        assert (
            actions_for(multi, "credential.secret", "password", env, "external", "external_ai")
            == Action.BLOCK
        )


def run(
    tmp_path: Path,
    policy: Policy,
    env: str | None,
    target: str | None,
    dest: str | None,
    content: str = LOG,
    name: str = "out.jsonl",
):
    src = tmp_path / "in.jsonl"
    src.write_text(content, encoding="utf-8")
    out = tmp_path / name
    report = sanitize_file(src, out, policy, ctx(env, target, dest), SanitizeOptions())
    return report, out


@pytest.mark.parametrize(
    ("env", "target", "dest", "status"),
    [
        ("dev", "dev", "local_dev", RunStatus.SANITIZED),
        ("stg", "stg", "staging_test", RunStatus.SANITIZED),
        ("prd", "external", "external_ai", RunStatus.SANITIZED),
        ("prd", "stg", "staging_test", RunStatus.BLOCKED),
        ("prd", "prd", "production_monitoring", RunStatus.SANITIZED),
        ("unknown", "external", "external_ai", RunStatus.REVIEW_REQUIRED),
        ("unknown", "dev", "local_dev", RunStatus.REVIEW_REQUIRED),
        ("dev", "unknown", "unknown", RunStatus.REVIEW_REQUIRED),
    ],
)
def test_matrix_end_to_end(
    tmp_path: Path, multi: Policy, env: str, target: str, dest: str, status: RunStatus
) -> None:
    report, out = run(tmp_path, multi, env, target, dest)
    assert report.status == status, report.gates
    assert out.exists() is (status == RunStatus.SANITIZED)
    assert report.context["environment"] == {"value": env, "source": "cli"}


def test_matrix_outputs_differ_by_context(tmp_path: Path, multi: Policy) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _, dev_out = run(tmp_path / "a", multi, "dev", "dev", "local_dev")
    _, prd_out = run(tmp_path / "b", multi, "prd", "external", "external_ai")
    dev, prd = dev_out.read_text(encoding="utf-8"), prd_out.read_text(encoding="utf-8")
    assert "user@example.invalid" in dev and "api-1.prod.internal" in dev
    assert "[REDACTED:pii.email]" in prd and "api-1.prod.internal" not in prd
    assert "10.0.12.7" not in prd


def test_prd_to_external_block_leaves_no_output(tmp_path: Path, multi: Policy) -> None:
    report, out = run(tmp_path, multi, "prd", "external", "external_ai", LOG_WITH_SECRET)
    assert report.status == RunStatus.BLOCKED and report.exit_code == 1
    assert not out.exists() and not list(tmp_path.glob(".ciphergate-*"))
    assert report.summary["by_reason_code"].get("credential_detected_hard_block") == 1


def test_prd_to_stg_blocked_without_reviewed_transfer(tmp_path: Path, multi: Policy) -> None:
    report, out = run(tmp_path, multi, "prd", "stg", "staging_test")
    assert [g["reason_code"] for g in report.gates] == [
        str(ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED)
    ]
    assert not out.exists()


def test_prd_to_stg_with_reviewed_transfer_and_rescan(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    approved = (
        (Path(__file__).resolve().parents[2] / "policies" / "multi_environment.yml")
        .read_text(encoding="utf-8")
        .replace(
            "name: multi-environment",
            "name: multi-environment-approved\ntransfers:\n  - id: masked-prd-to-stg\n"
            "    from_environments: [prd]\n    to_target_environments: [stg]\n"
            "    to_destinations: [staging_test]\n    approval:\n      reviewed_by: test-reviewer\n"
            "      reference: TEST-REF-0001\n      approved_on: 2026-01-01",
        )
    )
    p = policy_text(approved)
    report, out = run(tmp_path, p, "prd", "stg", "staging_test")
    assert report.status == RunStatus.SANITIZED and out.exists()
    assert report.transfer_approvals == ["masked-prd-to-stg"]
    assert report.rescan is not None and not report.rescan.failed
    # Production email never survives into staging, even with an approval.
    assert "alice.test" not in out.read_text(encoding="utf-8")


def test_missing_context_fails_closed(tmp_path: Path, multi: Policy) -> None:
    report, out = run(tmp_path, multi, None, None, None)
    reasons = {g["reason_code"] for g in report.gates}
    assert {
        "environment_required_but_missing",
        "destination_required_but_missing",
        "target_environment_required_but_missing",
    } <= reasons
    assert report.status == RunStatus.BLOCKED and not out.exists()


def test_environment_never_defaults_to_dev(tmp_path: Path, multi: Policy) -> None:
    report, _ = run(tmp_path, multi, None, "dev", "local_dev")
    assert report.context["environment"] == {"value": None, "source": "unset"}


def test_pinned_templates(
    tmp_path: Path, policy_file: Callable[[str], Policy], key_env: str
) -> None:
    for name, good in [
        ("dev_local.yml", ("dev", "dev", "local_dev")),
        ("stg_test.yml", ("stg", "stg", "staging_test")),
        ("prd_external_ai.yml", ("prd", "external", "external_ai")),
    ]:
        p = policy_file(name)
        d = tmp_path / name
        d.mkdir()
        report, _ = run(d, p, *good)
        assert report.status == RunStatus.SANITIZED, (name, report.gates, report.summary)
        with pytest.raises(ContextError):
            run(d, p, "unknown", None, None, name="x.jsonl")


def test_local_debug_blocks_prd_origin(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    p = policy_file("local_debug.yml")
    report, out = run(tmp_path, p, "prd", None, None)
    assert report.status == RunStatus.BLOCKED and not out.exists()
    report, out = run(tmp_path, p, "dev", None, None)
    assert report.status == RunStatus.SANITIZED


def test_plan_and_apply_agree_across_matrix(tmp_path: Path, multi: Policy) -> None:
    src = tmp_path / "in.jsonl"
    src.write_text(LOG, encoding="utf-8")
    for env, target, dest in [
        ("dev", "dev", "local_dev"),
        ("prd", "external", "external_ai"),
        ("prd", "prd", "production_monitoring"),
    ]:
        plan = plan_file(src, multi, ctx(env, target, dest))
        out = tmp_path / f"{env}-{dest}.jsonl"
        applied = sanitize_file(src, out, multi, ctx(env, target, dest))
        assert plan.summary["by_action"] == applied.summary["by_action"]


TRACE = (
    "Traceback (most recent call last):\n"
    '  File "/srv/app/handlers.py", line 42, in handle\n'
    "    user = load(email)\n"
    "ValueError: no user alice.test@example.com\n"
)


@pytest.mark.parametrize(
    ("policy_name", "env", "target", "dest", "frames_kept"),
    [
        ("dev_local.yml", "dev", "dev", "local_dev", True),
        ("developer_logs.yml", "dev", None, "local_dev", True),
        ("developer_logs.yml", "prd", None, "production_monitoring", True),
        ("developer_logs.yml", "stg", None, "staging_test", False),
        ("developer_logs.yml", "prd", None, "external_ai", False),
    ],
)
def test_stack_frames_follow_destination(
    tmp_path: Path,
    policy_file: Callable[[str], Policy],
    policy_name: str,
    env: str,
    target: str | None,
    dest: str,
    frames_kept: bool,
) -> None:
    src = tmp_path / "trace.log"
    src.write_text(TRACE, encoding="utf-8")
    out = tmp_path / "trace.out.log"
    report = sanitize_file(
        src, out, policy_file(policy_name), ctx(env, target, dest),
        SanitizeOptions(format=InputFormat.STACKTRACE),
    )  # fmt: skip
    assert report.status == RunStatus.SANITIZED, (report.gates, report.summary)
    text = out.read_text(encoding="utf-8")
    assert "alice.test@example.com" not in text  # never kept, whatever happens to frames
    assert ("handlers.py" in text and "load(email)" in text) is frames_kept
    assert ("[REDACTED:proprietary.source]" in text) is not frames_kept
