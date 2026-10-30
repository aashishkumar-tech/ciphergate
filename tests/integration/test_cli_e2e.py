"""CLI behaviour, exit codes and output separation (CliRunner + real subprocess smoke tests)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate import __version__
from ciphergate.cli import app
from tests.conftest import EXAMPLES, POLICIES, SYNTHETIC_SECRETS

runner = CliRunner()


def invoke(*args: str | Path, env: dict[str, str] | None = None):
    return runner.invoke(app, [str(a) for a in args], env=env)


def test_version_and_help() -> None:
    r = invoke("--version")
    assert r.exit_code == 0 and __version__ in r.stdout
    for cmd in ("init", "validate-policy", "inspect", "plan", "sanitize", "rescan", "explain"):
        assert invoke(cmd, "--help").exit_code == 0


def test_init_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "p.yml"
    r = invoke("init", "--output", target)
    assert r.exit_code == 0 and "template" in r.stdout.lower()
    assert invoke("validate-policy", target).exit_code == 0
    r = invoke("init", "--output", target)
    assert r.exit_code == 5 and "output_exists" not in r.stdout
    assert invoke("init", "--output", target, "--force").exit_code == 0


def test_init_lists_every_policy_template() -> None:
    r = invoke("init", "--list-templates")
    assert r.exit_code == 0
    assert r.stdout.split() == sorted(p.stem for p in POLICIES.glob("*.yml"))


@pytest.mark.parametrize("policy", sorted(POLICIES.glob("*.yml")), ids=lambda p: p.stem)
def test_init_template_writes_a_valid_copy(tmp_path: Path, policy: Path) -> None:
    target = tmp_path / "p.yml"
    r = invoke("init", "--template", policy.stem, "--output", target)
    assert r.exit_code == 0 and "template" in r.stdout.lower()
    assert target.read_text(encoding="utf-8") == policy.read_text(encoding="utf-8")
    assert invoke("validate-policy", target).exit_code == 0


def test_init_template_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "p.yml"
    target.write_text("keep", encoding="utf-8")
    assert invoke("init", "--template", "dev_local", "--output", target).exit_code == 5
    assert target.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("name", ["nope", "../pyproject", "dev_local.yml", ""])
def test_init_unknown_template_fails_and_writes_nothing(tmp_path: Path, name: str) -> None:
    target = tmp_path / "p.yml"
    r = invoke("init", "--template", name, "--output", target)
    assert r.exit_code == 2
    assert "--list-templates" in r.output and not target.exists()


def test_validate_policy_exit_codes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "policy_version: 1\nname: x\nrules:\n  - id: r\n    match: {categories: "
        "[credential.secret]}\n    action: allow\n",
        encoding="utf-8",
    )
    r = invoke("validate-policy", bad)
    assert r.exit_code == 3 and "credential_unsafe_action" in r.stderr
    r = invoke("validate-policy", bad, "--report-format", "json")
    assert r.exit_code == 3 and json.loads(r.stdout)["valid"] is False


def test_usage_errors_exit_2() -> None:
    assert (
        invoke(
            "inspect",
            EXAMPLES / "sample.csv",
            "--policy",
            POLICIES / "developer_logs.yml",
            "--environment",
            "production",
        ).exit_code
        == 2
    )
    assert (
        invoke(
            "sanitize", EXAMPLES / "sample.csv", "--policy", POLICIES / "developer_logs.yml"
        ).exit_code
        == 2
    )  # --output missing


def test_inspect_json_stdout_only(tmp_path: Path) -> None:
    r = invoke(
        "inspect",
        EXAMPLES / "sample.log",
        "--policy",
        POLICIES / "developer_logs.yml",
        "--environment",
        "dev",
        "--destination",
        "local_dev",
        "--report-format",
        "json",
    )
    assert r.exit_code == 0
    report = json.loads(r.stdout)  # stdout is pure JSON
    assert report["schema"] == "ciphergate.report/v1" and report["command"] == "inspect"
    assert report["input"]["path"] == "sample.log"


def test_inspect_blocked_exit_1_and_report_file(tmp_path: Path) -> None:
    rep = tmp_path / "r.json"
    r = invoke(
        "inspect",
        EXAMPLES / "sample.log",
        "--policy",
        POLICIES / "prd_external_ai.yml",
        "--report",
        rep,
    )
    assert r.exit_code == 1 and "BLOCKED" in r.stdout
    data = json.loads(rep.read_text(encoding="utf-8"))
    assert data["status"] == "blocked" and data["summary"]["blocked"] == 2
    # Report path must not be overwritten without --force.
    r = invoke(
        "inspect",
        EXAMPLES / "sample.log",
        "--policy",
        POLICIES / "prd_external_ai.yml",
        "--report",
        rep,
    )
    assert r.exit_code == 5


def test_missing_context_exit_1() -> None:
    r = invoke("plan", EXAMPLES / "sample.csv", "--policy", POLICIES / "developer_logs.yml")
    assert r.exit_code == 1 and "destination_required_but_missing" in r.stdout


def test_context_conflict_exit_1() -> None:
    r = invoke(
        "plan",
        EXAMPLES / "sample.csv",
        "--policy",
        POLICIES / "prd_external_ai.yml",
        "--environment",
        "dev",
    )
    assert r.exit_code == 1 and "environment_context_conflict" in r.stderr


def test_sanitize_requires_apply_and_respects_force(tmp_path: Path, key_env: str) -> None:
    out = tmp_path / "o.csv"
    base = [
        "sanitize",
        EXAMPLES / "sample.csv",
        "--policy",
        POLICIES / "prd_external_ai.yml",
        "--output",
        out,
    ]
    r = invoke(*base)
    assert r.exit_code == 0 and not out.exists() and "dry run" in r.stdout
    r = invoke(*base, "--apply", "--quiet")
    assert r.exit_code == 0 and out.exists() and r.stdout == ""
    assert invoke(*base, "--apply").exit_code == 5
    assert invoke(*base, "--apply", "--force").exit_code == 0
    assert key_env[4:] not in out.read_text(encoding="utf-8")


def test_sanitize_missing_key_exit_6(tmp_path: Path, no_key_env: None) -> None:
    out = tmp_path / "o.csv"
    r = invoke(
        "sanitize",
        EXAMPLES / "sample.csv",
        "--policy",
        POLICIES / "prd_external_ai.yml",
        "--output",
        out,
        "--apply",
    )
    assert r.exit_code == 6 and not out.exists() and "missing" in r.stdout


def test_rescan_summary_never_says_a_bare_pass(tmp_path: Path) -> None:
    policy = POLICIES / "prd_external_ai.yml"
    clean = tmp_path / "clean.log"
    clean.write_text("service started\n", encoding="utf-8")
    r = invoke("rescan", clean, "--policy", policy)
    assert r.exit_code == 0
    assert "NO GATING FINDINGS" in r.stdout and "does not mean the output is safe" in r.stdout
    assert "PASSED" not in r.stdout and "passed" not in r.stdout.replace("--", "")

    report = tmp_path / "report.json"
    assert invoke("rescan", clean, "--policy", policy, "--report", report).exit_code == 0
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "passed"


def test_rescan_summary_says_when_gating_findings_are_not_enforced(tmp_path: Path) -> None:
    src = tmp_path / "raw.csv"
    shutil.copy(EXAMPLES / "sample.csv", src)
    r = invoke("rescan", src, "--policy", POLICIES / "prd_external_ai.yml", "--no-strict")
    assert r.exit_code == 0
    assert "NOT ENFORCED" in r.stdout and "PASSED" not in r.stdout


def test_rescan_exit_7_and_read_only(tmp_path: Path) -> None:
    src = tmp_path / "raw.csv"
    shutil.copy(EXAMPLES / "sample.csv", src)
    before = src.read_bytes()
    r = invoke("rescan", src, "--policy", POLICIES / "prd_external_ai.yml")
    assert r.exit_code == 7 and "FAILED" in r.stdout
    assert (
        invoke("rescan", src, "--policy", POLICIES / "prd_external_ai.yml", "--no-strict").exit_code
        == 0
    )
    assert src.read_bytes() == before


def test_input_errors_exit_4(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"a": 1}\n{oops TEST_ONLY_NOT_A_CREDENTIAL\n', encoding="utf-8")
    r = invoke(
        "inspect",
        bad,
        "--policy",
        POLICIES / "developer_logs.yml",
        "--environment",
        "dev",
        "--destination",
        "local_dev",
    )
    assert r.exit_code == 4 and "line 2" in r.stderr and "TEST_ONLY" not in r.stderr
    r = invoke(
        "inspect",
        EXAMPLES / "sample.csv",
        "--policy",
        POLICIES / "developer_logs.yml",
        "--max-bytes",
        "10",
    )
    assert r.exit_code == 4


def test_output_alias_exit_5(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    shutil.copy(EXAMPLES / "sample.csv", src)
    r = invoke(
        "sanitize",
        src,
        "--policy",
        POLICIES / "developer_logs.yml",
        "--environment",
        "dev",
        "--destination",
        "local_dev",
        "--output",
        src,
        "--apply",
        "--force",
    )
    assert r.exit_code == 5 and src.read_bytes() == (EXAMPLES / "sample.csv").read_bytes()


def test_flags_do_not_change_decisions() -> None:
    base = [
        "plan",
        EXAMPLES / "sample.jsonl",
        "--policy",
        POLICIES / "external_ai.yml",
        "--environment",
        "prd",
        "--report-format",
        "json",
    ]
    a = json.loads(invoke(*base).stdout)["summary"]
    b = json.loads(invoke(*base, "--quiet", "--verbose", "--no-color").stdout)["summary"]
    assert a == b


def test_explain() -> None:
    r = invoke(
        "explain",
        "--policy",
        POLICIES / "multi_environment.yml",
        "--category",
        "pii.email",
        "--field",
        "/email",
        "--environment",
        "prd",
        "--target-environment",
        "external",
        "--destination",
        "external_ai",
    )
    data = json.loads(r.stdout)
    assert r.exit_code == 0 and data["decision"]["rule_id"] == "prd-external-guardrail"


def test_path_display_redacted() -> None:
    r = invoke(
        "inspect",
        EXAMPLES / "sample.csv",
        "--policy",
        POLICIES / "developer_logs.yml",
        "--environment",
        "dev",
        "--destination",
        "local_dev",
        "--report-format",
        "json",
        "--path-display",
        "redacted",
    )
    assert json.loads(r.stdout)["input"]["path"] == "<redacted>.csv"


def test_no_secrets_in_any_cli_output(tmp_path: Path, key_env: str) -> None:
    runs = [
        ["inspect", EXAMPLES / "sample.log", "--policy", POLICIES / "prd_external_ai.yml", "-v"],
        [
            "plan",
            EXAMPLES / "sample.log",
            "--policy",
            POLICIES / "developer_logs.yml",
            "--environment",
            "dev",
            "--destination",
            "local_dev",
            "--verbose",
        ],
        [
            "sanitize",
            EXAMPLES / "sample.log",
            "--policy",
            POLICIES / "developer_logs.yml",
            "--environment",
            "dev",
            "--destination",
            "local_dev",
            "--output",
            tmp_path / "o.log",
            "--apply",
            "--report",
            tmp_path / "r.json",
            "--verbose",
        ],
    ]
    for args in runs:
        r = invoke(*args)
        blob = r.stdout + r.stderr
        for secret in [*SYNTHETIC_SECRETS, key_env[4:], "alice.test"]:
            assert secret not in blob, (args[0], secret)
    report = (tmp_path / "r.json").read_text(encoding="utf-8")
    for secret in [*SYNTHETIC_SECRETS, "alice.test", "202 555", "USER_TEST"]:
        assert secret not in report


# ----------------------------------------------------------------------------- real processes


def _cli() -> list[str]:
    exe = shutil.which("ciphergate", path=str(Path(sys.executable).parent))
    return [exe] if exe else [sys.executable, "-m", "ciphergate"]


@pytest.mark.parametrize("argv", [[sys.executable, "-m", "ciphergate"], None])
def test_entry_points(argv: list[str] | None) -> None:
    cmd = argv or _cli()
    r = subprocess.run([*cmd, "--version"], capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0 and __version__ in r.stdout


def test_subprocess_internal_error_is_safe(tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run(
        [sys.executable, "-m", "ciphergate", "validate-policy", str(tmp_path / "missing.yml")],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert r.returncode == 3 and "policy_not_found" in r.stderr and "Traceback" not in r.stderr
