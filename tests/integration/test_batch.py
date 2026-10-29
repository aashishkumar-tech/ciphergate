"""Directory (batch) runs (#9): discovery safety, all-or-nothing publish, reports and exit codes."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate.cli import app
from ciphergate.config import RuntimeSettings
from ciphergate.constants import InputFormat
from ciphergate.errors import InputLimitError, UnsafePathError
from ciphergate.pipeline.batch import discover, is_inside
from ciphergate.pipeline.paths import file_digest
from tests.conftest import EXAMPLES, POLICIES, SYNTHETIC_SECRETS

runner = CliRunner()

PRD_EXTERNAL = [
    "--policy",
    str(POLICIES / "prd_external_ai.yml"),
    "--environment",
    "prd",
    "--target-environment",
    "external",
    "--destination",
    "external_ai",
]
SECRET_LINE = "login failed password=TEST_ONLY_NOT_A_CREDENTIAL\n"
LEAKS = [*SYNTHETIC_SECRETS, "alice.test"]


@pytest.fixture
def env(hmac_key: str) -> dict[str, str]:
    return {"CIPHERGATE_HMAC_KEY": hmac_key}


def invoke(*args: str | Path, env: dict[str, str] | None = None):
    return runner.invoke(app, [str(a) for a in args], env=env)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "in"
    (root / "sub").mkdir(parents=True)
    (root / "a.csv").write_bytes((EXAMPLES / "sample.csv").read_bytes())
    (root / "sub" / "b.jsonl").write_bytes((EXAMPLES / "sample.jsonl").read_bytes())
    (root / "notes.md").write_text("not a supported extension\n", encoding="utf-8")
    return root


def _digests(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): file_digest(p) for p in root.rglob("*") if p.is_file()}


def _no_leaks(*texts: str) -> None:
    for text in texts:
        for secret in LEAKS:
            assert secret not in text


def _report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- discovery


def test_discovery_non_recursive_skips_and_reports(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    d = discover(root, recursive=False, fmt=None, max_files=10)
    assert [p.as_posix() for p in d.files] == ["a.csv"]
    assert sorted((p.as_posix(), r) for p, r in d.skipped) == [
        ("notes.md", "unsupported_extension"),
        ("sub", "directory_not_recursed"),
    ]


def test_discovery_recursive_sorted_and_format_override(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    d = discover(root, recursive=True, fmt=None, max_files=10)
    assert [p.as_posix() for p in d.files] == ["a.csv", "sub/b.jsonl"]
    forced = discover(root, recursive=True, fmt=InputFormat.TEXT, max_files=10)
    assert [p.as_posix() for p in forced.files] == ["a.csv", "notes.md", "sub/b.jsonl"]


def test_discovery_limits(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    with pytest.raises(InputLimitError) as exc:
        discover(root, recursive=True, fmt=None, max_files=1)
    assert exc.value.code == "batch_file_limit_exceeded"
    deep = tmp_path / "deep"
    current = deep
    for i in range(40):
        current = current / f"d{i}"
    current.mkdir(parents=True)
    with pytest.raises(InputLimitError) as exc:
        discover(deep, recursive=True, fmt=None, max_files=10)
    assert exc.value.code == "batch_depth_exceeded"


def test_discovery_refuses_a_file_or_symlinked_root(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    with pytest.raises(UnsafePathError):
        discover(root / "a.csv", recursive=False, fmt=None, max_files=10)
    link = tmp_path / "link"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not available on this platform/account")
    with pytest.raises(UnsafePathError) as exc:
        discover(link, recursive=False, fmt=None, max_files=10)
    assert exc.value.code == "input_not_directory"


def test_discovery_never_follows_symlinks(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.log").write_text(SECRET_LINE, encoding="utf-8")
    try:
        (root / "linked.log").symlink_to(outside / "secret.log")
        (root / "linked_dir").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not available on this platform/account")
    d = discover(root, recursive=True, fmt=None, max_files=10)
    assert "linked.log" not in [p.as_posix() for p in d.files]
    reasons = {p.as_posix(): r for p, r in d.skipped}
    assert reasons["linked.log"] == "symlink_not_followed"
    assert reasons["linked_dir"] == "symlink_not_followed"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need POSIX")
def test_discovery_skips_fifos(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    os.mkfifo(root / "pipe.log")
    d = discover(root, recursive=False, fmt=None, max_files=10)
    assert ("pipe.log", "not_regular_file") in [(p.as_posix(), r) for p, r in d.skipped]


def test_is_inside(tmp_path: Path) -> None:
    assert is_inside(tmp_path / "a" / "b", tmp_path / "a")
    assert is_inside(tmp_path / "a", tmp_path / "a")
    assert not is_inside(tmp_path / "ab", tmp_path / "a")


def test_max_batch_files_must_be_positive() -> None:
    with pytest.raises(ValueError):
        RuntimeSettings(max_batch_files=0)


# --------------------------------------------------------------------------- CLI analysis


@pytest.mark.parametrize("command", ["inspect", "plan", "rescan"])
def test_analysis_commands_are_read_only(command: str, tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    before = _digests(root)
    report = tmp_path / "report.json"
    r = invoke(command, root, "-r", *PRD_EXTERNAL, "--report", report, "-q", env=env)
    assert r.exit_code in (0, 1, 7)
    assert _digests(root) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in", "report.json"]
    data = _report(report)
    assert data["schema"] == "ciphergate.batch-report/v1"
    assert [f["path"] for f in data["files"]] == ["a.csv", "sub/b.jsonl"]
    assert data["skipped"] == [{"path": "notes.md", "reason": "unsupported_extension"}]
    assert data["summary"]["files_total"] == 2
    _no_leaks(r.stdout, r.stderr, report.read_text(encoding="utf-8"))


def test_batch_json_report_on_stdout(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    r = invoke("inspect", root, *PRD_EXTERNAL, "--report-format", "json", env=env)
    data = json.loads(r.stdout)
    assert data["command"] == "inspect" and data["input"]["recursive"] is False
    assert data["files"][0]["report"]["input"]["path"] == "a.csv"


def test_redacted_path_display_hides_file_names(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    r = invoke(
        "inspect", root, "-r", *PRD_EXTERNAL, "--path-display", "redacted",
        "--report-format", "json", env=env,
    )  # fmt: skip
    assert "a.csv" not in r.stdout and "b.jsonl" not in r.stdout and "notes" not in r.stdout
    data = json.loads(r.stdout)
    assert [f["path"] for f in data["files"]] == ["<redacted:0001>.csv", "<redacted:0002>.jsonl"]


def test_empty_directory_fails(tmp_path: Path, env) -> None:
    (tmp_path / "empty").mkdir()
    r = invoke("inspect", tmp_path / "empty", *PRD_EXTERNAL, env=env)
    assert r.exit_code == 4 and "batch_empty" in r.stderr


def test_max_files_flag(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    r = invoke("inspect", root, "-r", "--max-files", "1", *PRD_EXTERNAL, env=env)
    assert r.exit_code == 4 and "batch_file_limit_exceeded" in r.stderr


def test_recursive_needs_directory(tmp_path: Path, env) -> None:
    r = invoke("inspect", EXAMPLES / "sample.csv", "-r", *PRD_EXTERNAL, env=env)
    assert r.exit_code == 2 and "recursive_needs_directory" in r.stderr


def test_report_inside_input_directory_refused(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    r = invoke("inspect", root, *PRD_EXTERNAL, "--report", root / "r.json", env=env)
    assert r.exit_code == 5 and "report_inside_batch_directory" in r.stderr
    assert not (root / "r.json").exists()


def test_exit_code_is_first_failing_file(tmp_path: Path, env) -> None:
    root = tmp_path / "in"
    root.mkdir()
    (root / "a.json").write_text('{"broken": ', encoding="utf-8")  # parse error -> 4
    (root / "b.log").write_text(SECRET_LINE, encoding="utf-8")  # credential -> blocked 1
    (root / "c.csv").write_bytes((EXAMPLES / "sample.csv").read_bytes())
    report = tmp_path / "r.json"
    r = invoke("plan", root, *PRD_EXTERNAL, "--report", report, "-q", env=env)
    data = _report(report)
    codes = {f["path"]: f["exit_code"] for f in data["files"]}
    assert codes["a.json"] == 4 and codes["b.log"] == 1
    assert r.exit_code == 4 and data["exit_code"] == 4 and data["status"] == "failed"
    assert data["files"][0]["status"] == "error" and "code" in data["files"][0]["error"]
    _no_leaks(r.stdout, r.stderr, report.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- CLI sanitize


def test_sanitize_directory_matches_single_file_runs(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    before = _digests(root)
    out = tmp_path / "out"
    report = tmp_path / "report.json"
    r = invoke(
        "sanitize", root, "-r", *PRD_EXTERNAL, "-o", out, "--apply", "--report", report, env=env
    )
    assert r.exit_code == 0, r.stderr
    assert _digests(root) == before
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()) == [
        "a.csv",
        "sub/b.jsonl",
    ]
    for rel in ("a.csv", "sub/b.jsonl"):
        single = tmp_path / ("single" + Path(rel).suffix)
        s = invoke("sanitize", root / rel, *PRD_EXTERNAL, "-o", single, "--apply", "-q", env=env)
        assert s.exit_code == 0
        assert (out / rel).read_bytes() == single.read_bytes()
        single.unlink()
    data = _report(report)
    assert data["output"] == {"written": True, "path": "out"}
    assert all(f["report"]["output"]["written"] for f in data["files"])
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".ciphergate-")]
    _no_leaks(r.stdout, r.stderr, report.read_text(encoding="utf-8"))
    for f in out.rglob("*"):
        if f.is_file():
            _no_leaks(f.read_text(encoding="utf-8"))


def test_one_blocked_file_publishes_nothing(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    (root / "z.log").write_text(SECRET_LINE, encoding="utf-8")
    out = tmp_path / "out"
    report = tmp_path / "report.json"
    r = invoke(
        "sanitize", root, "-r", *PRD_EXTERNAL, "-o", out, "--apply", "--report", report, env=env
    )
    assert r.exit_code == 1
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in", "report.json"]  # no staging left
    data = _report(report)
    assert data["output"]["written"] is False
    assert data["output"]["withheld_reason"] == "file_failed"
    assert not any(f["report"]["output"].get("written") for f in data["files"])
    _no_leaks(r.stdout, r.stderr, report.read_text(encoding="utf-8"))


def test_missing_key_publishes_nothing(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    out = tmp_path / "out"
    r = invoke("sanitize", root, "-r", *PRD_EXTERNAL, "-o", out, "--apply", env={})
    assert r.exit_code == 6
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in"]


def test_dry_run_writes_nothing(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    out = tmp_path / "out"
    r = invoke("sanitize", root, "-r", *PRD_EXTERNAL, "-o", out, env=env)
    assert r.exit_code == 0 and "dry run" in r.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in"]


def test_existing_output_directory_refused(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = invoke("sanitize", root, *PRD_EXTERNAL, "-o", out, "--apply", env=env)
    assert r.exit_code == 5 and "output_exists" in r.stderr
    assert list(out.iterdir()) == []
    r = invoke("sanitize", root, *PRD_EXTERNAL, "-o", out, "--apply", "--force", env=env)
    assert r.exit_code == 2 and "force_unsupported_for_directory" in r.stderr


def test_output_inside_input_refused(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    before = _digests(root)
    r = invoke("sanitize", root, *PRD_EXTERNAL, "-o", root / "out", "--apply", env=env)
    assert r.exit_code == 5 and "output_inside_input" in r.stderr
    assert _digests(root) == before and not (root / "out").exists()


def test_directory_to_stdout_refused(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    r = invoke("sanitize", root, *PRD_EXTERNAL, "-o", "-", "--apply", env=env)
    assert r.exit_code == 2 and "stdout_unsupported" in r.stderr


def test_report_inside_output_directory_refused(tmp_path: Path, env) -> None:
    root = _tree(tmp_path)
    out = tmp_path / "out"
    r = invoke(
        "sanitize", root, *PRD_EXTERNAL, "-o", out, "--apply", "--report", out / "r.json", env=env
    )
    assert r.exit_code == 5 and "report_inside_batch_directory" in r.stderr
    assert not out.exists()


def test_entry_replaced_after_discovery_is_not_processed(
    tmp_path: Path, policy_loader=None
) -> None:
    from ciphergate.pipeline.batch import Discovery, _run_each

    root = tmp_path / "in"
    root.mkdir()
    outside = tmp_path / "secret.log"
    outside.write_text(SECRET_LINE, encoding="utf-8")
    try:
        (root / "a.log").symlink_to(outside)  # was a regular file at discovery time
    except OSError:
        pytest.skip("symlinks not available on this platform/account")
    calls: list[Path] = []
    results = _run_each(
        Discovery(root, [Path("a.log")], []),
        "basename",
        lambda p, rel: calls.append(p),  # type: ignore[arg-type,func-returns-value]
    )
    assert calls == []
    assert results[0].error_code == "input_changed_type" and results[0].exit_code != 0
