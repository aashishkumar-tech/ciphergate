"""Repository safety check and commit-message rules (synthetic content only)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import check_commit_msg
import git_safety_check

SCRIPT = ROOT / "scripts" / "git_safety_check.py"
# Built at runtime so this file itself never contains a token-shaped literal.
GH_LIKE = "gh" + "p_" + "A1b2C3d4" * 5


@pytest.mark.parametrize(
    ("path", "forbidden"),
    [
        (".env", True),
        (".env.production", True),
        (".env.example", False),
        ("deploy/server.pem", True),
        ("keys/id_ed25519", True),
        ("data/customers.csv", True),
        ("sub/real_data/x.json", True),
        ("build/sample.sanitized.csv", True),
        (".claude/settings.local.json", True),
        ("src/ciphergate/cli.py", False),
        ("examples/sample.csv", False),
    ],
)
def test_forbidden_paths(path: str, forbidden: bool) -> None:
    assert (git_safety_check.forbidden_reason(path) is not None) is forbidden


def test_secret_scan_markers_and_allowlist() -> None:
    real_looking = f"value {GH_LIKE}"
    synthetic = "api_key = TEST_ONLY_NOT_A_CREDENTIAL"
    data = f"ok line\n{real_looking}\n{synthetic}\n".encode()
    flagged = git_safety_check.scan_secrets("f.txt", data, frozenset())
    assert [line for line, _ in flagged] == [2]
    allow = frozenset({("f.txt", git_safety_check.line_digest(real_looking))})
    assert git_safety_check.scan_secrets("f.txt", data, allow) == []
    # The allowlist is path-specific and content-bound.
    assert git_safety_check.scan_secrets("other.txt", data, allow)
    assert git_safety_check.scan_secrets("f.txt", data.replace(b"A1b2", b"Z9y8"), allow)
    assert git_safety_check.scan_secrets("bin", b"\0" + data, frozenset()) == []


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git not available")

    def run(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    run("init", "-q", "-b", "main")
    run("config", "user.email", "test@example.invalid")
    run("config", "user.name", "Test")
    return tmp_path


def check(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], check=False, cwd=repo, capture_output=True, text=True
    )


def test_staged_scan_never_prints_content(repo: Path) -> None:
    (repo / "config.txt").write_text(f"value {GH_LIKE}\n", encoding="utf-8")
    (repo / ".env").write_text("NAME=value\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", "."], cwd=repo, check=True)
    result = check(repo, "--staged", "--suggest-allowlist")
    assert result.returncode == 1
    assert "config.txt:1" in result.stdout and "[secret_pattern]" in result.stdout
    assert ".env: forbidden path" in result.stdout
    assert GH_LIKE not in result.stdout + result.stderr
    assert "NAME=value" not in result.stdout


def test_protected_branch_and_clean_feature_branch(repo: Path) -> None:
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    on_main = check(repo, "--staged", "--require-feature-branch")
    assert on_main.returncode == 1 and "[protected_branch]" in on_main.stdout
    subprocess.run(["git", "checkout", "-q", "-b", "feat/x"], cwd=repo, check=True)
    ok = check(repo, "--staged", "--require-feature-branch")
    assert ok.returncode == 0 and "not proof of absence" in ok.stdout


def test_large_file_rejected(repo: Path) -> None:
    (repo / "big.bin").write_bytes(b"x" * 2048)
    subprocess.run(["git", "add", "big.bin"], cwd=repo, check=True)
    result = check(repo, "--staged", "--max-bytes", "1024")
    assert result.returncode == 1 and "[file_too_large]" in result.stdout


def test_repository_itself_is_clean() -> None:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--all"],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    "message",
    [
        "feat(cli): add explain command",
        "fix: keep CSV header order",
        "security(policy)!: block credentials in header cells",
        "docs: describe branch workflow\n\nLonger body explaining why.\n",
        "Merge branch 'main' into feat/x",
        "fixup! feat: thing",
    ],
)
def test_valid_commit_messages(message: str) -> None:
    assert check_commit_msg.problems_for(message) == []


@pytest.mark.parametrize(
    "message",
    [
        "",
        "update stuff",
        "Feat: capitalised type",
        "feat: ends with a period.",
        "feat(Bad Scope): x",
        "feat: " + "x" * 80,
        "feat: subject\nbody without blank line",
    ],
)
def test_invalid_commit_messages(message: str) -> None:
    assert check_commit_msg.problems_for(message)


def test_commit_msg_cli(tmp_path: Path) -> None:
    good = tmp_path / "MSG"
    good.write_text("ci: run safety check\n# comment\n", encoding="utf-8")
    assert check_commit_msg.main([str(good)]) == 0
    assert check_commit_msg.main(["--title", "wip"]) == 1
    assert check_commit_msg.main([str(tmp_path / "missing")]) == 2
