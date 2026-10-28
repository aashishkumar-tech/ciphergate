"""Structural checks for .claude/ configuration and behaviour tests for the hook scripts.

These validate files against the documented schema shape; they do not prove Claude Code loads
them (see docs/claude-code-tooling.md for manual verification steps).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CLAUDE = ROOT / ".claude"
HOOKS = ROOT / "scripts" / "claude_hooks"
SKILL_FIELDS = {
    "name",
    "description",
    "when_to_use",
    "argument-hint",
    "arguments",
    "disable-model-invocation",
    "user-invocable",
    "allowed-tools",
    "disallowed-tools",
    "model",
    "effort",
    "context",
    "agent",
    "background",
    "hooks",
    "paths",
    "shell",
}
AGENT_FIELDS = {
    "name",
    "description",
    "tools",
    "disallowedTools",
    "model",
    "permissionMode",
    "maxTurns",
    "skills",
    "mcpServers",
    "hooks",
    "memory",
    "background",
    "effort",
    "isolation",
    "color",
}
READ_ONLY = {"Read", "Grep", "Glob"}


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    _, fm, body = text.split("---\n", 2)
    assert body.strip(), f"{path} has an empty body"
    data = yaml.safe_load(fm)
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize(
    "path", sorted((CLAUDE / "skills").glob("*/SKILL.md")), ids=lambda p: p.parent.name
)
def test_skill_frontmatter(path: Path) -> None:
    fm = frontmatter(path)
    assert set(fm) <= SKILL_FIELDS, set(fm) - SKILL_FIELDS
    assert fm["name"] == path.parent.name and 20 < len(fm["description"]) < 1536
    assert fm["name"] != "security-review"  # would replace the bundled /security-review


def test_expected_skills_and_agents_exist() -> None:
    skills = {p.parent.name for p in (CLAUDE / "skills").glob("*/SKILL.md")}
    assert skills == {
        "policy-review",
        "ciphergate-security-review",
        "test-and-verify",
        "release-readiness",
        "git-workflow",
    }
    agents = {p.stem for p in (CLAUDE / "agents").glob("*.md")}
    assert agents == {"security-reviewer", "policy-engine-reviewer", "test-reviewer"}


@pytest.mark.parametrize("path", sorted((CLAUDE / "agents").glob("*.md")), ids=lambda p: p.stem)
def test_agent_frontmatter_least_privilege(path: Path) -> None:
    fm = frontmatter(path)
    assert set(fm) <= AGENT_FIELDS and {"name", "description", "tools"} <= set(fm)
    assert fm["name"] == path.stem and ":" not in fm["name"]
    tools = {t.strip() for t in fm["tools"].split(",")}
    if path.stem == "test-reviewer":
        assert tools == READ_ONLY | {"Bash"}
    else:
        assert tools == READ_ONLY  # reviewers cannot write or run commands


def test_settings_schema_shape() -> None:
    settings = json.loads((CLAUDE / "settings.json").read_text(encoding="utf-8"))
    assert set(settings) <= {"$schema", "permissions", "hooks"}
    assert not (CLAUDE / "settings.local.json").exists() or "settings.local.json" in (
        ROOT / ".gitignore"
    ).read_text(encoding="utf-8")
    for event, groups in settings["hooks"].items():
        assert event in {"SessionStart", "PostToolUse"}
        for group in groups:
            assert set(group) <= {"matcher", "hooks"}
            for hook in group["hooks"]:
                assert hook["type"] == "command" and 0 < hook["timeout"] <= 60
                script = hook["command"].split("/")[-1].rstrip('"')
                assert (HOOKS / script).is_file()
    text = json.dumps(settings)
    assert "http" not in text.replace("https://json.schemastore.org", "")
    assert ":\\\\" not in text and "/Users/" not in text  # no machine-specific paths


def run_hook(script: str, event: dict | str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(ROOT), "CIPHERGATE_HMAC_KEY": "hex:" + "ab" * 40}
    payload = event if isinstance(event, str) else json.dumps(event)
    return subprocess.run(
        [sys.executable, str(HOOKS / script)],
        input=payload,
        text=True,
        capture_output=True,
        timeout=60,
        env=env,
        check=False,
    )


def test_session_start_hook() -> None:
    r = run_hook("session_start.py", {"hook_event_name": "SessionStart", "source": "startup"})
    assert r.returncode == 0 and "CipherGate project reminders" in r.stdout
    assert "abab" not in r.stdout


@pytest.mark.parametrize(
    "event",
    [
        "not json",
        {},
        {"tool_input": {}},
        {"tool_input": {"file_path": "/elsewhere/x.py"}},
        {"tool_input": {"file_path": str(ROOT / "README.md")}},
    ],
)
def test_post_edit_hook_ignores_irrelevant(event: dict | str) -> None:
    r = run_hook("post_edit_check.py", event)
    assert r.returncode == 0 and r.stderr == ""


def test_post_edit_hook_clean_python_and_policy() -> None:
    for target in (
        ROOT / "src" / "ciphergate" / "constants.py",
        ROOT / "policies" / "dev_local.yml",
    ):
        r = run_hook(
            "post_edit_check.py",
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Edit",
                "tool_input": {"file_path": str(target)},
            },
        )
        assert r.returncode == 0, r.stderr


def test_post_edit_hook_reports_lint_without_source(tmp_path: Path) -> None:
    bad = ROOT / "scripts" / "claude_hooks" / "_tmp_hook_probe.py"
    bad.write_text(
        "import os\nSECRET_VALUE_FOR_TEST = 'TEST_ONLY_NOT_A_CREDENTIAL'\n", encoding="utf-8"
    )
    try:
        r = run_hook(
            "post_edit_check.py", {"tool_name": "Write", "tool_input": {"file_path": str(bad)}}
        )
    finally:
        bad.unlink()
    if "not verified" in r.stderr:
        pytest.skip("ruff unavailable to the hook")
    assert r.returncode == 2 and "F401" in r.stderr
    assert "TEST_ONLY_NOT_A_CREDENTIAL" not in r.stderr


def test_post_edit_hook_reports_invalid_policy() -> None:
    bad = ROOT / "policies" / "_tmp_invalid_probe.yml"
    bad.write_text(
        "policy_version: 1\nname: probe\nrules:\n  - id: r\n    match: {categories: "
        "[credential.secret]}\n    action: allow\n",
        encoding="utf-8",
    )
    try:
        r = run_hook(
            "post_edit_check.py", {"tool_name": "Write", "tool_input": {"file_path": str(bad)}}
        )
    finally:
        bad.unlink()
    if "not verified" in r.stderr:
        pytest.skip("ciphergate CLI unavailable to the hook")
    assert r.returncode == 2 and "credential_unsafe_action" in r.stderr
