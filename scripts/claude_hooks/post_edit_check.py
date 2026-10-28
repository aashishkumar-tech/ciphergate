"""Claude Code PostToolUse hook: fast, local checks on the single file just edited.

* ``*.py`` under the repository -> ``ruff check --output-format concise`` on that file only.
* ``policies/*.yml`` / ``src/ciphergate/templates/*.yml`` -> ``ciphergate validate-policy``.

Contract (Claude Code hooks): reads the event JSON from stdin; exit 0 = nothing to report;
exit 2 = findings, printed to stderr so Claude sees them. Prints only tool diagnostics (codes,
line numbers, rule IDs) — never file contents, environment variables or data values. No network.
Missing tools are reported as "skipped (not verified)", never as passed. CI remains authoritative.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

TIMEOUT_SECONDS = 20
MAX_OUTPUT_LINES = 25


def project_root() -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])


def venv_tool(root: Path, name: str) -> str | None:
    for sub in ("Scripts", "bin"):
        for suffix in (".exe", ""):
            candidate = root / ".venv" / sub / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)
    return shutil.which(name)


def run(argv: list[str], root: Path) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, cwd=root, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired:
        return -1, "check timed out (not verified)"
    except OSError:
        return -1, "check could not start (not verified)"
    lines = (proc.stdout + proc.stderr).strip().splitlines()[:MAX_OUTPUT_LINES]
    return proc.returncode, "\n".join(lines)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # malformed event: nothing safe to do
    tool_input = event.get("tool_input") or {}
    raw_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not isinstance(raw_path, str) or not raw_path:
        return 0
    root = project_root().resolve()
    try:
        path = Path(raw_path).resolve()
        rel = path.relative_to(root)
    except (ValueError, OSError):
        return 0  # outside the repository: not our business
    if not path.is_file() or rel.parts[:1] in ((".venv",), (".git",)):
        return 0

    if path.suffix == ".py":
        ruff = venv_tool(root, "ruff")
        if ruff is None:
            print(
                f"ciphergate hook: ruff not found; lint skipped for {rel.as_posix()} "
                "(not verified)",
                file=sys.stderr,
            )
            return 0
        code, output = run(
            [ruff, "check", "--output-format", "concise", "--no-cache", str(rel)], root
        )
        if code == 1:
            print(f"ciphergate hook: ruff findings in {rel.as_posix()}:\n{output}", file=sys.stderr)
            return 2
        if code not in (0, 1):
            print(
                f"ciphergate hook: ruff did not complete for {rel.as_posix()} (not verified)",
                file=sys.stderr,
            )
        return 0

    is_policy = path.suffix in (".yml", ".yaml") and (
        rel.parts[:1] == ("policies",) or rel.parts[:3] == ("src", "ciphergate", "templates")
    )
    if is_policy:
        exe = venv_tool(root, "ciphergate")
        if exe is None:
            print(
                "ciphergate hook: ciphergate CLI not installed; policy validation skipped "
                "(not verified)",
                file=sys.stderr,
            )
            return 0
        code, output = run([exe, "validate-policy", str(rel), "--quiet"], root)
        if code == 3:
            print(
                f"ciphergate hook: policy {rel.as_posix()} failed validation:\n{output}",
                file=sys.stderr,
            )
            return 2
        if code != 0:
            print(
                f"ciphergate hook: policy validation did not complete for {rel.as_posix()} "
                "(not verified)",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
