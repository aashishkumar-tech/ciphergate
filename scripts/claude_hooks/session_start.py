"""Claude Code SessionStart hook: prints a short, static reminder (added to Claude's context).

Never reads environment variables, keys, datasets or file contents. No network.
"""

from __future__ import annotations

import sys

REMINDER = """CipherGate project reminders:
- Verify: python -m pytest -q; ruff check src tests scripts;
  ruff format --check src tests scripts; mypy
- Never print, log, or put into reports/tests/docs any raw value, secret or HMAC key.
- Fixtures/examples are synthetic only (example.com/.invalid, TEST_ONLY_* strings).
- Policy changes: run ciphergate validate-policy and the environment-matrix tests.
- Fail closed: missing rule/key/context must never become allow. Never weaken tests to pass.
- Git: feature branches only (never commit to main); follow /git-workflow.
- Skills: /policy-review, /ciphergate-security-review, /test-and-verify, /release-readiness,
  /git-workflow."""


def main() -> int:
    sys.stdin.read()  # consume the event; it is not needed
    print(REMINDER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
