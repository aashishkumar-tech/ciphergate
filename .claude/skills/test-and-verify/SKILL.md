---
name: test-and-verify
description: Run CipherGate's quality gates (pytest with coverage, ruff lint/format, mypy, policy validation, CLI smoke test, package build) and summarise exact commands and results. Use after code changes or when asked to verify the project.
allowed-tools: Bash(python -m pytest *), Bash(ruff *), Bash(mypy*), Bash(ciphergate *), Bash(python -m build *), Read, Grep, Glob
---

# Test and verify

Use the project virtualenv if present (`.venv/Scripts/` on Windows, `.venv/bin/` elsewhere).
Run each command, record exit code and a one-line result. Do not stop at the first failure.

```bash
python -m pytest -q --cov=ciphergate --cov-report=term
ruff check src tests scripts
ruff format --check src tests scripts
mypy
for f in policies/*.yml src/ciphergate/templates/*.yml; do ciphergate validate-policy "$f" --quiet; done
ciphergate --version
python -m build --wheel --outdir build/dist
```

Optional end-to-end smoke (synthetic data, needs a throwaway key in the environment):
`ciphergate sanitize examples/sample.csv --policy policies/prd_external_ai.yml --output build/smoke.csv --apply --force`.

## Rules

- Report failures with the failing test IDs and the assertion/lint code, not source dumps.
- Never delete, skip, xfail or weaken a test, lower a coverage threshold or add ignores to make
  checks pass. Fix the code, or report the failure as unresolved.
- Mark anything that could not run (missing tool, platform-only test) as **not verified**.

## Output

A table: command | exit code | result. Then failures, then items not verified.
