<!-- Title: Conventional Commits, e.g. "fix(readers): scan CSV header cells" (checked by CI). -->

## What and why

<!-- What changes, and the problem it solves. Link the issue: "Fixes #123" / "Refs #123". -->

## Type

- [ ] feat  - [ ] fix  - [ ] security  - [ ] perf  - [ ] refactor  - [ ] test
- [ ] docs  - [ ] build  - [ ] ci  - [ ] chore  - [ ] breaking change (schema / CLI / exit codes)

## Security and privacy impact

<!-- Required. Could this change leak raw values or keys, weaken a fail-closed path, change
policy precedence/context gates, path or atomic-write safety, or add a network call or
dependency? Say "none" only after checking. -->

## How it was verified

<!-- Exact commands and results. State anything NOT verified. -->

```text
ruff format --check src tests scripts
ruff check src tests scripts
mypy
python -m pytest -q --cov=ciphergate
python scripts/git_safety_check.py --all
```

## Checklist

- [ ] Branch is not `main`; commits follow Conventional Commits
- [ ] Tests added/updated for the behaviour change (no tests weakened, skipped or deleted)
- [ ] Only synthetic data in fixtures, examples, docs and this PR; no secrets or keys
- [ ] Policy changes validated (`ciphergate validate-policy`) and covered by tests
- [ ] Docs match behaviour; no compliance or "guaranteed safe" claims
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes
