---
name: release-readiness
description: Check whether CipherGate is ready to release — version/changelog consistency, documented limitations, policy validation, examples, clean-environment install, security tests, CI configuration and the CLAUDE.md section 18 acceptance checklist. Use before tagging or publishing a release.
disable-model-invocation: true
allowed-tools: Read, Grep, Glob, Bash(python -m pytest *), Bash(ciphergate *), Bash(python -m build *), Bash(python -m venv *), Bash(git status *), Bash(git tag *)
---

# Release readiness

1. **Version**: `src/ciphergate/__init__.py` `__version__` matches the top `CHANGELOG.md`
   entry and is not already tagged (`git tag`).
2. **Changelog**: the entry describes implemented behaviour only; deferred items are listed.
3. **Checks**: run the `/test-and-verify` skill; every item must pass or be explicitly
   accepted as not verified with a reason.
4. **Clean install**: build the wheel, create a fresh venv, install the wheel (not editable),
   run `ciphergate --version`, `ciphergate validate-policy` on every policy, and the README
   quick start against `examples/`.
5. **Docs honesty**: README, `docs/limitations.md`, `docs/detector-coverage.md`, SECURITY.md
   contain no compliance or "guaranteed" claims and match current flags/exit codes.
6. **Blockers needing the maintainer**: LICENSE still a placeholder? SECURITY.md contact still
   a placeholder? Package name availability checked? These block a *public* release.
7. **CI**: `.github/workflows/ci.yml` runs lint, types, tests, policy validation and the
   install smoke test on all supported Python versions.
8. Walk the CLAUDE.md section 18 checklist and mark each item met / not met / not verified.

## Output

Verdict (ready / not ready), blocking items, then the checklist table. Do not tag or publish.
