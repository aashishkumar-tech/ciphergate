# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
pre-commit install --hook-type pre-commit --hook-type commit-msg   # local hooks only
```

Run `git commit` with the virtual environment active: the hooks call `python` and need the
`ciphergate` package installed.

## Checks (all must pass)

```bash
python -m pytest -q --cov=ciphergate      # >= 85% overall; CI fails below 85%
ruff check src tests scripts
ruff format --check src tests scripts
mypy                                       # strict
for f in policies/*.yml src/ciphergate/templates/*.yml; do ciphergate validate-policy "$f"; done
```

CI also runs the suite at the lowest supported runtime versions (`ci/constraints-min.txt`, the
`min-deps` job). To change a lower bound in `pyproject.toml`, update that file in the same PR.
Workflow actions must be pinned to a full commit SHA with a `# vX.Y.Z` comment.

## Rules for changes

- **Synthetic data only.** Fixtures and examples use `example.com`/`.invalid`, `USER_TEST_*`,
  `TEST_ONLY_*` and private/documentation IP ranges. Never commit real data, logs or keys.
- **No values in output.** Findings, errors, logs and reports never contain raw values, matched
  text or keys. Add a leak test in `tests/security/` for any new output path.
- **Fail closed.** New options must not let missing configuration become `allow`. Document any
  setting that can weaken protection and make validation warn about it.
- **Detectors** need positive, negative, edge and ambiguity tests and an entry in
  `docs/detector-coverage.md`. Keep regexes bounded.
- **Policy compatibility.** Changes to `policy_version: 1` semantics must keep existing policies
  valid or bump the version; update `docs/policy-schema.md`; shipped policies must validate.
- **Transform changes** that alter output for the same input/key need a new transform version
  (`pz1` -> `pz2`) and a changelog entry.
- Never delete, skip or weaken tests to make CI green. Add a regression test for each bug fix.
- No network access or telemetry in `src/`.
- Update `CHANGELOG.md` (Unreleased section).

## Branches, commits and pull requests

The full procedure is in `.claude/skills/git-workflow/SKILL.md` (also usable as `/git-workflow`
in Claude Code). In short:

- **Never commit to `main`.** Branch from an up-to-date `main` as `<type>/<summary>`
  (`feat/`, `fix/`, `security/`, `perf/`, `refactor/`, `test/`, `docs/`, `build/`, `ci/`,
  `chore/`). `main` changes only through squash-merged pull requests with green CI.
- **Conventional Commits** (`fix(readers): scan CSV header cells`), checked by the `commit-msg`
  hook and, for PR titles, by CI (`scripts/check_commit_msg.py`).
- **Safety check before every commit** (`scripts/git_safety_check.py --staged
  --require-feature-branch`; CI runs `--all`): refuses commits on `main`, env/key/data/output
  files, files over 1 MiB, and secret-like lines without a synthetic marker. Reviewed false
  positives go in `.github/git-safety-allowlist.txt` (path + line hash, with a reason). It is a
  pattern scanner: passing is not proof that nothing sensitive is committed.
- Rebase your branch onto `origin/main` to sync; `--force-with-lease` only on your own branch;
  never force-push `main`, never `--no-verify`.
- Every PR uses the template (security/privacy impact and exact verification commands are
  required), links an issue, carries a type label and a milestone.
- Vulnerabilities are reported privately (SECURITY.md), never in a public issue.

`main` is protected on GitHub (#6), and the rules also apply to administrators:
- changes arrive only through a pull request;
- all 7 CI checks must pass on a branch that is up to date with `main`;
- PR conversations must be resolved;
- history stays linear (squash merge only);
- `main` cannot be force-pushed or deleted.

No approving review is required, because GitHub does not let an author approve their own PR
and the project currently has a single maintainer. The second-reviewer rule below still
applies whenever a second maintainer is available.

**If you rename or add a CI job**, update the required status checks in the branch
protection settings in the same change. Otherwise every PR waits forever for a check that
never runs.

## Security-sensitive review

Changes to `policy/`, `transforms/`, `pipeline/`, `reporting/`, `readers/` or `cli.py` need a
second reviewer. The `/ciphergate-security-review` skill and `security-reviewer` agent can help;
they do not replace human review.

## Ready to merge

All CI jobs pass (`repo-safety`, `test` matrix, `min-deps`, `install-smoke`); the PR title is a valid
Conventional Commit; docs and changelog match behaviour; new behaviour is tested (including a
negative/fail-closed case); no compliance or "guaranteed" claims were added.
