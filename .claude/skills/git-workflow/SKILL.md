---
name: git-workflow
description: CipherGate's production Git/GitHub workflow — feature branches only (never commit to main), Conventional Commits, pre-commit secret/path safety checks, pull/rebase, push, pull requests with CI, issues/labels/milestones, and releases. Use whenever asked to commit, branch, pull, push, open/update a PR, merge, tag or release, or to track work in GitHub.
---

# Git and GitHub workflow (CipherGate)

CipherGate protects sensitive data, so the repository is held to the same standard: nothing
reaches `main` without a branch, a reviewed pull request and green CI, and nothing sensitive is
ever committed. This skill is the procedure; `scripts/git_safety_check.py` and
`scripts/check_commit_msg.py` are the deterministic checks it relies on.

## Ground rules (never break these)

1. **Act only on explicit request.** Commit, push, open/merge a PR, tag or release only when the
   user asked for that action in this conversation. Approval for one push is not approval for the
   next. Never change global git config or credentials.
2. **Never commit to `main`.** All work happens on a short-lived branch from an up-to-date `main`.
   The only exception is the one-time empty bootstrap commit of a brand-new repository, which
   must be stated to the user.
3. **Never** `git push --force` to `main`, `--no-verify`, `--no-gpg-sign`, `git add -A`/`git add .`
   without reviewing the list, rewrite pushed shared history, or `git reset --hard`/`git clean`
   without explicit approval for that exact command.
4. **Never commit** `.env*` (except placeholder-only `.env.example`), keys/certificates, HMAC keys,
   real datasets, CipherGate output/report files, `.claude/settings.local.json`, or anything
   copied from production. Fixtures are synthetic only (`TEST_ONLY_*`, `example.invalid`).
5. **Never print secrets** in commit messages, PR text, issue comments or terminal output.
6. **Do not hide failures.** If a check fails, fix the cause or report it; never weaken a test,
   skip a hook or mark a check as passed to get a commit through.

## 1. Start work

```bash
git switch main && git pull --ff-only origin main
git switch -c <type>/<short-kebab-summary>        # e.g. fix/csv-header-scan
```

Branch prefixes: `feat/ fix/ security/ perf/ refactor/ test/ docs/ build/ ci/ chore/`
(lowercase, ≤ 50 characters). Link substantial work to a GitHub issue; mention it in the branch
or PR (`fix/123-csv-header-scan`).

## 2. Before every commit

Run from the repository root with the dev environment active:

```bash
ruff format --check src tests scripts && ruff check src tests scripts && mypy
python -m pytest -q                                  # or the relevant subset while iterating
python scripts/git_safety_check.py --staged --require-feature-branch
```

For policy changes also run `ciphergate validate-policy` on each changed file (see
`/policy-review`). For security-sensitive changes (src/, policies/, scripts/, reporting) run
`/ciphergate-security-review` before opening the PR.

Stage deliberately: `git status --short`, then `git add <explicit paths>`, then
`git diff --cached --stat` and read the staged diff. One logical change per commit.

If `git_safety_check.py` reports `[secret_pattern]`: open the line yourself. If it is a real
credential, **remove it, do not commit, and tell the user it may need rotation**. Only a
reviewed false positive (keyword in prose, synthetic test vector) may be added to
`.github/git-safety-allowlist.txt` via `--suggest-allowlist`, with a specific reason per entry.

## 3. Commit message (Conventional Commits, enforced by `scripts/check_commit_msg.py`)

```
<type>(<scope>)!: <imperative summary, ≤72 chars, no trailing period>

Why the change is needed and what it changes (wrap ~72). Note security impact,
behaviour changes and migration steps. Never include data values or secrets.

Refs: #123
BREAKING CHANGE: <only when applicable>
Co-Authored-By: <attribution trailer required by the session, if any>
```

Types: `feat fix security perf refactor test docs build ci chore revert`. Scopes follow the
package layout: `cli policy engine detectors readers transforms pipeline reporting policies docs
ci tooling deps`. Use `security` for fixes to a vulnerability or fail-open behaviour, and `!` /
`BREAKING CHANGE:` for schema, CLI or exit-code changes. Write the message with a heredoc or
`-F file`, never by interpolating untrusted text into a shell command.

Update `CHANGELOG.md` under `[Unreleased]` in the same PR for any user-visible change.

## 4. Pull / sync

Keep the branch current by rebasing onto `main` (the branch is yours; `main` is never rebased):

```bash
git fetch origin
git rebase origin/main            # resolve conflicts, then: git add <files>; git rebase --continue
python -m pytest -q               # re-verify after every conflict resolution
```

Use `git pull --ff-only` on `main`; never create merge commits on `main` locally. If a rebase
goes wrong, `git rebase --abort` and ask.

## 5. Push

```bash
git push -u origin HEAD                       # first push of the branch
git push --force-with-lease origin HEAD       # only after rebasing YOUR OWN branch
```

Never push to `main` directly. If a push is rejected, fetch and inspect; do not force.

## 6. Pull request

```bash
gh pr create --base main --fill-first --title "<conventional title>" \
  --body-file <file using .github/pull_request_template.md> --label <type> [--milestone <m>]
gh pr checks --watch                            # wait for CI; report failures with their logs
```

- The PR title must pass `scripts/check_commit_msg.py --title` (CI checks it): it becomes the
  squash-commit subject.
- Fill every section of the template, including **security/privacy impact** and **how it was
  verified** with the exact commands. State what was *not* verified.
- CI must be green: `test` matrix, `install-smoke`, `repo-safety`. Do not merge red or pending.
- Merge with **squash** (linear history) after review, then delete the branch:
  `gh pr merge <n> --squash --delete-branch` — only when the user asks to merge.

## 7. Tracking work in GitHub

- **Issues** for every bug, feature and follow-up (use the issue forms). Security
  vulnerabilities go to the private contact in SECURITY.md, never a public issue.
- **Labels**: one type label (`bug enhancement security documentation ci dependencies chore
  tests`), plus `breaking` / `needs-review` / `blocked` where relevant.
- **Milestones** per release (e.g. `v0.1.0`); every merged PR belongs to one.
- Reference issues from commits/PRs (`Refs: #12`, `Fixes: #12` closes it on merge).
- Deferred work from reviews becomes issues, not TODOs in code.

## 8. Releases (only on request)

From an up-to-date `main` after CI is green: move `[Unreleased]` entries in `CHANGELOG.md`
to the new version, bump `__version__` in `src/ciphergate/__init__.py` (via a PR), then

```bash
git tag -a vX.Y.Z -m "CipherGate vX.Y.Z"     # annotated; signed (-s) if the user has signing set up
git push origin vX.Y.Z
gh release create vX.Y.Z --verify-tag --notes-file <release notes from CHANGELOG>
```

Releases are blocked while `LICENSE` is a placeholder or `SECURITY.md` has no real contact
(see `/release-readiness`).

## Reporting back

After any git operation, tell the user exactly what happened: branch, commit SHAs and subjects,
what was pushed where, PR URL, CI status per job, and anything skipped or unverified.
