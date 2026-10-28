# Claude Code tooling

Development aids only. CipherGate never depends on Claude Code at runtime, and none of this
replaces the product's own controls, tests or CI. Validated against Claude Code 2.1.312 and the
docs at code.claude.com (hooks, skills, sub-agents) on 2026-10-28.

## Skills (`.claude/skills/`)

| Skill | Use | Notes |
|---|---|---|
| `/policy-review [file]` | review/author policies; recommends tests | read + `ciphergate validate-policy/explain` only |
| `/ciphergate-security-review` | leak/key/fail-open/path/network/false-assurance checklist | **Named so it does not replace the bundled `/security-review`** (a project skill with the same name would) |
| `/test-and-verify` | runs pytest+coverage, ruff, mypy, policy validation, build | must not weaken tests |
| `/release-readiness` | release checklist (CLAUDE.md section 18) | `disable-model-invocation: true` (manual only) |
| `/git-workflow` | branches, Conventional Commits, safety checks, pull/rebase, push, PRs, issues, releases | acts only on explicit request; relies on `scripts/git_safety_check.py` and `scripts/check_commit_msg.py` |

## Subagents (`.claude/agents/`)

| Agent | Tools | Delegate when |
|---|---|---|
| `security-reviewer` | Read, Grep, Glob | independent read-only security/privacy pass |
| `policy-engine-reviewer` | Read, Grep, Glob | engine/validator/context/policy changes |
| `test-reviewer` | Read, Grep, Glob, Bash (documented: bounded pytest/coverage only) | coverage-gap analysis |

Reviewers return findings; the main session integrates changes and runs the full suite. Do not
let several agents edit the same files concurrently.

## Hooks (`.claude/settings.json`, scripts in `scripts/claude_hooks/`)

| Event | Script | Behaviour |
|---|---|---|
| `SessionStart` (`startup|resume|clear|compact`) | `session_start.py` | prints a static reminder of verification commands and privacy rules |
| `PostToolUse` (`Edit|Write|MultiEdit`) | `post_edit_check.py` | edited `*.py` in the repo -> `ruff check` on that file; edited `policies/*.yml` or templates -> `ciphergate validate-policy`. Findings exit 2 (shown to Claude). Missing tools print "not verified" and exit 0 |

Both scripts are local-only, time-bounded (20 s per check), print only tool diagnostics (never
file contents, env vars or values) and never run the full test suite. Hooks are not a security
boundary.

**Inspect:** run `/hooks` in Claude Code. **Test:** `python -m pytest tests/tooling`, or pipe an
event: `echo '{"tool_input":{"file_path":"src/ciphergate/cli.py"}}' | python scripts/claude_hooks/post_edit_check.py`.
**Disable:** set `"disableAllHooks": true` in your own `.claude/settings.local.json` (not committed),
or delete the `hooks` block. **Remove:** delete the `hooks` block and `scripts/claude_hooks/`.

The hooks invoke `python`; if your PATH only has `python3`/`py`, override in
`.claude/settings.local.json`.

## Permissions

`settings.json` only *denies* reading `.env*`, `*.key`, `*.pem`, `secrets/` and `data/`. No
allow-rules are shipped (per-user choice). Do not commit `.claude/settings.local.json`.

## Intentionally omitted

- **MCP servers / plugins:** no concrete need; the product is local-first.
- **PreToolUse guard for risky shell commands:** a reliable parser for arbitrary shell commands is
  not feasible; Claude Code's own permission prompts remain the control.
- **Hooks running the full test suite:** too slow per edit; use `/test-and-verify` and CI.

## Verification status

Automated (`tests/tooling/test_claude_tooling.py`): frontmatter fields against the documented
schema, least-privilege tool lists, settings shape, hook behaviour on representative events
(irrelevant paths, clean files, lint failure without source leakage, invalid policy).

**Manual verification required** (not performed live — the CLI's non-interactive commands do not
list project skills/agents in this version): open Claude Code in the repo and check that
`/policy-review`, `/ciphergate-security-review`, `/test-and-verify` and `/release-readiness` appear
in the `/` menu, that `/agents` lists the three subagents, that `/hooks` shows both hooks, and
that editing a Python file with a lint error surfaces the ruff message.
