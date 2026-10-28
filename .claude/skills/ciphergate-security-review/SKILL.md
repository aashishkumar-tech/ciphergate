---
name: ciphergate-security-review
description: CipherGate-specific security and privacy review of current changes — raw-value leakage, key handling, unsafe defaults, path/atomic-write safety, false assurance, network behaviour and policy bypasses. Use before merging changes to src/, policies/, scripts/ or reporting code. (Named to avoid replacing the bundled /security-review.)
allowed-tools: Read, Grep, Glob, Bash(git diff *), Bash(git status *)
---

# CipherGate security review

Scope: the working-tree diff (`git diff` / `git status`) or the paths in `$ARGUMENTS`.
You may delegate a read-only pass to the `security-reviewer` subagent; verify its findings.

## Checklist (cite `file:line` for every finding)

1. **Raw-value leakage**: no value, matched text, line/row content or key in `Finding`,
   exceptions, `logging` calls, reports (`reporting/`), terminal output, test assertion
   messages or fixtures. Third-party error messages (json, csv, yaml, pydantic) must be
   replaced, not forwarded. Check `include_input=False` on pydantic errors.
2. **Keys**: only from named env vars; never CLI flags, defaults, fallbacks, logs or repr.
   HMAC with domain separation; no plain/unkeyed hashes as pseudonyms or fingerprints.
3. **Fail-closed**: missing rule/context/key/approval never becomes `allow` or a published
   output. `block`/`review` never reach the transformer. Credentials are never allowed.
4. **Paths and output**: input/output aliasing, symlinks, overwrite without `--force`,
   temp-file cleanup, atomic publish only after rescan and input-unchanged checks.
5. **Resource safety**: new regexes bounded (no nested quantifiers), size/depth limits kept,
   no unbounded reads.
6. **Network**: no new imports of socket/http/urllib/requests in `src/`; no downloads.
7. **False assurance**: docs/messages must not claim compliance, guaranteed anonymization or
   that a passing scan proves safety.
8. **Tests**: security-relevant changes have tests in `tests/security/`; no test weakened.

## Output

Findings grouped **Critical / High / Medium / Low** with evidence and a concrete fix. If no
issues are found, say which checklist items were examined and that this is not a full audit.
Never claim a clean security audit without evidence.
