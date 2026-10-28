---
name: policy-review
description: Review or author a CipherGate YAML policy (DEV/STG/PRD source environment vs destination, rule precedence, credential handling, fail-closed behaviour) and recommend tests. Use when a file under policies/ or src/ciphergate/templates/ is created or changed, or when asked whether a policy is safe.
argument-hint: "[policy file]"
allowed-tools: Read, Grep, Glob, Bash(ciphergate validate-policy *), Bash(ciphergate explain *)
---

# Policy review

Target: `$ARGUMENTS` (default: every changed file under `policies/`).

The schema and precedence are defined in `docs/policy-schema.md` and
`src/ciphergate/policy/precedence.py`. Read them; do not re-derive rules from memory.

## Steps

1. Run `ciphergate validate-policy <file>` (use `.venv` if present). Validation errors are
   blocking. Report warnings verbatim (acknowledged risky allows, transfer approvals, overrides).
2. Context: which of `environment`, `target_environment`, `destination` are pinned? Are the
   requirements consistent with the intended use? `environment` is where data came FROM;
   `destination` is who RECEIVES it — check they are not conflated. Flag any
   `allow_cli_override`.
3. Credentials: confirm `credential.secret` is `block` for untrusted destinations
   (`external_vendor`, `external_ai`, `public_repository`, `unknown`) and never `allow`.
4. For each `allow`: which categories and destinations can it reach? A high-risk category to
   an untrusted destination needs a documented justification, not only `acknowledge_risk`.
5. Precedence: for findings of interest, use
   `ciphergate explain --policy <file> --category <cat> --field <path> --environment <env>
   --target-environment <t> --destination <d>` and check the winning `rule_id` and
   `precedence`. Look for broad lower-level rules a reader might wrongly expect to win.
6. Fallback: `settings.unknown_sensitive_behavior` must be `review` or `block`; `strict` must
   be `true` for external/production targets.
7. `transfers` approvals: each must name a real reviewer and reference; flag placeholders.
8. Templates must say "template requiring review" and make no compliance claims
   (HIPAA/GDPR/PCI "compliant", "anonymized").

## Output

Findings by severity (blocking / should-fix / note) with `file:line`, then **recommended
tests**: at minimum add or update cases in `tests/integration/test_environment_matrix.py` and
`tests/unit/test_policy_engine.py` for every changed rule, including a negative case
(context where the rule must NOT apply). Do not edit the policy unless asked.
