# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/);
versioning: [PEP 440](https://peps.python.org/pep-0440/) with SemVer meaning (pre-1.0: minor versions may break;
`aN` = alpha pre-release).

## [Unreleased]

### Fixed

- Runtime dependency floors were not actually supported: with `typer` 0.12–0.18 and a current
  `click`, most CLI commands failed. The minimum is now `typer>=0.19`, and `PyYAML>=6.0.1`
  (6.0 does not install on current Python). A new `min-deps` CI job runs the suite at the
  declared lower bounds (`ci/constraints-min.txt`) so floors stay tested (#5).

### Security

- CI actions are pinned to full commit SHAs (`actions/checkout` v7.0.1,
  `actions/setup-python` v7.1.0) and checkout no longer persists the GitHub credential; a
  tooling test enforces both (#5).
- Dependabot only raises dependency lower bounds when a new release falls outside the declared
  range, and groups Actions updates.

## [0.1.0] - 2026-10-28

First release (still alpha quality: pre-1.0, interfaces may change). Same software as 0.1.0a1,
plus a configured security contact. Policy templates still need review for each real workflow
(#3); a successful run is never proof that output contains no sensitive data.

### Added

- Security contact in `SECURITY.md` (email), target response times, report scope and
  supported versions (#2).

## [0.1.0a1] - 2026-10-28

Pre-release (alpha). Licensed under Apache-2.0. Not a final release: the security contact in
`SECURITY.md` is still a placeholder (#2), and policy templates need review for real workflows
(#3).

### Added

- Apache-2.0 license (`LICENSE`, `NOTICE`, package metadata).
- Repository workflow: `scripts/git_safety_check.py` (protected-branch, forbidden-path, size and
  secret-pattern checks with a hashed allowlist), `scripts/check_commit_msg.py` (Conventional
  Commits), pre-commit `git-safety`/`commit-msg` hooks, a `repo-safety` CI job with PR-title
  check, PR template, issue forms, Dependabot, and the `/git-workflow` Claude Code skill.
- `ciphergate` CLI (first implementation, #12): `init`, `validate-policy`, `inspect`, `plan`, `sanitize --apply`, `rescan`,
  `explain`, `--version`; documented exit codes 0–8 and 130.
- Python API: `load_policy`, `validate_policy`, `inspect_file`, `plan_file`, `sanitize_file`,
  `rescan_file`.
- Readers/writers for CSV, JSON, JSONL/NDJSON and text/log with size, line, depth and findings
  limits; strict UTF-8 by default.
- Detectors: field names, policy classifications, email, phone, IPv4/IPv6, Luhn cards, dates/DOB,
  secrets (incl. multi-line PEM blocks), internal hosts, custom regex with safety heuristics.
- Policy schema v1 (pydantic, unknown keys rejected), safe YAML loader, computed precedence
  levels, conflict rejection, credential hard constraints, risky-allow acknowledgement,
  environment/destination context with pinning and explicit overrides, run-level guardrails
  (PRD -> non-production, strict + rescan for external/unknown/prd targets), reviewed transfer
  approvals.
- Actions: allow, redact, replace, pseudonymize (HMAC-SHA-256, transform version `pz1`),
  generalize, date_shift, drop_field, drop_record, block, review. `tokenize` rejected.
- Two-pass sanitize with plan/apply consistency check, residual rescan gate, input-change
  detection and atomic, no-overwrite publishing.
- Privacy-safe JSON (`ciphergate.report/v1`) and text reports.
- Policy templates: dev_local, stg_test, prd_external_ai, developer_logs, test_dataset,
  external_ai, healthcare_template, financial_template, local_debug, multi_environment.
- Synthetic examples with expected outputs; docs; CI workflow; Claude Code skills, subagents and
  hooks for development.

### Changed

- CI tests Linux (Python 3.11-3.13) and Windows (3.12); macOS was dropped because hosted
  runners could not be acquired (#21).

### Security fixes before first release (from an independent review)

- CSV header cells are now scanned, transformed (allow/drop_field/block/review), rescanned and
  hidden in reports when they produce a finding; previously the header was published unscanned.
- The rescan gate can no longer be emptied: `fail_on_categories: []` is rejected,
  `credential.secret` always gates, and untrusted destinations gate on every high-risk category.
- A missing destination is treated as untrusted by run-level gates (strict + rescan required).
- `secret_pattern`/`field_name` cannot be disabled for strict/untrusted/transfer policies or runs.
- JSON keys must be scanned for untrusted destinations; all templates set `scan_json_keys: true`.
- Custom categories in high-risk families are high-risk; external/unknown target environments
  count as untrusted for `allow` acknowledgement.
- Transfer approvals must name every supplied context dimension; future `approved_on` rejected.
- Temp-file cleanup failures are logged; a report-write failure after publishing says so.
- `developer_logs` keeps identifiers for internal destinations only for DEV/STG-origin data.
- CSV writer quotes rows containing a lone CR/LF (previously such a value could be corrupted).

### Known limitations

See `docs/limitations.md`. Deferred: optional NER/Presidio detectors, stdin/stdout streaming,
directory processing, structured log parsers, key files, reversible token vault, lossy decoding.

[Unreleased]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.1.0a1...v0.1.0
[0.1.0a1]: https://github.com/aashishkumar-tech/ciphergate/releases/tag/v0.1.0a1
