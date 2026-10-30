# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/);
versioning: [PEP 440](https://peps.python.org/pep-0440/) with SemVer meaning (pre-1.0: minor versions may break;
`aN` = alpha pre-release).

## [Unreleased]

### Changed

- Starter policies: `dev_local` keeps stack-trace frames and source lines (`stack_trace`
  detector) for local debugging. `developer_logs` keeps them for `local_dev`, `approved_internal`
  and `production_monitoring` and redacts them for every other destination. Before, these
  findings fell back to review with `--format stacktrace`. Other `proprietary.source` findings
  are unchanged.

## [0.6.0] - 2026-10-30

Adds stack-trace-aware log input as `--format stacktrace`. Existing formats behave as before.

### Added

- Stack-trace format (#47): `--format stacktrace` scans each line like `text` and also
  recognises Python tracebacks and JVM/Node.js frames. Frame and Python source lines get a
  `proprietary.source` finding from the new `stack_trace` detector (`/stack/frames/N`,
  `/stack/frames/N/source`), so policies can redact, review or block them; exception lines get
  `/stack/exception` (`/stack/caused_by`, `/stack/suppressed`). No lookahead or buffering;
  never selected from the file extension.

## [0.5.0] - 2026-10-29

Adds syslog (RFC 5424 and RFC 3164) and CEF parsing as `--format syslog`. Existing formats
behave as before; rescan additionally recognises CipherGate markers inside escaped fields.

### Added

- syslog/CEF format (#46): `--format syslog` for RFC 5424 and RFC 3164 lines (including rsyslog
  files) and CEF records, bare or as a syslog message. Header fields, RFC 5424 structured-data
  parameters (`/sd/<sd-id>/<name>`) and CEF headers and extensions (`/cef/extension/<key>`)
  become fields. Short CEF keys get canonical names for the field-name heuristics (`suser`,
  `src`, ...; `csN` via `csNLabel`) while findings keep the raw key. Escapes are decoded for
  scanning and re-applied to replacements; every rewritten line must still parse.

### Changed

- Rescan recognises a field whose whole decoded value is a CipherGate marker or replacement,
  even when a pattern matched only part of its escaped form (e.g. `[REDACTED:...\]` in syslog
  structured data).

## [0.4.0] - 2026-10-29

Adds two structured log formats, JSON-in-log and nginx/Apache access logs, and fixes a phone
detection gap in logfmt. Existing formats behave as before, except that `remote_user` fields
are now classified as customer identifiers.

### Added

- JSON-in-log format (#39): `--format jsonlog` for log lines that embed JSON objects. Each line
  is scanned exactly like `text`; embedded objects add field context (JSON Pointer paths,
  field-name heuristics and policy classifications on keys, decoding of escaped values and
  keys). Rewrites are JSON-escaped and re-validated; a rewrite that would break an embedded
  object fails the run. Never selected from the file extension.
- Access-log format (#39): `--format accesslog` for nginx/Apache common and combined lines.
  Fields get nginx variable names (`/remote_addr`, `/request/path`, `/http_user_agent`, ...),
  query parameters of the request and referer become fields (`/request/query/<name>`), and log
  escapes and percent-encoding are decoded for scanning. Replacements are re-encoded per field
  and every rewritten line must still parse, or the run fails.

### Changed

- The `remote_user` field name is now classified as `pii.customer_identifier` in every format.

### Fixed

- Phone numbers inside a value whose field name implies email (for example
  `email="call 202-555-0143"` in logfmt) are no longer suppressed by the whole-value field-name
  finding.

## [0.3.0] - 2026-10-29

Adds the Python API for streams and directories, and fixes a macOS path-safety bug in
directory runs that shipped in 0.2.0. CLI behaviour on Linux and Windows is unchanged.

### Added

- Python API for streams and directories (#38): `inspect_stream`, `plan_stream`,
  `rescan_stream` and `sanitize_stream` take binary streams (format required; input spooled to
  a private, size-capped workspace; output written only after a successful run).
  `inspect_directory`, `plan_directory`, `rescan_directory` and `sanitize_directory` expose
  directory runs and return the newly exported `BatchReport`. `sanitize_directory` refuses
  `force=True`, as the CLI does.

### Changed

- CI runs the test suite on macOS (py3.12) again (#37). Case-alias tests now run on any
  case-insensitive filesystem instead of only on Windows.

### Fixed

- macOS: a directory run accepted an output directory inside the input directory when the
  output path used a different letter case (`--output IN/out` for input `in`), because path
  comparison relied on `normcase`, which does nothing on POSIX. The check now compares file
  identity up the parent chain. The same applies to `--report` placement in directory runs.
  Windows and Linux were not affected. Found by the new macOS CI job (#37).

## [0.2.0] - 2026-10-29

Feature release. Existing policies, reports and single-file behaviour are unchanged, except
where noted below.

### Added

- Optional local NER detector (#7): `pip install 'ciphergate[ner]'` plus a user-installed spaCy
  model; enable with `detectors.presidio` in the policy (off by default). Presidio entities map
  to categories (default `PERSON` -> `pii.person_name`, `LOCATION` -> `location.coarse`) and
  findings use detector `presidio_ner`. A missing extra or model fails with exit 6 and is never
  downloaded. Third-party error messages are replaced. Tested with a fake engine only.
- Directory (batch) runs (#9): `inspect`, `plan`, `rescan` and `sanitize` accept a directory
  INPUT, with `--recursive` and `--max-files` (default 1000). Symlinks, junctions and special
  files are skipped and reported, never followed. `sanitize` stages the whole output tree and
  publishes a new directory only if every file was sanitized. Batch report schema
  `ciphergate.batch-report/v1`; the exit code is the first failing file's. CLI only.
- logfmt format (#11): `--format logfmt` for `key=value` log lines. Each line is scanned exactly
  like `text` (property-tested: never fewer findings), plus field context: findings inside a
  value are attributed to that field (`/key`) and field-name heuristics run on keys, so policy
  field rules apply to log fields. Lines are rewritten span by span, preserving quoting.
  `drop_field` becomes `review`. In span transforms, each finding now uses its own field path
  for pseudonym scope (unchanged for existing formats).
- Key files (#10): set `<key_env>_FILE` (e.g. `CIPHERGATE_HMAC_KEY_FILE`) to a key file path.
  The file must be regular and at most 4 KiB; on POSIX it must be owned by the current user with
  no group/other permissions (symlink targets are checked). Windows ACLs are not checked (a
  warning is logged). Setting both sources is refused. Failures exit 6 (`key_file_invalid`)
  without output. Reports add the key `source` (`env`/`file`), never the path.
- stdin/stdout support in the CLI (#8): `-` as INPUT for `inspect`, `plan`, `sanitize` and
  `rescan` (requires `--format`), and `sanitize --output -`. stdin is spooled to a private,
  size-capped temporary workspace that is always removed; stdout receives data only after every
  check passed, with the summary on stderr. A closed pipe exits 5 (`stdout_broken_pipe`).
  `--report -` is refused (it would previously have created a file named `-`).

### Changed

- Run reports list a `source` for each key (`env` or `file`).
- The Python API still rejects a directory input (`input_is_directory`); the message now points
  to the CLI, which supports directory runs.

## [0.1.1] - 2026-10-29

Patch release: corrects the declared minimum dependency versions and hardens CI. No change
to detection, policy or transform behaviour.

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
  range, groups Actions updates, and never updates `ci/constraints-min.txt`.

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

[Unreleased]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/aashishkumar-tech/ciphergate/compare/v0.1.0a1...v0.1.0
[0.1.0a1]: https://github.com/aashishkumar-tech/ciphergate/releases/tag/v0.1.0a1
