# CipherGate

**Inspect and sanitize logs and test datasets before they leave their environment** — with
policies that depend on where the data came from (DEV/STG/PRD) *and* where it is going (local
debugging, internal monitoring, an external vendor or AI assistant, a public repository).

Teams often hand-redact logs or keep ad-hoc scripts before pasting data into an AI assistant or a
vendor ticket. CipherGate replaces that with a local, explainable, scriptable gate:

```
inspect  ->  plan  ->  sanitize --apply  ->  rescan
```

> **Status: 0.1.1 (alpha).** No detector finds every sensitive value. A passing run means the
> configured processing completed under the selected policy; it is **not** proof that the output
> contains no sensitive information, and it is not a compliance (GDPR, HIPAA, PCI DSS, ...) or
> anonymization guarantee. Policy templates must be reviewed before use.

## What it is / what it is not

| It is | It is not |
|---|---|
| A local CLI + Python library; no network calls, accounts or telemetry | A hosted service, dashboard, or AI classifier |
| Deterministic detectors + a separate, testable policy engine | A guarantee that all PII/secrets are found |
| Environment- **and** destination-aware rules with fail-closed defaults | Proof of where data really came from (context is *declared*) |
| Redaction, replacement, keyed HMAC pseudonyms, generalization, date shifting, drops | Reversible tokenization (no token vault in this release) |
| Atomic, no-overwrite output with a residual rescan gate | A deployment tool or cloud integration |
| Privacy-safe JSON/text reports with stable reason codes and exit codes | A legal/compliance determination |

## Features (implemented and tested)

- **Formats:** CSV (quoted fields, embedded newlines, BOM, CRLF, configurable delimiter), JSON
  (whole document, JSON Pointer paths), JSONL/NDJSON (streamed), plain text/log (line based,
  multi-line PEM private-key blocks).
- **Detectors (local, deterministic):** field-name heuristics, email, phone (conservative
  confidence), IPv4/IPv6 (stdlib-validated; private addresses as `network.telemetry`), Luhn card
  numbers, dates (DOB only with field/context evidence), credentials/secrets (PEM, bearer/basic,
  AWS/GitHub/Slack/Stripe-style/Google keys, JWTs, URL passwords, connection strings,
  `password=`-style assignments), internal hostnames, policy field classifications, and custom
  regexes with safety checks. See [docs/detector-coverage.md](docs/detector-coverage.md).
- **Policy engine:** strict versioned YAML schema, deterministic precedence, conflict rejection,
  credential hard constraints, environment/destination guardrails, fail-closed fallback.
- **Actions:** `allow`, `redact`, `replace`, `pseudonymize` (HMAC-SHA-256, scoped, versioned),
  `generalize` (year, year-month, age bands, coordinate rounding, numeric bins), `date_shift`
  (keyed, per-dataset or per-entity), `drop_field`, `drop_record`, `block`, `review`.
- **Safe output:** two-pass processing, temp file + fsync + atomic publish, overwrite only with
  `--force`, input/output alias protection, input-change detection, cleanup on failure/Ctrl-C.
- **Reports:** counts by category/detector/action/reason/rule, safe locations, effective context
  and its source, gates, key *status* (never key material), no raw values or fingerprints.

## Install

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"      # or: python -m pip install .
ciphergate --version
```

Runtime dependencies: `typer`, `pydantic`, `PyYAML`.

## Quick start (synthetic examples)

```bash
# 1. Start from a template (refuses to overwrite without --force) and validate it.
ciphergate init --output ciphergate-policy.yml
ciphergate validate-policy ciphergate-policy.yml

# 2. Inspect: never modifies the input, never writes sanitized data.
ciphergate inspect examples/sample.csv --policy policies/developer_logs.yml \
  --environment dev --destination local_dev --report inspection.json

# 3. Plan: preview exactly what sanitize --apply would do.
ciphergate plan examples/sample.jsonl --policy policies/external_ai.yml \
  --environment prd --target-environment external --destination external_ai

# 4. Sanitize: needs --apply; pseudonymization needs a key in the environment (see below).
ciphergate sanitize examples/sample.csv --policy policies/prd_external_ai.yml \
  --environment prd --target-environment external --destination external_ai \
  --output build/sample.sanitized.csv --report build/sample.report.json --apply

# 5. Rescan the output (read-only). Exit 7 if gating residual findings remain.
ciphergate rescan build/sample.sanitized.csv --policy policies/prd_external_ai.yml
```

`policies/prd_external_ai.yml` pins its context (`prd` -> `external` / `external_ai`), so the
context flags in steps 4–5 must match it or be omitted; a conflicting value fails safely.

A log containing a (fake) credential is **blocked** for the external destination — exit 1 and no
output file:

```bash
ciphergate sanitize examples/sample.log --policy policies/prd_external_ai.yml \
  --output build/sample.sanitized.log --apply      # exit 1, nothing written
```

Expected sanitized outputs for `policies/developer_logs.yml` (`dev` -> `local_dev`) are in
[examples/expected/](examples/expected/). More scenarios: [docs/examples.md](docs/examples.md).

### Pseudonymization key

Keyed actions (`pseudonymize`, `date_shift`) read key material **only** from an environment
variable (default `CIPHERGATE_HMAC_KEY`; never a CLI flag, never the policy file). Minimum 32
bytes after decoding; `hex:` and `base64:` prefixes are decoded. There is no fallback key: if it
is missing or weak, `plan` reports `configuration_required` and `sanitize --apply` exits 6
without writing output.

```bash
# bash/zsh — generate locally; avoid pasting real keys into shell history or files you commit
export CIPHERGATE_HMAC_KEY="hex:$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

```powershell
# PowerShell
$env:CIPHERGATE_HMAC_KEY = "hex:" + (python -c "import secrets; print(secrets.token_hex(32))")
```

Keep the same key to get the same pseudonyms across runs; anyone with the key can link equal
values. In CI, inject it from the platform's secret store. See
[docs/security-and-privacy.md](docs/security-and-privacy.md).

## Context: environment vs destination

| Flag | Meaning | Values |
|---|---|---|
| `--environment` (`--source-environment`) | where the data **came from** | `dev`, `stg`, `prd`, `unknown` |
| `--target-environment` | environment that will use the output | `dev`, `stg`, `prd`, `external`, `unknown` |
| `--destination` | who/what **receives** it | `local_dev`, `approved_internal`, `staging_test`, `production_monitoring`, `external_vendor`, `external_ai`, `public_repository`, `unknown` |
| `--profile` / `--use-case` | domain profile / purpose | see [docs/policy-schema.md](docs/policy-schema.md) |

Context can be pinned by a policy or supplied per run. Missing required context fails closed;
nothing defaults to `dev` or to a trusted destination. Built-in guardrails (not overridable by
rules): PRD -> non-production is blocked without a reviewed `transfers` approval; external,
unknown, missing or production targets require a strict policy with the rescan gate and enabled
credential detectors (and JSON key scanning for JSON input); strict policies send `unknown`
context to review. **Context is declared, not verified** — in CI, set it from
controlled pipeline configuration.

## Shipped policy templates (review before use)

`dev_local`, `stg_test`, `prd_external_ai`, `developer_logs`, `test_dataset`, `external_ai`,
`healthcare_template`, `financial_template`, `local_debug`, and `multi_environment` (one policy
whose outcomes vary by environment *and* destination). All validate in CI. Templates named for
healthcare or finance are starting points, **not** HIPAA/PCI controls.

## Commands and exit codes

`init`, `validate-policy`, `inspect`, `plan`, `sanitize` (needs `--apply`), `rescan`, `explain`
(decision for a hypothetical finding — no data needed). All support `--help`.

Common options: `--policy`, `--format csv|json|jsonl|text`, `--report PATH`,
`--report-format json|text` (JSON without `--report` prints only JSON on stdout),
`--max-bytes`, `--encoding` (UTF-8 default; ASCII-compatible encodings only),
`--path-display basename|redacted|full`, `--force`, `--quiet`, `--verbose`, `--no-color`,
`--debug` (frames only, never messages/values). `rescan` adds `--strict/--no-strict`.

| Code | Meaning |
|---|---|
| 0 | Completed; no block/review; required context validated |
| 1 | Blocked, review required, missing/conflicting context |
| 2 | Command-line usage error |
| 3 | Policy syntax/schema/semantic error |
| 4 | Input parse/encoding/size/format error |
| 5 | Output/path error (exists without `--force`, alias, symlink, write failure) |
| 6 | Key or transform configuration missing/invalid, or a value a transform cannot handle |
| 7 | Strict rescan found gating residual findings (output withheld) |
| 8 | Unexpected internal error (safe message) |
| 130 | Interrupted (no output published) |

### Troubleshooting

- `destination_required_but_missing` — pass `--destination` (and `--environment`).
- `environment_context_conflict` — the policy pins that value; use a matching policy.
- `no_applicable_rule_requires_review` — add a rule for that category; inspect lists them.
- `key_missing` / exit 6 — set `CIPHERGATE_HMAC_KEY` (32+ bytes).
- `format_required` — unknown extension; pass `--format`.

## Python API

```python
from ciphergate import load_policy, sanitize_file, ContextInput, Environment, Destination
policy = load_policy("policies/developer_logs.yml")
report = sanitize_file("app.log", "app.clean.log", policy,
                       ContextInput(environment=Environment.DEV, destination=Destination.LOCAL_DEV))
print(report.status, report.exit_code)
```

Supported API: `load_policy`, `validate_policy`, `inspect_file`, `plan_file`, `sanitize_file`,
`rescan_file` and the types exported from `ciphergate`. Other modules are internal.

## Documentation

[Architecture](docs/architecture.md) · [Policy schema](docs/policy-schema.md) ·
[Detector coverage](docs/detector-coverage.md) · [Threat model](docs/threat-model.md) ·
[Security & privacy](docs/security-and-privacy.md) · [Limitations](docs/limitations.md) ·
[Examples](docs/examples.md) · [Claude Code tooling](docs/claude-code-tooling.md) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Development

```bash
python -m pytest -q --cov=ciphergate
ruff check src tests scripts && ruff format --check src tests scripts
mypy
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see also [NOTICE](NOTICE). The license
covers the software only: it is not legal advice and makes no compliance claim.
