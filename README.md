# CipherGate

**Inspect and sanitize logs and test datasets before they leave their environment** — with
policies that depend on where the data came from (DEV/STG/PRD) *and* where it is going (local
debugging, internal monitoring, an external vendor or AI assistant, a public repository).

Teams often hand-redact logs or keep ad-hoc scripts before pasting data into an AI assistant or a
vendor ticket. CipherGate replaces that with a local, explainable, scriptable gate:

```
inspect  ->  plan  ->  sanitize --apply  ->  rescan
```

> **Status: 0.5.0 (alpha).** No detector finds every sensitive value. A passing run means the
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
  multi-line PEM private-key blocks), logfmt (`--format logfmt`: `key=value` log lines), JSON
  in log lines (`--format jsonlog`), nginx/Apache access logs (`--format accesslog`),
  syslog/CEF (`--format syslog`) and logs with Python/JVM/Node stack traces
  (`--format stacktrace`), see below.
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

Alternatively, put the key in a file and set `CIPHERGATE_HMAC_KEY_FILE` to its path (the
Docker/Kubernetes secrets convention; it works for any `key_env` name plus `_FILE`):

```bash
umask 077 && python -c 'import secrets; print("hex:" + secrets.token_hex(32))' > ~/.ciphergate.key
export CIPHERGATE_HMAC_KEY_FILE=~/.ciphergate.key
```

The file must be a regular file of at most 4 KiB. On Linux/macOS it must be owned by you and not
accessible to group or others (`chmod 600` or `400`), otherwise the run fails with
`key_file_invalid`; symlinks are followed and the target is checked. On Windows CipherGate
cannot check the ACL and prints a warning: restrict the file to your account yourself. Setting
both `CIPHERGATE_HMAC_KEY` and `CIPHERGATE_HMAC_KEY_FILE` is refused.

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

Common options: `--policy`, `--format csv|json|jsonl|text|logfmt|jsonlog|accesslog|syslog|stacktrace`, `--report PATH`,
`--report-format json|text` (JSON without `--report` prints only JSON on stdout),
`--max-bytes`, `--encoding` (UTF-8 default; ASCII-compatible encodings only),
`--path-display basename|redacted|full`, `--force`, `--quiet`, `--verbose`, `--no-color`,
`--debug` (frames only, never messages/values). `rescan` adds `--strict/--no-strict`.

### Optional local NER (Presidio)

Person names and places in free text are not found by the built-in pattern detectors. An
optional detector based on [Microsoft Presidio](https://microsoft.github.io/presidio/) can add
them. It is **off by default** and not part of the base install:

```bash
python -m pip install "ciphergate[ner]"
python -m spacy download en_core_web_lg   # one-time, explicit; CipherGate never downloads models
```

```yaml
detectors:
  presidio:
    enabled: true
    model: en_core_web_lg        # an installed spaCy model package
    language: en
    min_score: 0.6               # Presidio score threshold
    entities:                    # Presidio entity -> CipherGate category (default shown)
      PERSON: pii.person_name
      LOCATION: location.coarse
```

- If the extra or the model is missing, the run fails with exit 6 (`ner_not_installed` /
  `ner_model_missing`) and publishes nothing. It never falls back to running without NER. The
  model is checked before Presidio is imported, because Presidio's spaCy engine would otherwise
  download a missing model.
- Findings use detector ID `presidio_ner` and go through the policy like any other finding, so
  rules decide what happens (`match: {detectors: [presidio_ner]}` works). NER never allows a
  value, so block and review rules still win.
- NER misses names and flags non-names. It is slow (every string value goes through spaCy) and
  memory-hungry, and its scores are Presidio's, not calibrated probabilities. Treat it as extra
  recall, not proof.

### Directories (batch runs)

`inspect`, `plan`, `rescan` and `sanitize` accept a directory as INPUT:

```bash
ciphergate inspect logs/ --policy policies/developer_logs.yml --environment dev \
  --destination local_dev --recursive --report build/batch.json
ciphergate sanitize logs/ --policy ... --output build/logs.sanitized --apply
```

- Files are chosen by extension (`.csv`, `.json`, `.jsonl`, `.ndjson`, `.txt`, `.log`), or all
  regular files when `--format` is given. Subdirectories are processed only with
  `--recursive`/`-r` (at most 32 levels). Symlinks, junctions, devices, FIFOs and other
  extensions are **skipped and listed** in the report with a reason; links are never followed.
  At most 1000 files by default (`--max-files N`); more fails the run (exit 4) before anything
  is processed. An empty selection fails with `batch_empty` (exit 4).
- Each file is processed exactly like a single-file run, in sorted path order; a failing file
  does not stop the others, so the report covers every file.
- `sanitize` needs a **new** output directory (an existing one is refused; `--force` is not
  supported for directories) outside the input directory. The whole tree is built in a private
  staging directory next to it and published with one rename **only if every file was
  sanitized**; otherwise nothing is published and the staging directory is removed.
- The exit code is the first failing file's code in sorted order (0 if all succeeded). The JSON
  report (`ciphergate.batch-report/v1`) has a summary, every file's full report and the skipped
  entries. Paths are relative to INPUT; `--path-display redacted` replaces them with
  `<redacted:NNNN>.ext`. `--report` must not point inside the input or output directory.
- Directory runs cannot use stdin/stdout. The same behaviour is available from Python as
  `inspect_directory` / `plan_directory` / `rescan_directory` / `sanitize_directory`.

### Structured logs (logfmt)

`--format logfmt` reads `key=value` log lines such as
`ts=2026-01-05T10:00:00Z level=info msg="login ok" user_email=alice.test@example.com`. It is
never selected from the file extension (`.log` stays `text`).

- Every line is still scanned exactly like `text`, so logfmt never finds less than text mode
  (property-tested). The parse only adds field context: a finding inside a value is attributed to
  that field (`field_path` `/user_email`), and field-name heuristics run on the keys, so
  `customer_name="…"` or `user_id=…` are found even when the value itself looks harmless.
  Policy `field_names` / `field_paths` rules therefore apply to log fields.
- Output keeps each line as it was; only the protected spans change, so quoting and free text are
  preserved. `drop_field` is not supported for logfmt (it becomes `review`; a credential there
  blocks).
- Keys must start with a letter or `_`; values are bare or double-quoted with backslash escapes.
  A line with broken quoting gets no field context (it is still scanned as text), and lines inside
  a PEM private key block are never parsed as fields. JSON embedded in log lines is not parsed
  by logfmt; use `jsonlog` for that.

### Structured logs (JSON in log lines)

`--format jsonlog` reads log lines that embed JSON objects, such as
`2026-01-05T10:00:00Z ERROR login failed {"user": {"email": "alice.test@example.com"}}`. Like
logfmt, it is never selected from the file extension.

- Every line is still scanned exactly like `text` (property-tested: jsonlog never protects fewer
  characters than text mode). Each embedded object adds field context: findings inside a value
  are attributed to it (`field_path` is the JSON Pointer inside the object, e.g. `/user/email`),
  and field-name heuristics and policy classifications run on every key and cover the whole
  value. String values and keys containing JSON escapes (`\u0040`) are also decoded and scanned.
- Output keeps the line as it was; only protected spans change. Replacements are JSON-escaped, a
  replaced number/boolean/null becomes a JSON string, and every embedded object is re-parsed
  after rewriting; if one would no longer be valid JSON, the run fails and nothing is published.
  A match that covers only JSON punctuation (for example a credential assignment right before an
  object) protects every value of that object.
- Only objects (`{...}`) are recognised, at most 16 start positions per line, nested at most
  64 levels (the JSON depth limit). Text that is not valid JSON, and lines inside a PEM private
  key block, get no field context (they are still scanned as text). `drop_field` is not
  supported (it becomes `review`; a credential there blocks).

### Access logs (nginx/Apache common and combined)

`--format accesslog` reads NCSA common/combined lines, the default layout of nginx and Apache
httpd:
`192.0.2.10 - alice [05/Jan/2026:10:00:00 +0000] "GET /p?email=a%40example.com HTTP/1.1" 200 12 "-" "curl/8"`.
It is never selected from the file extension.

- Every line is still scanned exactly like `text` (property-tested). Fields get nginx variable
  names as paths: `/remote_addr`, `/ident`, `/remote_user`, `/time_local`, `/request` (or
  `/request/method`, `/request/path`, `/request/protocol`), `/status`, `/body_bytes_sent`,
  `/http_referer` and `/http_user_agent`. Query strings of the request and the referer become
  fields as well (`/request/query/email`), so field-name heuristics and `field_names` rules
  apply to parameters such as `email` or `access_token`.
- Log escapes (`\x22`, `\"`) and percent-encoding (`%40`) are decoded and the decoded value is
  scanned too, so `alice.test%40example.com` is found although the raw-text scan misses it.
- Output keeps the line as it was; only protected spans change. Replacements are
  percent-encoded in paths and query strings and `\xHH`-escaped elsewhere, and each rewritten
  line must still parse with all its fields, or the run fails and nothing is published.
- A `-` field gets no field context. Only lines that start with the common/combined layout are
  recognised: fields after the user agent (such as `$http_x_forwarded_for`), virtual-host
  prefixes and custom layouts get text-mode scanning only. `drop_field` is not supported (it
  becomes `review`).

### syslog and CEF

`--format syslog` reads RFC 5424 and RFC 3164 (BSD) syslog lines, including files written by
rsyslog (no `<PRI>`, traditional or RFC 3339 timestamps), and CEF records, either bare or as the
message of a syslog line:

```text
<34>1 2026-01-05T10:00:00Z web01 billing 4242 ID47 [auth@32473 email="alice.test@example.com"] login failed
Jan  5 10:00:00 web01 sshd[4242]: Accepted publickey for USER_TEST_001
<134>Jan 05 10:00:00 fw01 CEF:0|Vendor|Product|1.0|100|Login ok|5|suser=alice.test src=192.0.2.10
```

It is never selected from the file extension.

- Every line is still scanned exactly like `text` (property-tested). Header fields become
  `/timestamp`, `/hostname`, `/app_name`, `/procid`, `/msgid`; RFC 5424 structured data becomes
  `/sd/<sd-id>/<name>`; the message is `/msg`.
- CEF header fields are `/cef/device_vendor`, `/cef/device_product`, `/cef/device_version`,
  `/cef/signature_id`, `/cef/event_name` (CEF "Name") and `/cef/severity`; extensions are
  `/cef/extension/<key>`. Common short keys also get a canonical name for the field-name
  heuristics (`suser` is read as `source_user_name`, `src` as `source_ip`, `dhost` as
  `destination_hostname`, ...), and `cs1`-style custom fields use their `cs1Label`. Findings keep
  the raw key, so `field_names: [suser]` rules apply.
- Escapes are decoded for scanning and re-applied to replacements: `\"`, `\\`, `\]` in
  structured data; `\|`, `\\` in CEF headers; `\=`, `\\`, `\n` in CEF extensions.
  Header fields get `_` for whitespace (an RFC 3164 tag for anything outside
  `[A-Za-z0-9_./-]`). Each rewritten line must still parse with all its fields, or the run fails.
- `-` (NILVALUE) fields get no field context. RFC 3164 lines need a `tag:` (or a CEF message) to
  be recognised; other layouts, LEEF and multi-line messages get text-mode scanning only.
  `drop_field` is not supported (it becomes `review`).

### Stack traces (Python, JVM, Node.js)

`--format stacktrace` reads a log like `text` and also recognises stack trace lines, so a policy
can decide what leaves with them. It is never selected from the file extension.

- Every line is still scanned exactly like `text` (property-tested); a credential or email in a
  frame or source line is found and handled whatever the policy does with the frame.
- Frame lines (Python `File "...", line N, in f`; JVM `at a.B.c(B.java:12)`; Node
  `at fn (x.js:1:2)` and `at x.js:1:2`) and the indented Python source/caret lines under a frame
  get a `proprietary.source` finding from the `stack_trace` detector, at `/stack/frames/N` and
  `/stack/frames/N/source`. Rules can select them by category or by `detectors: [stack_trace]`.
  A policy without such a rule falls back to `unknown_sensitive_behavior` (review or block).
- Other findings on trace lines get the trace path too: the Python exception line is
  `/stack/exception`, JVM `Caused by:`/`Suppressed:` lines are `/stack/caused_by` and
  `/stack/suppressed`.
- Redacting frames keeps the exception type and message for debugging:

```yaml
  - id: strip-stack-frames
    priority: 200
    match: {categories: [proprietary.source], destinations: [external_ai]}
    action: redact
```

- There is no lookahead and nothing is buffered: each line is classified from the lines before
  it, keeps the `max_record_bytes` limit, and a trace of any length is streamed. So a JVM or Node
  header line (`Exception in thread ...`, `TypeError: ...`) is not marked as part of the trace,
  and frames are recognised on their own (a truncated or interleaved trace still has every frame
  flagged). An unrelated log line ends a trace; frame numbering restarts after it.
- Matching is structural, not semantic: any indented `at name (...)` line counts as a frame, and
  Python source lines are only recognised after a traceback header or frame. Python exception
  groups (`| ` prefixes), .NET, Go, Ruby and other runtimes get text-mode scanning only.
  `drop_field` is not supported (it becomes `review`).

### Pipes (stdin/stdout)

Use `-` as INPUT to read stdin (then `--format` is required), and `sanitize --output -` to write
the sanitized data to stdout:

```bash
kubectl logs my-pod | ciphergate sanitize - --format text --policy policies/prd_external_ai.yml \
  --environment prd --target-environment external --destination external_ai \
  --output - --apply --report build/report.json > build/safe.log
```

- stdout receives data **only after every check passed**. A blocked, review, rescan-failed or
  errored run writes nothing to stdout and exits nonzero, so always check the exit status (in
  shells, `set -o pipefail`).
- With `--output -` the human summary goes to stderr. Use `--report PATH` for the JSON report;
  `--report -` and `--report-format json` without `--report` are refused because stdout carries
  the data.
- stdin is copied into a private temporary workspace (owner-only on POSIX), capped by
  `--max-bytes`, and deleted when the run ends. Reports name the input `<stdin>` and the output
  `<stdout>`.
- If the reader closes the pipe early, the run exits 5 (`stdout_broken_pipe`): what it received
  is incomplete.
- A file actually named `-` must be passed as `./-`.

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
- `key_missing` / exit 6 — set `CIPHERGATE_HMAC_KEY` (32+ bytes) or `CIPHERGATE_HMAC_KEY_FILE`.
- `key_file_invalid` / exit 6 — the key file is unreadable, too large, not a regular file,
  accessible to group/others (POSIX), or both the variable and `_FILE` are set.
- `format_required` — unknown extension; pass `--format`.

## Python API

```python
from ciphergate import load_policy, sanitize_file, ContextInput, Environment, Destination
policy = load_policy("policies/developer_logs.yml")
report = sanitize_file("app.log", "app.clean.log", policy,
                       ContextInput(environment=Environment.DEV, destination=Destination.LOCAL_DEV))
print(report.status, report.exit_code)
```

Streams and directories use the same pipeline and the same safety rules as the CLI:

```python
import io
from ciphergate import InputFormat, SanitizeOptions, sanitize_stream, sanitize_directory

out = io.BytesIO()
report = sanitize_stream(open("app.log", "rb"), out, policy, ctx,
                         SanitizeOptions(format=InputFormat.TEXT))
# out is written only if report.ok; a blocked/review/failed run leaves it untouched.

batch = sanitize_directory("logs/", "logs.clean/", policy, ctx, recursive=True)
print(batch.status, batch.exit_code, batch.to_dict()["summary"])
```

- `*_stream` functions take binary streams (`"rb"`, `io.BytesIO`) and need an explicit format
  (`fmt=` or `SanitizeOptions.format`). The input is spooled to a private temporary workspace,
  capped at `max_input_bytes`, and removed afterwards. `sanitize_stream` copies to `output`
  only after every check has passed. If that copy fails part-way, it raises `OutputWriteError`
  (`stream_write_failed`), and `output` may hold an incomplete prefix of sanitized data.
- `*_directory` functions return a `BatchReport` (`status`, `exit_code`, `files`, `skipped`,
  `to_dict()` in the `ciphergate.batch-report/v1` schema). `sanitize_directory` needs a new
  output directory outside the input, publishes it only if every file was sanitized, and refuses
  `SanitizeOptions(force=True)`.
- As with `sanitize_file`, `SanitizeOptions()` defaults to `apply=True`; pass `apply=False` for
  a plan. Keys come from the environment unless `SanitizeOptions(keys=...)` is given.

Supported API: `load_policy`, `validate_policy`, `inspect_file`, `plan_file`, `sanitize_file`,
`rescan_file`, the `*_stream` and `*_directory` functions above, and the types exported from
`ciphergate` (including `BatchReport`). Other modules are internal.

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
