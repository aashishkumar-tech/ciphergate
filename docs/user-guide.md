# CipherGate user guide (step by step)

This guide walks you through CipherGate from install to a safe file you can share. Every command
and output below was run on synthetic data with CipherGate 0.17.0.

## 1. What CipherGate does, in one picture

```text
your file ──> inspect ──> plan ──> sanitize --apply ──> rescan ──> share the safe copy
 (log, CSV,   (what is    (what    (writes a NEW file;  (checks the
  JSON...)     found?)     would    original untouched)  new file again)
                           change?)
```

You tell it three things:

1. **Where the data came from.** `--environment dev|stg|prd|unknown`
2. **Where it is going.** `--destination local_dev | approved_internal | staging_test |
   production_monitoring | external_vendor | external_ai | public_repository | unknown`, plus
   optionally `--target-environment dev|stg|prd|external|unknown`.
3. **The rules.** A policy YAML file (`--policy`).

The same email can be kept for a local debug file and removed for ChatGPT/Claude. That is the
policy's choice, and the reports show which rule decided each value.

> CipherGate never sends anything over the network. It never changes your input file. A
> successful run does **not** prove the output is free of sensitive data, because detectors can
> miss values (for example names in free text). It is not legal or compliance advice.

## 2. Install

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install ciphergate-cli
ciphergate --version          # ciphergate 0.17.0
```

## 3. Pick a starting policy

```bash
ciphergate init --list-templates
ciphergate init --template external_ai --output my-policy.yml
ciphergate validate-policy my-policy.yml
```

| You want to... | Start from |
|---|---|
| send logs to an AI assistant (ChatGPT, Claude, ...) | `external_ai` or `prd_external_ai` |
| debug on your own machine | `dev_local` or `local_debug` |
| general application logs, many destinations | `developer_logs` or `multi_environment` |
| make test datasets | `test_dataset` |
| staging data | `stg_test` |
| healthcare (US) | `hospital_us_override` (built on the `us_hipaa` pack) |
| finance | `financial_template` |

Templates are starting points. **Open the file and read it** before you rely on it. The
`validate-policy` command checks the rules and never reads your data.

## 4. Worked example: share an error log with an AI assistant

Say `app.log` contains:

```text
2026-01-05T10:00:01Z ERROR api-1.prod.internal login failed for alice.test@example.com from 10.0.12.7
2026-01-05T10:00:02Z ERROR payment failed for customer_id=USER_TEST_001 phone +1 202 555 0143
2026-01-05T10:00:03Z INFO  retry scheduled request_id=req-TEST-0001
```

### Step 1: inspect (read-only)

```bash
ciphergate inspect app.log --policy my-policy.yml --environment prd
```

```text
CipherGate inspect: READY (exit 0)
  findings: 4  blocked: 0  review: 0
    by category: network.telemetry=2, pii.email=1, pii.phone=1
    line 1, chars 64-86: pii.email (high, email_regex) -> redact [...; rule redact-everything-identifying]
```

The output shows **where** each value is (line and characters), **what** it is (category),
**what will happen** to it (action) and **which rule** decided that. The values themselves are
never printed. `external_ai` already pins the target and destination, so `--environment` is the
only context you must give.

### Step 2: plan, or sanitize without `--apply`

```bash
ciphergate sanitize app.log --policy my-policy.yml --environment prd --output app.safe.log
#   output:  not written (apply_not_set)
#   (dry run: pass --apply to write the sanitized output)
```

Without `--apply`, nothing is written. `ciphergate plan` does the same preview.

### Step 3: sanitize for real

```bash
ciphergate sanitize app.log --policy my-policy.yml --environment prd \
  --output app.safe.log --report app.report.json --apply
```

`app.safe.log`:

```text
2026-01-05T10:00:01Z ERROR [REDACTED:network.telemetry] login failed for [REDACTED:pii.email] from [REDACTED:network.telemetry]
2026-01-05T10:00:02Z ERROR payment failed for customer_id=USER_TEST_001 phone [REDACTED:pii.phone]
2026-01-05T10:00:03Z INFO  retry scheduled request_id=req-TEST-0001
```

The error text, timestamps and structure stay, so the AI can still help you debug.

**Look at the result.** `customer_id=USER_TEST_001` was **not** removed: in a plain-text log
the detectors did not recognise it. Fix this by:

- adding a custom detector or rule to your policy for your ID format; or
- using a structured format such as `--format logfmt`, which reads `key=value` field names.

This is why you always read the output before you share it.

Safety behaviour you will see:

- Running it again fails with `error[output_exists]` (exit 5). Add `--force` to replace the file.
- The original `app.log` is never modified.
- If the policy **blocks** something (for example a password or token going to `external_ai`),
  exit code is 1 and **no output file is written**.

### Step 4: rescan the output

```bash
ciphergate rescan app.safe.log --policy my-policy.yml --environment prd
#   CipherGate rescan: NO GATING FINDINGS (exit 0)
```

"No gating findings" means the detectors found nothing that must block. It does **not** mean
the output is safe.

### Step 5 (optional): see it visually

```bash
ciphergate review app.log --policy my-policy.yml --environment prd -o app.review.html
```

Open `app.review.html` in a browser. A tree on the left shows the run steps and each record; the
right side shows that record's decisions. Add `--include-input` to also see the original text
next to the output. The page then contains raw data, so keep it private.

## 5. Ask "what would happen if...?" without any data

```bash
ciphergate explain --policy my-policy.yml --category pii.email --field email \
  --environment prd --target-environment external --destination external_ai
```

This prints JSON with the effective context (and where each value came from), the action, the
winning rule (`rule_id`) and its precedence level. Use it to check a policy change.

## 6. Exit codes (for scripts and CI)

| Code | Meaning |
|---|---|
| 0 | done; nothing blocked |
| 1 | blocked, or a human review is needed; no output written |
| 2 | wrong command-line usage |
| 3 | the policy is invalid |
| 4 | input could not be read (format, encoding or size) |
| 5 | output problem, for example the file exists and `--force` was not given |
| 6 | a required key or transform setting is missing |
| 7 | the rescan found gating findings |
| 8 | internal error |

A CI job can run `ciphergate sanitize ... --apply` and fail the pipeline on any non-zero code.

## 7. Keys (only if your policy pseudonymizes or shifts dates)

`pseudonymize` and `date_shift` need a secret key in an environment variable. Never put it in a
command-line flag or in a file you commit.

```bash
# bash
export CIPHERGATE_HMAC_KEY="hex:$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

```powershell
# PowerShell
$env:CIPHERGATE_HMAC_KEY = "hex:" + (python -c "import secrets; print(secrets.token_hex(32))")
```

Use the same key to get the same pseudonyms on every run. Without the key, `sanitize --apply`
stops with exit 6 and writes nothing; there is no fallback.

## 8. File formats

CipherGate picks the format from the file extension (`.csv`, `.json`, `.jsonl`, `.log`,
`.txt`). Set it explicitly with `--format csv|json|jsonl|text|logfmt|jsonlog|accesslog|syslog|stacktrace`.
A directory works too (`-r` for subdirectories).

## 9. Making your own policy (layering)

Don't copy a whole template. Extend one and keep only your differences:

```yaml
policy_version: 1
name: my-team
extends: [us_hipaa]                 # shipped packs: healthcare_baseline, us_hipaa, eu_gdpr, india_dpdp
context: {environment: prd, target_environment: external, destination: external_ai}
classifications:
  - {id: our-ids, field_names: [visit_number], category: pii.customer_identifier}
```

You can also extend your own files: `extends: ["org/base.yml"]`. The path must stay inside the
policy's folder. Local-file layers arrive in the release after 0.17.0; with 0.17.0 itself, use
shipped packs only.

A later layer can only make things stricter. To deliberately weaken a rule, name it in
`relaxes:`; validation shows that as a warning. Hard and guardrail rules can never be relaxed.
See [policy-schema.md](policy-schema.md#layering-extends).

## 10. Common problems

| Message | What to do |
|---|---|
| `environment_required_but_missing` | add `--environment dev/stg/prd` |
| `destination_required_but_missing` | add `--destination ...`, or pin it in the policy |
| `environment_context_conflict` | your flag disagrees with a value pinned in the policy; remove the flag or change the policy |
| `output_exists` | use another `--output` or add `--force` |
| exit 1 with `blocked` | read the `next:` lines; usually a secret or a field your policy forbids for this destination |
| `key_missing` (exit 6) | set `CIPHERGATE_HMAC_KEY` (section 7) |

## 11. Where to read more

- [README](../README.md): the feature list and all commands
- [policy-schema.md](policy-schema.md): every policy field
- [detector-coverage.md](detector-coverage.md): what is detected, and what is missed
- [limitations.md](limitations.md): what CipherGate cannot do
