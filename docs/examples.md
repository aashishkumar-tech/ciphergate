# Examples

All inputs in `examples/` are synthetic (reserved domains, `USER_TEST_*` IDs, `TEST_ONLY_*`
credentials, private/documentation IP ranges).

## Same data, different context (`policies/multi_environment.yml`)

```bash
P=policies/multi_environment.yml
ciphergate explain --policy $P --category pii.email --field /email \
  --environment dev --target-environment dev --destination approved_internal   # replace
ciphergate explain --policy $P --category pii.email --field /email \
  --environment prd --target-environment prd --destination approved_internal   # redact
ciphergate explain --policy $P --category network.telemetry --field /host \
  --environment dev --target-environment dev --destination local_dev           # allow
ciphergate explain --policy $P --category network.telemetry --field /host \
  --environment dev --target-environment external --destination external_ai    # redact
```

| Source | Target / destination | Outcome with `multi_environment.yml` (tested) |
|---|---|---|
| dev | dev / local_dev | emails -> `user@example.invalid`; hosts/IPs/trace IDs kept; credentials redacted |
| stg | stg / staging_test | same as dev; credentials redacted |
| prd | external / external_ai | guardrail redacts identifiers and infrastructure; credentials block the run |
| prd | stg / staging_test | **blocked** (no reviewed `transfers` approval) |
| prd | prd / production_monitoring | only `trace_id`/`request_id`/`correlation_id` kept; emails and hosts redacted; credentials block |
| unknown | any | review required (strict) — nothing written |

Tests: `tests/integration/test_environment_matrix.py`.

## Developer logs for local debugging

```bash
ciphergate sanitize examples/sample.log --policy policies/developer_logs.yml \
  --environment dev --destination local_dev --output build/sample.clean.log --apply
```

Output (also `examples/expected/sample.dev_local_dev.log`):

```text
2026-01-05T10:00:01Z ERROR api-1.prod.internal login failed for [REDACTED:pii.email] from 10.0.12.7
2026-01-05T10:00:02Z DEBUG config loaded: db_password=[REDACTED:credential.secret]
2026-01-05T10:00:03Z DEBUG outbound call with Authorization: Bearer [REDACTED:credential.secret]
```

The same file with `--destination external_ai` is blocked (credentials).

## PRD CSV for an external AI assistant (needs `CIPHERGATE_HMAC_KEY`)

```bash
ciphergate sanitize examples/sample.csv --policy policies/prd_external_ai.yml \
  --output build/sample.sanitized.csv --apply
```

Emails become `email_pz1_...` (the same email inside `message` gets the same token), user IDs
`id_pz1_...`, trace IDs `trace_pz1_...`, names/phones/IPs/internal hosts are redacted, and birth
dates keep only the year. The pseudonyms depend on your key, so no expected file is shipped.

## Healthcare-style records

`policies/healthcare_template.yml` pseudonymizes patient IDs per patient, date-shifts clinical
dates per patient (intervals preserved), and sends clinical values (`diagnosis`, `medication`, …)
to review — or blocks them for external destinations from prd/stg/unknown. It is not a HIPAA
method.
