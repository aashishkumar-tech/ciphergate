# Policy schema (`policy_version: 1`)

Policies are YAML, loaded with a strict safe loader (no tags, anchors/aliases or duplicate keys;
max 1 MiB) and validated by pydantic with **unknown keys rejected** everywhere except `metadata`.
Validate with `ciphergate validate-policy FILE` (never reads data).

## Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `policy_version` | `1` | required | other versions rejected |
| `name` | slug `[a-z0-9][a-z0-9_.-]{0,63}` | required | also the default pseudonym namespace |
| `metadata` | mapping | `{}` | free-form extension namespace; not interpreted |
| `context` | [Context](#context) | all unset | pinned context |
| `requirements` | `{environment, target_environment, destination}` booleans | `true, false, true` | which context must be present (a run without a destination is still treated as untrusted; turning the requirement off warns) |
| `settings` | [Settings](#settings) | | |
| `detectors` | [Detectors](#detectors) | | |
| `custom_categories` | list of `prefix.name` | `[]` | must not duplicate built-ins |
| `classifications` | list | `[]` | declare that fields contain a category |
| `rules` | list of [Rule](#rules) | `[]` | |
| `defaults` | map category-selector -> `{action, params, reason}` | `{}` | level 8 |
| `transfers` | list of [Transfer](#transfers) | `[]` | reviewed PRD -> non-prod approvals |

## Context

`environment` (`dev|stg|prd|unknown`), `target_environment` (`dev|stg|prd|external|unknown`),
`destination` (`local_dev|approved_internal|staging_test|production_monitoring|external_vendor|
external_ai|public_repository|unknown`), `domain_profile` (`developer_logs|test_dataset|healthcare|
financial|general`), `use_case` (`debugging|analytics|training|external_llm|support_bundle|
test_fixture|monitoring|incident_response`), `allow_cli_override` (list of those field names).

A pinned value combined with a different caller value fails with
`environment_context_conflict` unless the field is in `allow_cli_override` (recorded as
`cli_override` in the report; validation warns). Untrusted destinations are `external_vendor`,
`external_ai`, `public_repository`, `unknown`.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `strict` | `true` | unknown context -> review; required for external/unknown/prd targets |
| `unknown_sensitive_behavior` | `review` | fallback for findings no rule/default covers: `review` or `block` (never allow) |
| `fail_on_parse_error` | `true` | malformed CSV rows / JSONL lines fail the run |
| `malformed_record_action` | unset | required (`drop_record`) when `fail_on_parse_error: false` |
| `report_raw_values` | `false` | `true` is rejected |
| `scan_json_keys` | `false` | scan JSON object keys; only allow/drop/block/review apply to keys. Required (validation error) when the policy pins an untrusted destination; JSON/JSONL runs toward an untrusted or missing destination are blocked (`json_key_scan_required`) without it. All templates set `true` |
| `csv_duplicate_headers` | `reject` | or `disambiguate` (`name#2` internally, header unchanged) |
| `preserve_blank_lines` | `false` | blank CSV/JSONL lines are removed and counted otherwise |
| `rescan.enabled` | `true` | residual gate before publishing |
| `rescan.fail_on_categories` | high-risk set | categories whose unexpected residuals fail the gate. Must not be empty; `credential.secret` is always added; toward an untrusted or missing destination every high-risk category is added regardless |

## Detectors

`disabled` (built-in IDs: `field_name`, `secret_pattern`, `luhn_card`, `ip_address`,
`date_pattern`, `email_regex`, `internal_host`, `phone_pattern`), `dates_emit_generic` (report
non-DOB dates as `date.generic`), `internal_host_suffixes` (default `.internal .local .corp .lan
.intranet .localdomain`), `custom` (list of `{id, category, pattern, confidence, ignore_case}`;
patterns are checked for compile errors, empty matches, nested quantifiers, backreferences and
multiple unbounded wildcards — heuristics, not proof), `reject_risky_regex` (default `true`).

`presidio` (optional NER, needs the `ner` extra): `enabled` (default `false`), `language`
(two-letter code, default `en`), `model` (installed spaCy package name, default `en_core_web_lg`),
`min_score` (0..1, default `0.6`), `entities` (map of Presidio entity names such as `PERSON` to
CipherGate categories; default `{PERSON: pii.person_name, LOCATION: location.coarse}`; categories
must exist). When enabled, validation adds a warning and rules may reference detector
`presidio_ner`; a run without the extra or model fails with exit 6.

`secret_pattern` and `field_name` cannot be disabled in strict policies, policies pinned to an
untrusted destination, or policies with transfer approvals (`credential_detection_required`). Runs
toward an untrusted or missing destination with either disabled are blocked.

Custom categories in the `credential`, `pii`, `health`, `financial`, `employment` or `unknown`
families (e.g. `pii.member_number`) are high-risk: `allow` toward an untrusted destination needs
`acknowledge_risk`, and they gate the rescan by default.

Classifications: `{id, field_names | field_paths, category, confidence}` — e.g. mark
`admission_date` as `health.clinical_date` so rules can act on it.

## Rules

```yaml
- id: pseudonymize-email          # unique slug
  priority: 300                   # 0..10000, higher wins within a level
  hard: false                     # level 2; cannot be allow
  guardrail: false                # level 3; needs environments + target/destinations; not allow
  match:                          # at least one selector; empty lists rejected
    categories: [pii.email]       # exact, "prefix.*" or "*"
    detectors: [email_regex]      # built-in IDs, policy_classification, custom:<id>
    field_names: [email]          # normalized (camelCase/kebab/case-insensitive)
    field_paths: ["/users/*/email"]   # fnmatch on JSON Pointer / CSV header
    field_regex: "^/meta/"        # safety-checked
    environments: [prd]
    target_environments: [external]
    destinations: [external_ai]
    domain_profiles: [developer_logs]
    use_cases: [debugging]
    formats: [csv, json, jsonl, text]
    min_confidence: 0.8
    max_confidence: 1.0
  action: pseudonymize
  params: {scope: category, prefix: "email_"}
  reason: keep_join_key           # slug shown in reports
  acknowledge_risk: false         # required for allow of high-risk categories to untrusted dests
```

A context selector never matches missing context.

### Actions and parameters

| Action | Params | Notes |
|---|---|---|
| `allow` | — | credentials never; high-risk to untrusted needs `acknowledge_risk` |
| `redact` | `marker` (default `[REDACTED:{category}]`; shape `[WORD]` / `[WORD:{category}]`) | |
| `replace` | `value` (required; str/int/float/bool/null) | strings checked: emails need reserved domains, no card/secret/real-looking phone/public IP |
| `pseudonymize` | `scope` (required: `field`/`category`/`entity`), `entity`, `prefix`, `key_env` (default `CIPHERGATE_HMAC_KEY`), `normalize` (`nfc`/`casefold_nfc`/`none`), `namespace` | output is a string |
| `generalize` | `strategy` (`year`, `year_month`, `age_band`, `round_coordinates`, `numeric_bin`), `band_size`, `max_age`, `decimals`, `bins` | unfit values fail the run |
| `date_shift` | `max_days` (required 1..3650), `scope` (`dataset`/`entity`), `entity_field`, `formats` (`iso` or strptime), `key_env`, `namespace` | |
| `drop_field` | — | CSV: whole column; JSON: nearest object property; text: unsupported -> review |
| `drop_record` | — | CSV row / JSONL line / text line / top-level JSON array item |
| `block` | — | run blocked, nothing written |
| `review` | — | run needs human decision, nothing written |
| `tokenize` | — | **rejected**: no token vault in this release |

## Precedence (deterministic)

1. Engine hard constraints: missing/invalid context gates; credential never allowed (forced
   `block`); high-risk allow to an untrusted/missing destination or an external/unknown target
   environment without acknowledgement -> `review`; unsupported transform for the location ->
   `review` (a credential there -> `block`).
2. `hard: true` rules.
3. `guardrail: true` rules.
4. Field rules (`field_names`/`field_paths`/`field_regex`).
5. Context rules (environment/target/destination/profile/use case, no field selector).
6. Category rules (`categories`/`detectors`/`formats` only).
7. Confidence-only rules.
8. `defaults` (exact category, then `prefix.*`, then `*`).
9. Fallback `settings.unknown_sensitive_behavior`.

Levels are computed from selectors, not declared. Within a level the highest `priority` wins.
Two rules at the same level and priority that may match the same finding and choose different
actions/params are **rejected** (`policy_conflict`, naming both rule IDs).

Several findings on one value combine: `drop_record` > `drop_field` > whole-value transform
(most protective by rank) > span transforms (overlaps merged, most protective wins).

## Transfers

```yaml
transfers:
  - id: masked-prd-to-stg
    from_environments: [prd]
    to_target_environments: [stg]
    to_destinations: [staging_test]
    approval: {reviewed_by: "<reviewer>", reference: "<ticket>", approved_on: 2026-01-01}
```

Lifts the built-in PRD -> non-production block for exactly the listed context. Every context
dimension the run supplies must be listed: an approval naming only `to_target_environments: [stg]`
does not cover a run that also gives `--destination local_dev`. `approved_on` cannot be in the
future. Requires `strict: true` and the rescan gate; validation always warns, and approvals do not
expire automatically — review them. No shipped policy contains an
approval. Rules still apply — an approval does not allow raw data through.

## Invalid examples

```yaml
rules:
  - {id: r, match: {categories: ["*"]}, action: allow}          # credential_unsafe_action
  - {id: r, match: {categories: [pii.email]}, action: allow}    # high_risk_allow_unacknowledged
  - {id: r, match: {}, action: redact}                          # empty match
  - {id: r, match: {categories: [pii.email]}, action: tokenize} # no token vault
settings: {report_raw_values: true}                             # rejected
```
