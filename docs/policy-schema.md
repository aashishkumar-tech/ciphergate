# Policy schema (`policy_version: 1`)

Policies are YAML, loaded with a strict safe loader (no tags, anchors/aliases or duplicate keys;
max 1 MiB) and validated by pydantic with **unknown keys rejected** everywhere except `metadata`.
Validate with `ciphergate validate-policy FILE` (never reads data).

## Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `policy_version` | `1` | required | other versions rejected |
| `name` | slug `[a-z0-9][a-z0-9_.-]{0,63}` | required | also the default pseudonym namespace |
| `extends` | list of shipped pack names or relative `.yml`/`.yaml` paths (max 4) | `[]` | build on [packs and local layers](#layering-extends) |
| `metadata` | mapping | `{}` | free-form extension namespace; not interpreted |
| `context` | [Context](#context) | all unset | pinned context |
| `requirements` | `{environment, target_environment, destination}` booleans | `true, false, true` | which context must be present (a run without a destination is still treated as untrusted; turning the requirement off warns) |
| `settings` | [Settings](#settings) | | |
| `detectors` | [Detectors](#detectors) | | |
| `custom_categories` | list of `prefix.name` | `[]` | must not duplicate built-ins |
| `classifications` | list | `[]` | declare that fields contain a category |
| `keep` | `{field_names, field_paths}` | empty | fields exempt from [allowlist mode](#allowlist-mode-unrecognized_values) |
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
| `unrecognized_values` | `off` | [allowlist mode](#allowlist-mode-unrecognized_values) for CSV/JSON/JSONL: `redact`, `review` or `block` every value nothing recognised in a field not listed under `keep` |
| `fail_on_parse_error` | `true` | malformed CSV rows / JSONL lines fail the run |
| `malformed_record_action` | unset | required (`drop_record`) when `fail_on_parse_error: false` |
| `report_raw_values` | `false` | `true` is rejected |
| `scan_json_keys` | `false` | scan JSON object keys; only allow/drop/block/review apply to keys. Required (validation error) when the policy pins an untrusted destination; JSON/JSONL runs toward an untrusted or missing destination are blocked (`json_key_scan_required`) without it. All templates set `true` |
| `csv_duplicate_headers` | `reject` | or `disambiguate` (`name#2` internally, header unchanged) |
| `preserve_blank_lines` | `false` | blank CSV/JSONL lines are removed and counted otherwise |
| `rescan.enabled` | `true` | residual gate before publishing |
| `rescan.fail_on_categories` | high-risk set | categories whose unexpected residuals fail the gate. Must not be empty; `credential.secret` is always added; toward an untrusted or missing destination every high-risk category is added regardless |

### Allowlist mode (`unrecognized_values`)

By default CipherGate changes only what a detector, classification or field name recognises;
everything else passes through. For data with unfamiliar structure (for example FHIR), turn
this around: list the fields that may stay, and protect the rest.

```yaml
settings:
  unrecognized_values: redact      # or review / block; default off
keep:
  field_names: [resourceType, status, gender, system]
  field_paths: ["/meta/*"]         # fnmatch on the JSON Pointer / CSV header
```

* A value is **unrecognized** when no finding covers the whole value and its field is not
  kept. It gets category `unknown.sensitive_candidate`, detector `unrecognized_value`, rule
  `settings:unrecognized_values` and reason `unrecognized_value_not_kept`. Rules do not apply to
  it; to let a field through, add it to `keep`.
* A value with only a partial finding (a phone inside a note) is protected **whole**.
* `keep` is not `allow`: detectors and rules still run on kept fields, so an email inside a
  kept field is still redacted. An explicit rule decision (such as an `allow` for `state`)
  still stands.
* Numbers and booleans are protected too (their type changes to a string marker); empty
  strings, nulls, JSON keys, CSV headers and CipherGate's own markers are not.
* Supported for `csv`, `json` and `jsonl`. Any other format fails with
  `unrecognized_values_unsupported_format` (exit 4) rather than running without it.
* Quote `"off"` or leave it out: YAML reads a bare `off` as false, which is accepted as `off`.
  `keep` while the mode is off gives a validation warning.
* Layers: the stricter mode is kept (`block` > `review` > `redact` > `off`). `keep` entries are
  combined; a layer that adds them after an earlier layer turned the mode on gets a warning.

## Detectors

`disabled` (built-in IDs: `field_name`, `secret_pattern`, `luhn_card`, `ip_address`,
`date_pattern`, `email_regex`, `internal_host`, `phone_pattern`, `mac_address`, `iban`, `ssn_pattern`),
`dates_emit_generic` (report
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
    detectors: [email_regex]      # built-in IDs, policy_classification, stack_trace, custom:<id>
    field_names: [email]          # normalized (camelCase/kebab/case-insensitive)
    field_paths: ["/users/*/email"]   # fnmatch on JSON Pointer / CSV header
    field_regex: "^/meta/"        # safety-checked
    environments: [prd]
    target_environments: [external]
    destinations: [external_ai]
    domain_profiles: [developer_logs]
    use_cases: [debugging]
    formats: [csv, json, jsonl, text, logfmt, jsonlog, accesslog, syslog, stacktrace]
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

A rule or default that applies `redact`, `replace`, or any other non-`block`, non-`review` action
to `credential.secret` toward a possibly untrusted destination validates with a warning, because
a detector can match only part of a secret. A destination that is not pinned counts as possibly
untrusted. A `hard: true` block that covers every untrusted destination, with no selectors other
than `categories` and `destinations`, removes the warning.

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

## Hard rules and guardrails

`hard: true` puts a rule at level 2, above guardrails, field rules and everything else except the
engine's own constraints. Use it for "never, whatever other rules say", such as blocking
credentials for untrusted destinations. A hard rule cannot `allow`.

`guardrail: true` puts a rule at level 3. It must name `environments` and either
`target_environments` or `destinations`, so it only fires for a specific environment-to-recipient
move (for example PRD to `external_ai`). A guardrail cannot `allow`, and a rule cannot be both.

A blocked run prints `next:` lines in the terminal summary with what to change, based on the
reason codes. They never include input values.

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

## Layering (`extends`)

A policy can build on shipped **packs** instead of repeating them:

```yaml
policy_version: 1
name: my-hospital
extends: [us_hipaa]          # us_hipaa itself extends healthcare_baseline
context: {environment: prd, target_environment: external, destination: external_ai}
classifications:
  - {id: local-ids, field_names: [visit_number], category: pii.customer_identifier}
```

Shipped packs (`policies/packs/`, all **templates requiring review**):

| Pack | Extends | What it adds |
|---|---|---|
| `healthcare_baseline` | — | Strict default for healthcare-style data anywhere: credentials hard-blocked; clinical values blocked toward external/unknown destinations and sent to review elsewhere; identifiers redacted; DOB and clinical dates cut to the year; internal infrastructure redacted; everything else review. Needs no key. |
| `us_hipaa` | `healthcare_baseline` | Field classifications modelled on the 18 HIPAA Safe Harbor identifier types (geography, dates, ages, record/plan/account numbers, licenses, vehicles, devices, URLs, biometrics, photos); ages banded with 90 and over as `90+`. It is **not** Safe Harbor or Expert Determination by itself: the 3-digit ZIP allowance and the "no actual knowledge" condition are not implemented, binary photos/biometrics are not parsed, and free-text detection is incomplete. |
| `eu_gdpr` | `healthcare_baseline` | GDPR Art. 9 special-category fields (genetic, biometric, ethnic origin, religion, political opinion, trade union, sex life/orientation) blocked toward external/unknown destinations and reviewed elsewhere; national and health-insurance id fields from several member states plus an Italian codice fiscale value pattern; ages banded. It cannot decide a lawful basis or Chapter V transfers, and pseudonymised data is still personal data, so it redacts by default. |
| `india_dpdp` | `healthcare_baseline` | Aadhaar (field name, and value when grouped as `1234 5678 9012`; no Verhoeff check; unseparated 12 digits by field name only), ABHA numbers and `@abdm`/`@sbx` addresses, PAN (value and field), EPIC/passport/licence/ration card/UHID fields, PIN codes as address; SPDI-style sensitive fields blocked toward external/unknown destinations and reviewed elsewhere; ages banded. It cannot decide consent, purpose, retention or cross-border rules. |

`policies/hospital_us_override.yml` is an example third layer (`ciphergate init --template
hospital_us_override`). A policy may extend several jurisdiction packs at once (for example
`extends: [us_hipaa, eu_gdpr, india_dpdp]` for a hospital group); the strictest combination
applies.

**Local layers.** An entry containing `/` or ending in `.yml`/`.yaml` is a local file, for
example an organisation-wide layer shared by several hospitals:

```text
policies/
├── org/base.yml        # extends: [us_hipaa]        -> your organisation's additions
└── hospital-a.yml      # extends: ["org/base.yml"]  -> one site's differences
```

* The path resolves against the directory of the file that names it, and must stay inside the
  **top-level policy's directory** (subdirectories are fine). Absolute paths, drive letters,
  backslashes and `..` segments are rejected by the schema; a path that still resolves outside
  (for example through a symlinked directory) fails with `unsafe_extends_path`.
* Symlinked files are rejected; the target must be a regular file within the usual 1 MiB policy
  limit, loaded with the same safe YAML loader.
* Only a policy loaded from a file can extend local files. Shipped packs, templates and inline
  policies (`load_policy_text`) cannot (`local_extends_unavailable`).
* Layer names (each file's `name:`) must be distinct across the chain (`duplicate_layer_name`).
* Reports show local layers with kind `file` and their path relative to the top-level policy's
  directory; `--path-display redacted` hides it. Changing a local layer changes the digest.

**Resolution.** Pack names are compared to the shipped packs and never used as paths. Layers may
extend layers (at most 4 levels, 8 layers; cycles, including a file extending itself, are
rejected). Layers are ordered base first, your policy last; a layer reached twice is used once.
Every check in this document then runs on the merged policy.

**Merge rules — a later layer can never quietly weaken an earlier one:**

| Part | Merge | Rejected (validation error) |
|---|---|---|
| `context` | later layers may pin unset fields | pinning a different value (`layer_context_conflict`); `allow_cli_override` for a field an earlier layer pinned without allowing overrides (`layer_weakens_context`) |
| `requirements` | any layer requiring a field requires it | setting `false` where an earlier layer has `true` (`layer_weakens_setting`) |
| `settings` | stricter value kept: `strict`, `fail_on_parse_error`, `scan_json_keys`, `rescan.enabled` (true), `unknown_sensitive_behavior` (`block` > `review`), `unrecognized_values` (`block` > `review` > `redact` > `off`), `csv_duplicate_headers` (`reject`), `malformed_record_action` (unset); `rescan.fail_on_categories` lists are combined (an unset value contributes every high-risk category) | a weaker value (`layer_weakens_setting`) |
| `detectors` | custom detectors and internal host suffixes are added; enabling Presidio is allowed | disabling a detector or Presidio that an earlier layer runs, or turning off `reject_risky_regex` (`layer_weakens_detectors` / `layer_weakens_setting`) |
| `custom_categories`, `transfers` | combined | — |
| `classifications`, `rules` | combined | reusing an id from an earlier layer (`duplicate_id`) |
| `keep` | combined (a warning when added after an earlier layer turned allowlist mode on) | — |
| `defaults` | a later default replaces an earlier one for the same selector | a later default that would take over a category from an earlier default with a weaker action (`layer_weakens_default`) |
| `name`, `metadata` | the last layer's | — |

**Rules.** Actions are ranked `block` > `review` > any transform > `allow`. A later rule that
[outranks](#precedence-deterministic) an earlier rule it may overlap with and picks a lower-ranked
action fails with `layer_weakens_rule`. To do it on purpose, name the earlier rule in
`relaxes`:

```yaml
rules:
  - id: hospital-keep-state
    priority: 300
    match: {categories: [location.coarse], field_names: [state]}
    action: allow
    relaxes: ["defaults:location.*"]    # or an earlier rule id
```

Each relaxation is printed as a validation warning and appears in every run report's warnings.
`hard` and `guardrail` rules from an earlier layer can **never** be relaxed. A later `allow` rule
over categories an earlier non-allow default handles needs `relaxes: ["defaults:<selector>"]`.
Swapping one transform for another (for example `pseudonymize` instead of `redact`) needs no
`relaxes`. `relaxes` is rejected in a policy without `extends`, and must name a rule or default
from an earlier layer.

**Provenance.** `validate-policy` prints the layer chain. Reports add `policy.layers` (each
layer's name, kind, source and file digest) and each decision's `layer`; `policy.digest` covers
every layer in order, so editing any pack changes it. With `--path-display redacted` your own
policy file name is hidden; shipped pack names are kept.

## Invalid examples

```yaml
rules:
  - {id: r, match: {categories: ["*"]}, action: allow}          # credential_unsafe_action
  - {id: r, match: {categories: [pii.email]}, action: allow}    # high_risk_allow_unacknowledged
  - {id: r, match: {}, action: redact}                          # empty match
  - {id: r, match: {categories: [pii.email]}, action: tokenize} # no token vault
settings: {report_raw_values: true}                             # rejected
```
