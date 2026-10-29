# Detector coverage

All detectors are built-in, local and deterministic (no optional dependencies). Confidence values
are engineering estimates mapped to bands (`low` < 0.5 <= `medium` < 0.8 <= `high`); they are
**not** calibrated probabilities. Coverage is not complete. Tests: `tests/unit/test_detectors.py`,
`tests/unit/test_properties.py`, `tests/security/`.

| Detector ID | Targets -> category | Positive (synthetic) | Negative | Confidence | Known gaps / false positives |
|---|---|---|---|---|---|
| `field_name` | field names -> many categories | `email`, `contactEmail`, `api_key`, `date-of-birth`, `userId`, `trace_id` | `token_count`, `key_name`, `monkey`, `product_name`, `email_verified` | 0.45–0.85 per term | heuristic dictionary; benign values in sensitive-looking fields are flagged; sensitive data in generic fields (`notes`, `value`) is missed unless content detectors match |
| `policy_classification` | policy-declared fields | `admission_date` (healthcare template) | | configured | only as good as the policy |
| `email_regex` | `pii.email` | `alice.test@example.com` | `a..b@example.com`, `user@localhost` | 0.9 | ASCII only; no IDN; obfuscated forms (`alice at example dot com`) missed |
| `phone_pattern` | `pii.phone` | `+1 202 555 0143` (high), `(202) 555-0143` (medium) | dates, IPs, card numbers, repeated digits, < 7 digits | 0.3 bare digits, 0.55–0.8 prefixed/formatted, +0.2 keyword | no numbering-plan validation; IDs can look like phones (low band) |
| `ip_address` | `pii.ip_address` (global), `network.telemetry` (private/loopback/link-local) | `8.8.8.8`, `10.0.0.1`, `2606:4700::1111`, `fe80::1%eth0` | `256.1.1.1`, `std::vector`, `12:30:45` | 0.85 / 0.8 | version strings like `1.2.3.4` match; documentation ranges flagged with evidence |
| `luhn_card` | `pii.payment_card` | `4111 1111 1111 1111` | Luhn-invalid, mixed separators, repeated digits | 0.4 Luhn-only, 0.8 issuer prefix, +0.15 keyword | random IDs pass Luhn ~10% (low band); cards split across fields missed |
| `date_pattern` | `pii.date_of_birth` with field/keyword evidence; `date.generic` if enabled | `dob: 1990-04-12`, field `birth_date` | `created 2026-01-05` (no DOB evidence), invalid dates | 0.85 / 0.6 | `DD/MM` vs `MM/DD` ambiguity flagged; free-text DOBs without keywords missed |
| `secret_pattern` | `credential.secret` | PEM blocks, `Bearer ...`, `AKIA...`, `ghp_...`, `xox?-`, `sk_test_...`, `AIza...`, JWTs, `scheme://u:pw@`, `Password=...;`, `password=`, `api_key:`, `token=` | `password=`, `password: null`, markers, `******` | 0.8–0.99 | base64/hex-wrapped, split, custom-format or high-entropy secrets without keywords are **missed**; prose like `password: required` is flagged |
| `internal_host` | `network.telemetry` | `api-1.prod.internal`, `db.corp`, `localhost` | `example.com`, `a.internalx` | 0.75 | internal names without listed suffixes missed; configurable |
| `custom:<id>` | configured | | | configured | regex-safety checks are heuristics |
| `presidio_ner` (optional, off by default) | Presidio entities -> mapped categories (default `PERSON` -> `pii.person_name`, `LOCATION` -> `location.coarse`) | `ticket opened by <a person's name>` | numbers, single characters, CipherGate markers/pseudonyms | Presidio score, filtered by `min_score` | statistical model: misses and false positives, language/model dependent, slow; requires `ciphergate[ner]` plus a locally installed spaCy model |

## Optional NER (`presidio_ner`)

Needs `pip install 'ciphergate[ner]'` and a spaCy model installed by the user (for example
`python -m spacy download en_core_web_lg`). CipherGate checks that the model package is importable
before importing Presidio and fails with `ner_model_missing` instead of letting Presidio download
it. Strings with no letters or under two characters are not sent to the model. Tests
(`tests/unit/test_presidio_ner.py`) use a fake engine. Presidio itself is **not** exercised in
CI, so accuracy on real text has not been measured by this project.

## Text/log specifics

Multi-line PEM private-key blocks are tracked across lines; every line up to the END marker (or
end of file) is flagged. Other multi-line constructs (stack traces, JSON fragments split over
lines) are scanned line by line only.

With `--format logfmt` the same line scan runs unchanged, and `field_name` plus policy
classifications additionally run on each `key=value` key (covering the whole value). Content
findings inside a value are attributed to that field. Tests: `tests/unit/test_logfmt.py`,
including a property test that logfmt findings are a superset of text-mode findings.

With `--format jsonlog` the line scan also runs unchanged; for each JSON object embedded in the
line, `field_name` plus policy classifications run on every key (covering the whole value), and
content findings inside a value are attributed to its JSON Pointer. Values and keys that contain
JSON escapes are also decoded and scanned with every detector, since the raw-text scan cannot see
through `\uXXXX` escapes. Keys that are CipherGate markers or pseudonyms give no field context
(their values are still content-scanned). Tests: `tests/unit/test_jsonlog.py`, including a
property test that jsonlog protects at least the characters text mode protects.

With `--format accesslog` the line scan also runs unchanged; `field_name` plus policy
classifications run on each access-log field (`remote_addr` maps to `pii.ip_address`,
`remote_user` to `pii.customer_identifier`) and on each query-string parameter of the request
and referer. Values with log escapes or percent-encoding are decoded and scanned with every
detector. Tests: `tests/unit/test_accesslog.py`, including the same superset property.

With `--format syslog` the line scan also runs unchanged; `field_name` plus policy
classifications run on syslog header fields (`hostname` maps to `network.telemetry`), RFC 5424
structured-data parameter names, and CEF extension keys. Short CEF keys are also checked under a
canonical name (`suser` as `source_user_name`, `src` as `source_ip`, `smac` as
`source_mac_address`, ...) and `csN` fields under their `csNLabel`. Escaped values are decoded
and scanned with every detector. Tests: `tests/unit/test_syslog.py`, including the same
superset property.

## Not detected (deferred)

Person names in free text (only with the optional NER detector), postal addresses in free text, government IDs by value
pattern, bank account numbers by value pattern, device IDs/MACs by value, proprietary source
code or business logic, non-English context keywords, encoded/escaped variants beyond simple
quoting. Field-name heuristics partially cover several of these in structured data.
