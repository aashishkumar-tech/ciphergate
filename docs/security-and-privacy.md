# Security and privacy design

## Local-only

No network calls, telemetry, accounts or downloads. `tests/security/test_no_network.py` runs the
API and CLI with socket creation, connection and DNS patched to fail, and asserts that no module
in `src/` imports network libraries.

## Fail-closed behaviour

| Condition | Result |
|---|---|
| Invalid/unsupported policy | exit 3, nothing processed |
| Required context missing | gate `*_required_but_missing`, exit 1, no output |
| CLI context conflicts with pinned policy context | exit 1 (`environment_context_conflict`) |
| `unknown` context under strict policy | gate review, exit 1 |
| PRD -> non-production without reviewed transfer | gate block, exit 1 |
| External/unknown/missing destination or prd target with non-strict policy, rescan disabled, or credential detectors disabled | gate block |
| JSON/JSONL toward an untrusted/missing destination without `scan_json_keys` | gate block |
| Credential (or other value transform) in a CSV header cell / JSON key | `block` (credential) / `review` |
| No rule for a finding | `review` (or `block`), never allow |
| Credential decided as allow (any route) | forced `block` |
| Key missing/short/invalid | `configuration_required`, exit 6, no output |
| Parse error (strict), size/depth/findings limit | exit 4, no output |
| Transform cannot handle a value | exit 6, no output |
| Gating residual in rescan | exit 7, output withheld |
| Input changed during processing | exit 4, no output |
| Write/flush/rename failure, interruption | exit 5 / 130, temp file removed (a failed removal is logged with the temp path) |
| Report write fails after publishing | exit 5; message states the output was published |

## Keys

- Source: environment variable named by the policy (`key_env`, default `CIPHERGATE_HMAC_KEY`).
  CLI flags are deliberately not offered (process lists, shell history). Key files are not
  supported in this release.
- Format: `hex:<hex>`, `base64:<b64>` or raw text (UTF-8 bytes). At least 32 bytes after
  decoding and 8 distinct byte values; otherwise the status is `too_short`, `invalid_encoding` or
  `low_diversity`.
- Generate: `python -c "import secrets; print('hex:' + secrets.token_hex(32))"`.
- Read only when a keyed transform runs; cached in memory for the run; never in `repr`, logs,
  reports, errors, outputs or docs. Reports show only the variable name, status and transform
  version (`pz1`).
- No fallback key exists. Changing the key changes every pseudonym and date offset.
- Platform note: environment variables are readable by same-user/privileged processes and some
  diagnostic tools on every OS; prefer a CI secret store and short-lived shells.

## Pseudonyms

HMAC-SHA-256 with a key-derived subkey and a versioned, length-prefixed domain
(`ciphergate:pz1:<namespace>:<scope>`), type-tagged canonical values (NFC by default), 160-bit
base32 tokens (`<prefix>pz1_<32 chars>`), and in-run collision detection. Pseudonymization is not
anonymization: equal values under the same key and scope are linkable, and pseudonymized data
can remain personal data.

## Reports and logs

Reports contain: run ID, UTC time, version, input basename (or `<redacted>`), format, byte and
record counts, policy name/version/SHA-256 digest of the policy file, effective context with
sources, gates, counts by category/detector/action/band/reason/rule, safe locations (record,
line, field path, character span), rule IDs and reason codes, key status, changes, parse error
line numbers and codes, rescan summary, warnings and a disclaimer. They never contain values,
snippets, keys, mappings, or hashes of values. Field paths whose segments look like sensitive
values are replaced with `<redacted-key>`; control and bidi characters are escaped.

Logging uses the standard library and never receives values. `--verbose` lists more items;
`--debug` adds traceback frame locations for internal errors without exception messages.

## Files

Inputs must be regular files (FIFOs/devices refused). A directory INPUT starts a batch run:
entries are listed with `lstat`/`scandir` without following symlinks, junctions or other
reparse points (they are reported as skipped), each file is re-checked just before it is
read, the output directory must be new and outside the input, and the sanitized tree is
staged in a private `mkdtemp` directory next to it and renamed into place only if every file
passed. Outputs and reports refuse
symlinks, directories, aliases of the input (realpath, `samefile`, Windows case folding) and
existing files without `--force`. Temp files are created with `mkstemp` in the destination
directory (0600 on POSIX; on Windows they inherit the directory ACL — CipherGate does not change
ACLs). `--force` uses `os.replace`, so the previous file remains until the new one is complete.

`-` (stdin) is spooled into a private `mkdtemp` workspace (owner-only on POSIX) as a 0600 file,
capped by `--max-bytes`, and the workspace is removed when the run ends, including on failure
and Ctrl-C. `--output -` is staged in the same workspace and copied to stdout only after the run
succeeded; stdout then carries no human text.

## Dependencies

`typer` (+ `click`, `rich` transitively — rich tracebacks are disabled because they print local
variables), `pydantic`, `PyYAML` (safe loader subclass). No lockfile, SBOM or dependency
vulnerability scan is provided in this release.
