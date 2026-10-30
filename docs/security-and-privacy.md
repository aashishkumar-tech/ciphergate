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

- Source: environment variable named by the policy (`key_env`, default `CIPHERGATE_HMAC_KEY`),
  or a key file whose path is in `<key_env>_FILE`. CLI flags are deliberately not offered
  (process lists, shell history), and paths are never put in policies (they are shared).
  Setting both the variable and `_FILE` is refused (`ambiguous_source`).
- Key files: regular file, at most 4 KiB, one trailing newline removed, same format as the
  variable. On POSIX the file must be owned by the effective user and have no group/other
  permission bits (`0600`/`0400`), checked on the symlink target (Kubernetes secret mounts use
  symlinks; set `defaultMode: 0400`). On Windows the ACL is **not** checked; a warning is logged.
  The file is read once per run. A failure yields status `file_unreadable`, `file_not_regular`,
  `file_too_large` or `file_permissions_insecure` and exit 6 (`key_file_invalid`) with no output.
  The check runs before the read, so a file swapped between the two (TOCTOU) by someone who can
  write its directory is not detected; keep it in a directory only you can write.
- Format: `hex:<hex>`, `base64:<b64>` or raw text (UTF-8 bytes). At least 32 bytes after
  decoding and 8 distinct byte values; otherwise the status is `too_short`, `invalid_encoding` or
  `low_diversity`.
- Generate: `python -c "import secrets; print('hex:' + secrets.token_hex(32))"`.
- Read only when a keyed transform runs; cached in memory for the run; never in `repr`, logs,
  reports, errors, outputs or docs. Reports show only the variable name, the source (`env` or
  `file`, never the path), status and transform version (`pz1`).
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

## Release publishing

Releases are built only by `.github/workflows/publish.yml`, on a GitHub-hosted runner, from the
release tag. The workflow first checks that the tag matches `__version__` and is on `main`. It
attaches the wheel, the sdist and `SHA256SUMS` to the GitHub release, then uploads the same files
to PyPI as `ciphergate-cli`. The PyPI upload uses Trusted Publishing: a short-lived OIDC
credential, so no PyPI token is stored in the repository. It runs only in the `pypi` GitHub
environment, which requires the maintainer's approval. The upload action produces PEP 740
attestations by default. Releases up to 0.6.1 were built on the maintainer's machine and are
only on GitHub. Do not `pip install ciphergate`: that PyPI name belongs to an unrelated project.
