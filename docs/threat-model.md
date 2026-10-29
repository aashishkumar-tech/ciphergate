# Threat model

## Assets

Raw input values and files; credentials, tokens, private keys, connection strings; direct and
indirect identifiers; regulated/sensitive fields; proprietary content; the pseudonymization key;
file paths and reports; relationships that pseudonyms are meant to preserve.

## Adversaries and failure sources

| Threat | Mitigation | Residual risk |
|---|---|---|
| Developer shares unmasked data | Inspect/plan/sanitize workflow; fail-closed fallback; CI exit codes | Users can skip the tool or pick a permissive policy |
| Detector false negative | Field-name + content detectors; conservative policies; rescan gate | **High**: free text, encodings, names and custom secrets can be missed |
| Detector false positive | Confidence bands; scoped rules; `explain` | Over-redaction reduces utility |
| Overly permissive rule | Credential hard constraint; acknowledgement for risky allows; conflict rejection; validation warnings | A reviewed-but-wrong policy still leaks |
| Missing policy/context/key resolves to allow | Required context gates; `review`/`block` fallback; no fallback key; status `configuration_required` | — (tested) |
| Mislabelled environment | Documented as declared context; PRD guardrails | CipherGate cannot verify origin |
| Exception/log prints data | Authored messages; parser messages replaced; no rich tracebacks; leak tests | Python itself may print on catastrophic failure (e.g. interpreter crash) |
| Report reveals data | Counts/locations only; header cells/keys with findings shown as `<redacted-key>`, other labels masked when they look sensitive; no fingerprints; path display modes | Field names (e.g. a person's name used as a key), counts and line numbers can still be revealing |
| Malformed/malicious file | Size/line/depth/findings limits; strict parsers; bounded regexes; regular files only | Regex backtracking heuristics are not a proof |
| Path traversal / symlinks / overwrite | Alias checks (realpath, samefile, case), symlink output refusal, no-overwrite default | TOCTOU between check and publish on hostile local filesystems |
| Partial output on failure | Temp file + fsync + atomic publish after all checks; cleanup | Cleanup can fail (logged to stderr with the temp path); power loss semantics depend on filesystem; the report is written after publication |
| Raw stdin on disk (`-` input) | Spooled to a `mkdtemp` workspace (0700/0600 on POSIX), capped by `max_input_bytes`, removed on success, failure and interruption | Exists on disk for the run; a hard kill or power loss can leave a `ciphergate-stdio-*` directory in the temp dir; on Windows it inherits the user temp directory ACL |
| Unsafe data on stdout (`--output -`) | Staged in the workspace and copied to stdout only after all checks pass; summary on stderr; JSON report to stdout refused | A closed pipe mid-copy leaves the reader with partial (sanitized) data; exit 5 signals it, but only if the caller checks the status |
| Key exposure/weak key | Env-var only, min 32 bytes, diversity check, never logged | Env vars visible to privileged local processes |
| Cross-context linkage via pseudonyms | Default narrow scopes; scope explicit in policy; namespace | Same key + scope links equal values by design |
| Optional model downloads / network | No optional detectors shipped; no network imports in `src/` (tested) | Dependencies are trusted |

## Assumptions

The host, Python runtime and dependencies are trusted. The tool runs with the user's OS
permissions and cannot protect against a compromised host or administrator. Policies are
reviewed by someone who understands the data.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
