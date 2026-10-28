# Limitations

## Detection

- Detection is incomplete. Names, addresses, government IDs and bank accounts are not detected by
  value in free text; secrets in custom formats or encoded forms are missed. See
  [detector-coverage.md](detector-coverage.md).
- A clean rescan is a quality gate, not proof of safety. Rescan cannot verify date-shifted values
  (reported as `unverifiable`) and recognises CipherGate's own markers/pseudonyms/replacement
  constants as transformed output.
- Confidence values are uncalibrated engineering estimates.

## Context

- Environment, target environment and destination are declared by the caller or policy and are
  not verified. CipherGate does not inspect cloud identity or control deployments.

## Formats and processing

- JSON is parsed as a whole document (default limit 32 MiB). CSV/JSONL/text are streamed with
  per-record limits (default 1 MiB) and a total limit (default 100 MiB).
- Only ASCII-compatible encodings (UTF-8, ASCII, Latin-1, CP1252); undecodable bytes fail the run
  (no lossy mode).
- JSON output is re-serialized (2-space indent, UTF-8); whitespace and number formatting of
  untouched values may change while values stay equal. JSONL is re-serialized per line.
- Text is line-based; only PEM private keys are tracked across lines. No structured log parsers.
- No stdin/stdout data streaming, no directory/batch processing, no Parquet/PDF/Office/database
  inputs.
- `drop_field` is unsupported for text; `drop_record` is unsupported for a single (non-array)
  JSON document; both become `review`.
- JSON object keys are only scanned with `scan_json_keys: true` (all shipped templates set it;
  policies pinned to an untrusted destination must, and JSON runs toward an untrusted or missing
  destination are blocked without it). CSV header cells are always scanned. Only
  allow/drop_field/block/review can apply to a key or header cell; a value transform there becomes
  `review`, and a credential there blocks.
- When a header cell or key produces a finding, its label is replaced by `<redacted-key>` in
  reports. Other labels are shown, masked only if they look like an email, secret, card, IP or
  phone number — a person's name used as a JSON key, for example, can still appear in a report
  path.
- `--report` is written after the output is published. If writing the report fails, the CLI exits
  5 and says explicitly that the output **was** published.

## Transforms

- No reversible tokenization (rejected by validation).
- `pseudonymize` outputs strings (numeric types are not preserved). `date_shift` supports ISO
  dates/datetimes with fixed offsets and explicit strptime patterns; no named time zones or epoch
  values.
- Generalization does not make data anonymous; combinations of quasi-identifiers can remain
  identifying.

## Platform

- POSIX-only behaviours (0600 temp permissions, hard-link no-overwrite publish, directory fsync,
  FIFO rejection) are tested only on POSIX CI runners. On Windows the publish uses `os.rename`
  (fails if the target exists) and file ACLs are inherited.
- Symlink tests are skipped where the OS/user cannot create symlinks.

## Compliance

CipherGate is not legal advice, a compliance system, or a certified de-identification service.
Templates named for healthcare or finance do not satisfy HIPAA Safe Harbor, Expert Determination,
PCI DSS or any other requirement by themselves.
