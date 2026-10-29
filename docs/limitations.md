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
- Text is line-based; only PEM private keys are tracked across lines, plus stack traces with
  `--format stacktrace` (Python, JVM and Node.js frames, without lookahead: JVM/Node header
  lines are not marked as part of the trace; any indented `at name (...)` line counts as a
  frame; exception groups and other runtimes get text-mode scanning only). The structured log
  parsers are `logfmt` (`key=value`), `jsonlog` (JSON objects embedded in a line), `accesslog`
  (nginx/Apache common and combined layouts) and `syslog` (RFC 5424, RFC 3164 with a `tag:`, and
  CEF); LEEF gets text-mode scanning only. None of them supports
  `drop_field`. CEF keys outside a small built-in list get no canonical name for the
  heuristics, and an unescaped ` key=` inside a CEF value starts a new field. `accesslog` recognises only
  lines that start with the common/combined layout; fields after the user agent, virtual-host
  prefixes and custom `log_format`/`LogFormat` layouts get no field context. A logfmt line with
  malformed quoting, and JSON that is invalid, an array at top level, split over several lines,
  nested deeper than the JSON depth limit (64) or past the 16th `{` of a line, get no field
  context. jsonlog may turn a replaced JSON number/boolean/null into a string.
- No Parquet/PDF/Office/database inputs.
- Directory runs (CLI and `*_directory` API) skip symlinks, junctions and special files rather than following
  them, select files by extension unless `--format` is given, and are limited to 1000 files
  (`--max-files`) and 32 directory levels. Discovery and processing are separate steps: an
  entry is re-checked with `lstat` just before it is read, but a hostile local user who can
  write the input directory can still race that check. Publishing renames the staging
  directory; on POSIX `rename` can replace an *empty* directory created at that path in the
  instant after the final existence check. Output directories are created owner-only (0700)
  on POSIX. `--force` does not replace output directories.
- The optional Presidio NER detector is tested only against a fake engine; its real accuracy,
  speed and memory use depend on the spaCy model and have not been measured by this project.
  CipherGate prevents Presidio's automatic model download by checking that the model is
  installed first, but cannot otherwise control what third-party code does once imported.
- stdin/stdout (CLI `-`) and binary streams (`*_stream` API) are spooled to a private temporary
  file before processing (the pipeline reads its input twice), so they are not incremental:
  nothing is written to stdout or the output stream until the whole input has been processed,
  and the input must fit within `--max-bytes` / `max_input_bytes`.
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
  FIFO rejection, key-file permission checks) are tested on the Linux and macOS CI runners. CI
  runs on Linux (Python 3.11-3.13), macOS (3.12) and Windows (3.12). Case-alias checks run on
  whichever filesystems are case-insensitive (default macOS APFS, Windows NTFS); a
  case-sensitive APFS volume behaves like Linux. On Windows the publish uses `os.rename` (fails
  if the target exists) and file ACLs are inherited.
- Symlink tests are skipped where the OS/user cannot create symlinks.

## Compliance

CipherGate is not legal advice, a compliance system, or a certified de-identification service.
Templates named for healthcare or finance do not satisfy HIPAA Safe Harbor, Expert Determination,
PCI DSS or any other requirement by themselves.
