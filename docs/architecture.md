# Architecture

## Data flow

```text
Input file
   |  pipeline/paths.py        regular file, size limit, alias checks
   v
Format adapter (readers/)      CSV / JSON / JSONL / text -> Records -> ScanItems
   v
Detectors (detectors/)         candidates: category, confidence, evidence, location (no values)
   v
Policy engine (policy/)        context resolution + run gates + per-finding Decision
   v
Planner (pipeline/planner.py)  pass 1: counts, items, drops, key needs -> status
   |   status != ready  ->  report only, nothing written (exit 1 / 6)
   v
Transformer (transforms/)      pass 2: same Analyzer re-decides; transforms values
   v
AtomicOutput                   temp file -> fsync -> rescan gate -> input unchanged? -> publish
   v
Report (reporting/)            privacy-safe JSON / text summary
```

## Module responsibilities

| Module | Responsibility | Must not |
|---|---|---|
| `constants.py` | Stable IDs: environments, destinations, categories, actions, reason/exit codes | — |
| `errors.py` | Exception hierarchy with stable codes and authored, value-free messages | forward third-party messages |
| `config.py` | Runtime limits (bytes, depth, findings, encoding, path display) | change policy decisions |
| `models/` | Typed `Finding`/`Location`/`ScanItem`, policy schema (pydantic, `extra=forbid`), context, report | hold raw values in findings/reports |
| `readers/` | Parse and write each format; limits; encodings; JSON Pointer paths | decide actions |
| `detectors/` | Produce candidate findings; per-run `DetectorSet` (no global registry) | decide actions |
| `policy/loader.py` | Safe YAML (no tags, no aliases, no duplicate keys, size limit) | execute code |
| `policy/validator.py` | Schema + semantic checks, compile into immutable `Policy` | — |
| `policy/precedence.py` | Computed precedence levels and static overlap analysis | — |
| `policy/context.py` | Pinned vs caller context, run-level gates | infer one context dimension from another |
| `policy/engine.py` | `decide(finding, context, format) -> Decision` + hard constraints | read values |
| `transforms/` | Execute approved actions; HMAC pseudonyms; key lookup | log values or keys |
| `pipeline/` | Orchestration, two passes, rescan, atomic output, path safety | publish on any failure |
| `reporting/` | Report building, control-char escaping, field-path masking, rendering | include values/fingerprints |
| `cli.py` | Typer CLI, exit codes, safe error rendering, SIGTERM -> interrupt | enable rich tracebacks (they print locals) |

## Why two passes

Pass one builds the complete plan (all findings, drop-column decisions for CSV, key needs) before
any output exists, so a `block`/`review` anywhere in the file prevents any output, and CSV columns
can be dropped at schema level. Pass two re-reads and re-decides with the same `Analyzer`; the
per-action decision counts must equal the plan or the run fails (`plan_apply_mismatch`). The input
digest is compared before publication to detect concurrent modification.

## Error paths

Every `CipherGateError` carries a stable `code` and an exit code; the CLI prints
`error[<code>]: <message>`. Unexpected exceptions become exit 8 with a generic message; `--debug`
adds frame locations only. `AtomicOutput` removes the temp file on any exception or
`KeyboardInterrupt` (SIGTERM is converted to `KeyboardInterrupt` by the CLI).

## Trust boundaries

- **Input data**: untrusted; parsed with bounded readers; values never leave memory except as
  transformed output.
- **Policy files**: trusted configuration, but validated strictly (they can weaken protection).
- **Context flags**: declared by the caller; not verified.
- **Key material**: environment variable, read only when a keyed transform runs.
- **Reports**: designed to be shareable; no values, only counts, locations and decisions. Field
  labels are structural metadata: labels of keys/header cells with findings are replaced by
  `<redacted-key>`, others are masked only when they look sensitive (see limitations).

## Optional detectors

`detectors/presidio_ner.py` (extra `ner`) is the only optional detector. `DetectorSet` imports it
only when `detectors.presidio.enabled` is true, so the base install never loads it. It checks
that `presidio_analyzer` and the configured spaCy model package are importable *before* importing
Presidio (Presidio would otherwise download a missing model), builds the engine once per process,
replaces every third-party error message, and only produces findings; the engine still decides.
A missing extra or model is `DetectorUnavailableError` (exit 6).
