"""inspect / plan / sanitize / rescan orchestration.

Sanitize flow (apply mode):

1. validate input and output paths (no aliasing, no accidental overwrite);
2. pass one: full analysis and plan; stop here unless the plan status is ``ready``;
3. pass two: re-read, re-decide (same engine) and transform into an ``AtomicOutput`` temp file;
4. verify pass-two decision counts equal the plan (otherwise internal error, nothing published);
5. residual rescan of the temp file (when enabled) — gating residuals withhold the output;
6. verify the input file did not change during processing;
7. atomically publish. Any failure or interruption removes the temp file.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from ciphergate.config import RuntimeSettings
from ciphergate.constants import LINE_FORMATS, Action, InputFormat
from ciphergate.detectors.field_names import normalize_field_name
from ciphergate.errors import InputFormatError, InternalError, TransformError
from ciphergate.models.context import ContextInput
from ciphergate.models.report import RunReport, RunStatus
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.pipeline.inspector import Analyzer, Evaluated, RunSetup, prepare_run
from ciphergate.pipeline.paths import display_path, file_digest, validate_output_path
from ciphergate.pipeline.planner import Analysis, analyze_file
from ciphergate.pipeline.rescan import rescan_path
from ciphergate.policy.validator import Policy
from ciphergate.readers import STRUCTURED_LINE_FORMATS, Reader, Record, make_writer
from ciphergate.readers.json_reader import pointer_escape
from ciphergate.readers.line_structure import (
    FieldRegion,
    SpanCodec,
    region_tokens,
    structure_still_valid,
)
from ciphergate.readers.logfmt_reader import parse_fields
from ciphergate.reporting.audit import build_report
from ciphergate.transforms.keys import KeyProvider
from ciphergate.transforms.registry import EntityLookup, Transformer


@dataclass(frozen=True)
class SanitizeOptions:
    apply: bool = True
    force: bool = False
    keys: KeyProvider | None = None
    format: InputFormat | None = None
    runtime: RuntimeSettings | None = None


# --------------------------------------------------------------------------- public operations


def inspect_file(
    path: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
    keys: KeyProvider | None = None,
) -> RunReport:
    """Detect and evaluate; never writes any data file."""
    setup = prepare_run(path, policy, context, runtime, fmt)
    analysis = analyze_file(setup, keys or KeyProvider())
    return build_report("inspect", analysis)


def plan_file(
    path: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
    keys: KeyProvider | None = None,
) -> RunReport:
    """Preview the decisions apply mode would execute; never writes any data file."""
    setup = prepare_run(path, policy, context, runtime, fmt)
    analysis = analyze_file(setup, keys or KeyProvider())
    return build_report("plan", analysis, output=_withheld(None, analysis, "plan_only"))


def rescan_file(
    path: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    strict: bool | None = None,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
) -> RunReport:
    """Report residual findings in an existing (sanitized) file. Read-only."""
    setup = prepare_run(path, policy, context, runtime, fmt)
    effective_strict = policy.document.settings.strict if strict is None else strict
    analysis = analyze_file(setup, KeyProvider({}))
    summary = rescan_path(setup, setup.input_path, strict=effective_strict)
    if file_digest(setup.input_path) != analysis.digest:
        raise InputFormatError("file changed while being rescanned", code="input_changed")
    status = RunStatus.RESCAN_FAILED if summary.failed else RunStatus.PASSED
    warnings = []
    if not summary.failed and summary.counts.get("unexpected", 0):
        warnings.append("unexpected residual findings present (not gating in this mode)")
    analysis.key_statuses = {}
    return build_report("rescan", analysis, status=status, rescan=summary, extra_warnings=warnings)


def sanitize_file(
    input_path: str | Path,
    output_path: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    options: SanitizeOptions | None = None,
) -> RunReport:
    options = options or SanitizeOptions()
    setup = prepare_run(input_path, policy, context, options.runtime, options.format)
    out_path = Path(output_path)
    validate_output_path(out_path, protected=[setup.input_path], force=options.force)
    keys = options.keys or KeyProvider()
    analysis = analyze_file(setup, keys)
    shown = display_path(out_path, setup.runtime.path_display)
    if not options.apply:
        return build_report(
            "sanitize", analysis, output=_withheld(shown, analysis, "apply_not_set")
        )
    if analysis.status != RunStatus.READY:
        return build_report(
            "sanitize", analysis, output=_withheld(shown, analysis, str(analysis.status))
        )

    encoding = setup.reader_options.encoding.replace("-sig", "")
    with AtomicOutput(out_path, force=options.force, encoding=encoding) as out:
        changes = _write_transformed(setup, analysis, out.stream, keys)
        out.finish_writing()
        rescan = None
        if policy.document.settings.rescan.enabled:
            if out.temp_path is None:
                raise InternalError("temporary output missing", code="output_temp_missing")
            rescan = rescan_path(setup, out.temp_path, strict=True)
            if rescan.failed:
                out.abort()
                return build_report(
                    "sanitize",
                    analysis,
                    status=RunStatus.RESCAN_FAILED,
                    output=_withheld(shown, analysis, "residual_finding"),
                    changes=changes,
                    rescan=rescan,
                )
        if file_digest(setup.input_path) != analysis.digest:
            raise InputFormatError(
                "input changed during processing; output discarded", code="input_changed"
            )
        out.publish()
    warnings = [] if rescan is not None else ["rescan gate disabled by policy"]
    return build_report(
        "sanitize",
        analysis,
        status=RunStatus.SANITIZED,
        output={"written": True, "path": shown},
        changes=changes,
        rescan=rescan,
        extra_warnings=warnings,
    )


def _withheld(shown: str | None, analysis: Analysis, reason: str) -> dict[str, Any]:
    return {"written": False, "path": shown, "withheld_reason": reason}


# --------------------------------------------------------------------------- pass two


def _write_transformed(
    setup: RunSetup, analysis: Analysis, stream: IO[str], keys: KeyProvider
) -> dict[str, Any]:
    reader = setup.new_reader()
    analyzer = Analyzer(setup, reader)
    transformer = Transformer(setup.policy, keys)
    writer = make_writer(stream, reader, set(analysis.acc.dropped_columns))
    actions: Counter[str] = Counter()
    stats = {
        "records_written": 0,
        "records_dropped": 0,
        "malformed_records_dropped": 0,
        "values_changed": 0,
        "type_changes": 0,
    }
    for _, evaluated in analyzer.analyze_header():
        for _, decision in evaluated:
            actions[str(decision.action)] += 1
    for record in reader.records():
        if record.malformed:
            stats["malformed_records_dropped"] += 1
            continue
        if record.index < 0:
            writer.write_record(record, record.data)
            continue
        analyzed = analyzer.analyze(record)
        for _, evaluated in analyzed:
            for _, decision in evaluated:
                actions[str(decision.action)] += 1
        if any(d.action == Action.DROP_RECORD for _, ev in analyzed for _, d in ev):
            stats["records_dropped"] += 1
            continue
        data = _transform_record(
            setup.fmt, record, analyzed, transformer, stats, reader, setup.runtime.max_json_depth
        )
        writer.write_record(record, data)
        stats["records_written"] += 1
    writer.close()
    if dict(actions) != dict(analysis.acc.by_action):
        raise InternalError(
            "apply-mode decisions differ from the plan; output discarded",
            code="plan_apply_mismatch",
        )
    dropped = [analysis.acc.dropped_columns[i] for i in sorted(analysis.acc.dropped_columns)]
    return {**stats, "dropped_columns": dropped, "schema_changed": bool(dropped)}


def _csv_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _transform_record(
    fmt: InputFormat,
    record: Record,
    analyzed: list[tuple[Any, Evaluated]],
    transformer: Transformer,
    stats: dict[str, int],
    reader: Reader,
    max_depth: int,
) -> Any:
    def note(changed: bool, type_changed: bool) -> None:
        stats["values_changed"] += int(changed)
        stats["type_changes"] += int(type_changed)

    if fmt in LINE_FORMATS:
        line = record.data
        lookup: EntityLookup | None = None
        codec: SpanCodec | None = None
        regions: list[FieldRegion] = []
        structure = STRUCTURED_LINE_FORMATS.get(fmt)
        if fmt == InputFormat.LOGFMT:
            lookup = _logfmt_lookup(line)
        elif structure is not None:
            regions = structure.parse(line, max_depth)
            lookup, codec = _structured_lookup(regions), SpanCodec(structure, regions)
        original = line
        for item, evaluated in analyzed:
            outcome = transformer.transform_value(
                line, evaluated, field_path=item.field_path, entity_lookup=lookup, span_codec=codec
            )
            note(outcome.changed, False)
            line = outcome.value
        if (
            structure is not None
            and regions
            and line != original
            and not structure_still_valid(structure, line, regions, max_depth)
        ):
            raise TransformError(
                f"rewriting a line would break its {fmt} structure; nothing was published",
                code=f"{fmt}_rewrite_invalid",
            )
        return line

    if fmt == InputFormat.CSV:
        row = list(record.data)
        lookup = _csv_lookup(record, getattr(reader, "field_names", []))
        for item, evaluated in analyzed:
            outcome = transformer.transform_value(
                row[item.column_index], evaluated, field_path=item.field_path, entity_lookup=lookup
            )
            if not outcome.drop_field:
                row[item.column_index] = _csv_text(outcome.value)
            note(outcome.changed, False)
        return row

    values: dict[str, Evaluated] = {}
    key_drops: set[str] = set()
    for item, evaluated in analyzed:
        if item.in_key:
            if any(d.action == Action.DROP_FIELD for _, d in evaluated):
                key_drops.add(item.field_path)
        else:
            values[item.field_path] = evaluated
    prefix = f"/{record.index}" if getattr(reader, "top_level_array", False) else ""
    lookup = _json_lookup(record.data)

    def rebuild(node: Any, pointer: str) -> tuple[Any, bool]:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                child = f"{pointer}/{pointer_escape(key)}"
                if child in key_drops:
                    note(True, False)
                    continue
                new_value, drop = rebuild(value, child)
                if drop:
                    continue
                out[key] = new_value
            return out, False
        if isinstance(node, list):
            items_out = []
            drop_any = False
            for i, value in enumerate(node):
                new_value, drop = rebuild(value, f"{pointer}/{i}")
                drop_any = drop_any or drop
                items_out.append(new_value)
            return items_out, drop_any
        evaluated = values.get(pointer)
        if not evaluated:
            return node, False
        outcome = transformer.transform_value(
            node, evaluated, field_path=pointer, entity_lookup=lookup
        )
        note(outcome.changed, outcome.type_changed)
        if outcome.drop_field:
            return node, True
        return outcome.value, False

    data, dropped_root = rebuild(record.data, prefix)
    if dropped_root:
        raise TransformError(
            "drop_field cannot remove the root of a record", code="drop_field_unsupported"
        )
    return data


def _csv_lookup(record: Record, field_names: list[str | None]) -> EntityLookup:
    columns: dict[str, Any] = {}
    for i, name in enumerate(field_names):
        if name is not None:
            columns.setdefault(normalize_field_name(name), record.data[i])

    def lookup(name: str) -> Any:
        return columns.get(normalize_field_name(name))

    return lookup


def _structured_lookup(regions: list[FieldRegion]) -> EntityLookup:
    values: dict[str, Any] = {}
    for token in region_tokens(regions):
        if token.kind != "key" and token.key is not None:
            values.setdefault(normalize_field_name(token.key), token.value)

    def lookup(name: str) -> Any:
        return values.get(normalize_field_name(name))

    return lookup


def _logfmt_lookup(line: str) -> EntityLookup:
    values: dict[str, str] = {}
    for field in parse_fields(line) or []:
        values.setdefault(normalize_field_name(field.key), field.value)

    def lookup(name: str) -> Any:
        return values.get(normalize_field_name(name))

    return lookup


def _json_lookup(data: Any) -> EntityLookup:
    def lookup(name: str) -> Any:
        target = normalize_field_name(name)
        stack = [data]
        while stack:
            node = stack.pop(0)
            if isinstance(node, dict):
                for key, value in node.items():
                    if (key == name or normalize_field_name(key) == target) and not isinstance(
                        value, dict | list
                    ):
                        return value
                stack.extend(v for v in node.values() if isinstance(v, dict | list))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, dict | list))
        return None

    return lookup
