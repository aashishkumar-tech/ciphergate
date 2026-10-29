"""Run setup and per-record analysis (readers -> detectors -> policy engine).

The same ``Analyzer`` is used by inspect, plan, sanitize (both passes) and rescan, so the plan
predicts exactly the decisions that apply mode executes.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from ciphergate.config import RuntimeSettings
from ciphergate.constants import Action, InputFormat, ReasonCode
from ciphergate.detectors.base import is_ciphergate_token
from ciphergate.detectors.registry import (
    FIELD_CONTEXT_DETECTORS,
    DetectorSet,
    TextBlockState,
)
from ciphergate.models.context import ContextInput, EffectiveContext
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.pipeline.paths import validate_input_path
from ciphergate.policy.context import resolve_context
from ciphergate.policy.engine import Decision, PolicyEngine
from ciphergate.policy.precedence import LEVEL_HARD_CONSTRAINT
from ciphergate.policy.validator import Policy
from ciphergate.readers import (
    STRUCTURED_LINE_FORMATS,
    ReaderOptions,
    Record,
    detect_format,
    open_reader,
)
from ciphergate.readers.base import Reader, normalize_encoding
from ciphergate.readers.json_reader import JSONReader
from ciphergate.readers.line_structure import (
    LineStructure,
    region_tokens,
    snap_span,
    token_at,
)
from ciphergate.readers.logfmt_reader import field_for_span, parse_fields

Evaluated = list[tuple[Finding, Decision]]


def _attribute(finding: Finding, key: str) -> Finding:
    return _attribute_path(finding, key, "/" + key)


def _attribute_path(finding: Finding, key: str, path: str) -> Finding:
    location = replace(finding.location, field_path=path)
    return replace(finding, field_name=key, location=location)


def _with_span(finding: Finding, span: tuple[int, int]) -> Finding:
    return replace(finding, location=replace(finding.location, span=span))


@dataclass(frozen=True)
class RunSetup:
    input_path: Path
    fmt: InputFormat
    policy: Policy
    ctx: EffectiveContext
    runtime: RuntimeSettings
    reader_options: ReaderOptions
    detectors: DetectorSet
    engine: PolicyEngine

    def new_reader(self, path: Path | None = None) -> Reader:
        return open_reader(path or self.input_path, self.fmt, self.reader_options)


def prepare_run(
    input_path: str | Path,
    policy: Policy,
    context: ContextInput | None,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
) -> RunSetup:
    runtime = runtime or RuntimeSettings()
    ctx = resolve_context(policy, context)
    path = Path(input_path)
    validate_input_path(path, runtime.max_input_bytes)
    detected = detect_format(path, fmt)
    options = ReaderOptions(
        runtime=runtime,
        policy_settings=policy.document.settings,
        encoding=normalize_encoding(runtime.encoding),
    )
    return RunSetup(
        input_path=path,
        fmt=detected,
        policy=policy,
        ctx=ctx,
        runtime=runtime,
        reader_options=options,
        detectors=DetectorSet(policy.document.detectors, policy.document),
        engine=PolicyEngine(policy),
    )


class Analyzer:
    def __init__(self, setup: RunSetup, reader: Reader) -> None:
        self.setup = setup
        self.reader = reader
        self.text_state = TextBlockState()
        self._single_json_document = isinstance(reader, JSONReader)

    def analyze(self, record: Record) -> list[tuple[ScanItem, Evaluated]]:
        return self._analyze_items(self.reader.iter_items(record))

    def analyze_header(self) -> list[tuple[ScanItem, Evaluated]]:
        """CSV header cells (key items). Must run before ``records()`` is iterated."""
        header_items = getattr(self.reader, "header_items", None)
        if header_items is None:
            return []
        return self._analyze_items(header_items())

    def _analyze_items(self, items: Iterable[ScanItem]) -> list[tuple[ScanItem, Evaluated]]:
        setup = self.setup
        out: list[tuple[ScanItem, Evaluated]] = []
        for item in items:
            if setup.fmt == InputFormat.TEXT:
                findings = setup.detectors.scan_text_line(item, self.text_state)
            elif setup.fmt == InputFormat.LOGFMT:
                findings = self._scan_logfmt_line(item)
            elif setup.fmt in STRUCTURED_LINE_FORMATS:
                findings = self._scan_structured_line(item, STRUCTURED_LINE_FORMATS[setup.fmt])
            else:
                findings = setup.detectors.scan(item)
            if not findings:
                continue
            evaluated = [
                (f, self._constrain(setup.engine.decide(f, setup.ctx, setup.fmt), item))
                for f in findings
            ]
            out.append((item, evaluated))
        return out

    def _scan_logfmt_line(self, item: ScanItem) -> list[Finding]:
        """Text-mode scan of the whole line, plus field context from the key=value parse."""
        detectors = self.setup.detectors
        in_key_block = self.text_state.in_private_key_block
        findings = detectors.scan_text_line(item, self.text_state)
        fields = None if in_key_block else parse_fields(item.text or "")
        if not fields:
            return findings
        out: list[Finding] = []
        for finding in findings:
            span = finding.location.span
            field = field_for_span(fields, span) if span is not None else None
            out.append(_attribute(finding, field.key) if field is not None else finding)
        for field in fields:
            if field.end <= field.start:
                continue  # empty value: nothing to protect
            key_item = ScanItem(
                item.record_index, item.line, "/" + field.key, field.key, field.value
            )
            for finding in detectors.scan_field_context(key_item):
                location = replace(
                    finding.location, field_path="/" + field.key, span=(field.start, field.end)
                )
                out.append(replace(finding, location=location))
        return detectors.post_process(out)

    def _scan_structured_line(self, item: ScanItem, structure: LineStructure) -> list[Finding]:
        """Text-mode scan of the whole line, plus field context from the line's parsed fields."""
        detectors = self.setup.detectors
        in_key_block = self.text_state.in_private_key_block
        findings = detectors.scan_text_line(item, self.text_state)
        text = item.text or ""
        max_depth = self.setup.runtime.max_json_depth
        regions = [] if in_key_block else structure.parse(text, max_depth)
        if not regions:
            return findings
        tokens = region_tokens(regions)
        out: list[Finding] = []
        for finding in findings:
            span = finding.location.span
            if span is None:
                out.append(finding)
                continue
            # Never let a replacement cross field syntax; keep the original span if nothing is left.
            for piece in snap_span(regions, *span) or [span]:
                moved = finding if piece == span else _with_span(finding, piece)
                owner = token_at(tokens, *piece)
                if owner is not None and owner.kind != "key" and owner.key is not None:
                    moved = _attribute_path(moved, owner.key, owner.pointer)
                out.append(moved)
        for token in tokens:
            if token.kind == "key" or token.key is None or token.end <= token.start:
                continue
            value_item = ScanItem(
                item.record_index, item.line, token.pointer, token.key, token.value
            )
            # A key CipherGate wrote (marker/pseudonym) says nothing about its value: field
            # context from it would flag our own output. Content detectors still run.
            own_key = is_ciphergate_token(token.key)
            if own_key and not token.escaped:
                continue
            # Escaped strings hide content from the raw-text scan: scan the decoded value too.
            found = (
                detectors.scan(value_item)
                if token.escaped
                else detectors.scan_field_context(value_item)
            )
            if token.hint and not own_key:
                # A canonical name (e.g. CEF "suser" -> "source_user_name") adds heuristics on
                # top of the real key; findings keep the real key for policy field_names rules.
                hint_item = replace(value_item, field_name=token.hint)
                found += detectors.scan_field_context(hint_item)
            if own_key:
                found = [f for f in found if f.detector not in FIELD_CONTEXT_DETECTORS]
            for finding in found:
                location = replace(
                    finding.location, field_path=token.pointer, span=(token.start, token.end)
                )
                out.append(replace(finding, field_name=token.key, location=location))
        for token in tokens:
            if token.kind == "key" and token.escaped:
                key_item = ScanItem(item.record_index, item.line, token.pointer, None, token.value)
                for finding in detectors.scan(key_item):
                    location = replace(finding.location, span=(token.start, token.end))
                    out.append(replace(finding, location=location))
        # Each scan above already applied phone suppression; re-running it on the merged list
        # would let whole-value spans hide findings, so only de-duplicate.
        return detectors.dedupe(out)

    def _constrain(self, decision: Decision, item: ScanItem) -> Decision:
        """Location-dependent applicability (fail closed to review, never silently skip)."""
        single_doc = self._single_json_document and not getattr(
            self.reader, "top_level_array", False
        )
        header_cell = item.record_index < 0
        unsupported = (decision.action == Action.DROP_RECORD and (single_doc or header_cell)) or (
            decision.action == Action.DROP_FIELD
            and self.setup.fmt in (InputFormat.JSON, InputFormat.JSONL)
            and item.field_name is None
            and not item.in_key
        )
        if unsupported:
            return Decision(
                Action.REVIEW,
                ReasonCode.UNSUPPORTED_TRANSFORM,
                LEVEL_HARD_CONSTRAINT,
                overridden_rule_id=decision.rule_id,
            )
        return decision
