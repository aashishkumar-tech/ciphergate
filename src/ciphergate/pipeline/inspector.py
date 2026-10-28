"""Run setup and per-record analysis (readers -> detectors -> policy engine).

The same ``Analyzer`` is used by inspect, plan, sanitize (both passes) and rescan, so the plan
predicts exactly the decisions that apply mode executes.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ciphergate.config import RuntimeSettings
from ciphergate.constants import Action, InputFormat, ReasonCode
from ciphergate.detectors.registry import DetectorSet, TextBlockState
from ciphergate.models.context import ContextInput, EffectiveContext
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.pipeline.paths import validate_input_path
from ciphergate.policy.context import resolve_context
from ciphergate.policy.engine import Decision, PolicyEngine
from ciphergate.policy.precedence import LEVEL_HARD_CONSTRAINT
from ciphergate.policy.validator import Policy
from ciphergate.readers import ReaderOptions, Record, detect_format, open_reader
from ciphergate.readers.base import Reader, normalize_encoding
from ciphergate.readers.json_reader import JSONReader

Evaluated = list[tuple[Finding, Decision]]


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
