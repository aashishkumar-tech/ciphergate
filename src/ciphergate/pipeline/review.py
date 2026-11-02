"""``review``: run the sanitize steps without publishing output, and write a local HTML page.

The sanitized data goes to an owner-only temp file next to the page so the normal residual rescan
can run on it; that temp file is always removed and never published. The page shows the would-be
output with changed spots marked, the decisions per record and run metrics. The original input is
added only with ``include_input`` (the page then holds raw data and must be handled like it).

A blocked, review-required or key-missing run produces no output, so its page shows the plan only.
The page is written atomically, refuses to overwrite without ``force`` and never aliases the input.
"""

from __future__ import annotations

import csv
import difflib
import io
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ciphergate.config import RuntimeSettings
from ciphergate.constants import LINE_FORMATS, Action, InputFormat
from ciphergate.errors import InputFormatError, InternalError
from ciphergate.models.context import ContextInput
from ciphergate.models.report import RunReport, RunStatus
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.pipeline.inspector import Analyzer, Evaluated, RunSetup, prepare_run
from ciphergate.pipeline.paths import display_path, file_digest, validate_output_path
from ciphergate.pipeline.planner import analyze_file
from ciphergate.pipeline.rescan import rescan_path
from ciphergate.pipeline.sanitizer import _write_transformed
from ciphergate.policy.validator import Policy
from ciphergate.readers import Record
from ciphergate.readers.json_reader import pointer_escape
from ciphergate.reporting.audit import build_report
from ciphergate.reporting.review_page import render_review_page
from ciphergate.reporting.safe_text import safe_field_path
from ciphergate.transforms.keys import KeyProvider

MAX_RECORDS = 500  # records shown on the page; the rest are counted
MAX_RECORD_CHARS = 4_000  # longer records are cut before comparing and display
# Words, runs of spaces, or single punctuation marks: changes are shown per token, not per letter.
_TOKEN_RE = re.compile(r"\w+|\s+|[^\w\s]")
# Categories where part of a value left next to a replacement often means a partial find.
_NAME_LIKE = frozenset({"pii.person_name", "pii.address"})
Span = tuple[int, int, tuple[str, ...]]  # start, end, decision labels
Fields = dict[str, tuple[int, int]]  # cell or JSON pointer -> start, end in the shown text


@dataclass(frozen=True)
class Segment:
    """A marked range of a shown text: ``change``, ``delete``, ``kept`` or ``finding``."""

    start: int
    end: int
    kind: str
    labels: tuple[str, ...]
    partial: bool = False


@dataclass
class ReviewRecord:
    index: int
    line: int | None
    after: str | None  # the would-be output; None when dropped or no output exists
    dropped: bool
    out_segments: list[Segment]
    decisions: list[dict[str, Any]]
    before: str | None = None  # only with include_input
    in_segments: list[Segment] = field(default_factory=list)
    truncated: bool = False


@dataclass
class ReviewData:
    report: RunReport
    records: list[ReviewRecord]
    records_with_findings: int
    records_hidden: int
    category_actions: dict[str, dict[str, int]]  # every finding, not only the shown records
    possible_partial: int
    has_output: bool
    include_input: bool
    page_path: str | None


@dataclass(frozen=True)
class ReviewOptions:
    force: bool = False
    include_input: bool = False
    keys: KeyProvider | None = None
    format: InputFormat | None = None
    runtime: RuntimeSettings | None = None
    protected: tuple[Path, ...] = ()


def review_file(
    input_path: str | Path,
    page_path: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    options: ReviewOptions | None = None,
) -> ReviewData:
    """Build the review data and atomically write the HTML page to ``page_path``."""
    options = options or ReviewOptions()
    setup = prepare_run(input_path, policy, context, options.runtime, options.format)
    page = Path(page_path)
    validate_output_path(
        page, protected=[setup.input_path, *options.protected], force=options.force, label="review"
    )
    data = build_review(setup, page, options)
    html_text = render_review_page(data)
    with AtomicOutput(page, force=options.force, encoding="utf-8") as out:
        out.stream.write(html_text)
        out.publish()
    return data


def build_review(setup: RunSetup, page: Path, options: ReviewOptions) -> ReviewData:
    keys = options.keys or KeyProvider()
    analysis = analyze_file(setup, keys)
    collector = _Collector(
        setup,
        options.include_input,
        set(analysis.acc.dropped_columns),
        analysis.top_level_array,
    )
    withheld = {"written": False, "path": None, "withheld_reason": "review_only"}
    if analysis.status != RunStatus.READY:
        reader = setup.new_reader()
        analyzer = Analyzer(setup, reader)
        analyzer.analyze_header()
        for record in reader.records():
            if not record.malformed and record.index >= 0:
                collector.add(record, analyzer.analyze(record), None, has_output=False)
        report = build_report("review", analysis, output=withheld)
        return collector.result(report, has_output=False, page=page, setup=setup)

    encoding = setup.reader_options.encoding.replace("-sig", "")
    # Never published: only the parent directory of this name is used, for the temp file.
    scratch = page.with_name(page.name + ".sanitized-preview")
    with AtomicOutput(scratch, force=False, encoding=encoding) as out:
        changes = _write_transformed(
            setup,
            analysis,
            out.stream,
            keys,
            on_record=lambda record, analyzed, after: collector.add(
                record, analyzed, after, has_output=True
            ),
        )
        out.finish_writing()
        rescan = None
        if setup.policy.document.settings.rescan.enabled:
            if out.temp_path is None:
                raise InternalError("temporary output missing", code="output_temp_missing")
            rescan = rescan_path(setup, out.temp_path, strict=True)
        out.abort()
    if file_digest(setup.input_path) != analysis.digest:
        raise InputFormatError("input changed during processing", code="input_changed")
    status = RunStatus.RESCAN_FAILED if rescan is not None and rescan.failed else RunStatus.READY
    warnings = [] if rescan is not None else ["rescan gate disabled by policy"]
    report = build_report(
        "review",
        analysis,
        status=status,
        output=withheld,
        changes=changes,
        rescan=rescan,
        extra_warnings=warnings,
    )
    return collector.result(report, has_output=True, page=page, setup=setup)


class _Collector:
    def __init__(
        self,
        setup: RunSetup,
        include_input: bool,
        dropped_columns: set[int],
        top_level_array: bool,
    ) -> None:
        self.setup = setup
        self.include_input = include_input
        self.dropped_columns = dropped_columns
        self.top_level_array = top_level_array
        self.records: list[ReviewRecord] = []
        self.with_findings = 0
        self.hidden = 0
        self.partial = 0
        self.matrix: dict[str, Counter[str]] = defaultdict(Counter)
        self.redact = setup.runtime.path_display == "redacted"
        self.delimiter = setup.runtime.csv_delimiter

    def add(
        self,
        record: Record,
        analyzed: list[tuple[Any, Evaluated]],
        after_data: Any,
        *,
        has_output: bool,
    ) -> None:
        pairs = [(f, d) for _, evaluated in analyzed for f, d in evaluated]
        if not pairs:
            return
        self.with_findings += 1
        for finding, decision in pairs:
            self.matrix[finding.category][str(decision.action)] += 1
        dropped = has_output and after_data is None
        before, before_fields = self._render(record.data, drop_columns=False, index=record.index)
        after: str | None = None
        after_fields: Fields = {}
        if after_data is not None:
            after, after_fields = self._render(after_data, drop_columns=True, index=record.index)
        cut = max(len(before), len(after or "")) > MAX_RECORD_CHARS
        before, before_fields = _clip(before, before_fields)
        if after is not None:
            after, after_fields = _clip(after, after_fields)
        if self.setup.fmt in LINE_FORMATS:
            out_segments, in_segments = self._line_segments(pairs, before, after)
        else:
            out_segments, in_segments = self._field_segments(
                pairs, before, before_fields, after, after_fields
            )
        self.partial += sum(1 for s in out_segments if s.partial)
        if len(self.records) >= MAX_RECORDS:
            self.hidden += 1
            return
        self.records.append(
            ReviewRecord(
                index=record.index,
                line=record.line,
                after=after,
                dropped=dropped,
                out_segments=out_segments,
                decisions=[self._decision(f, d) for f, d in pairs],
                before=before if self.include_input else None,
                in_segments=in_segments if self.include_input else [],
                truncated=cut,
            )
        )

    def _line_segments(
        self, pairs: list[tuple[Any, Any]], before: str, after: str | None
    ) -> tuple[list[Segment], list[Segment]]:
        """Line formats: findings carry character spans inside the shown line."""
        spans = self._finding_spans(p for p in pairs if p[1].action != Action.ALLOW)
        kept = self._finding_spans(p for p in pairs if p[1].action == Action.ALLOW)
        if after is not None:
            return _diff_segments(before, after, spans, kept, _labels(pairs, allow=False))
        return [], [Segment(s, e, "finding", labels) for s, e, labels in spans + kept]

    def _field_segments(
        self,
        pairs: list[tuple[Any, Any]],
        before: str,
        before_fields: Fields,
        after: str | None,
        after_fields: Fields,
    ) -> tuple[list[Segment], list[Segment]]:
        """CSV and JSON: compare each cell or value on its own and label it with its decisions."""
        by_field: dict[str, list[tuple[Any, Any]]] = defaultdict(list)
        for finding, decision in pairs:
            by_field[self._field_key(finding)].append((finding, decision))
        fallback = _labels(pairs, allow=False)
        out: list[Segment] = []
        inp: list[Segment] = []
        for key, (bs, be) in before_fields.items():
            own = by_field.get(key, [])
            changed_labels = _labels(own, allow=False)
            kept_labels = _labels(own, allow=True)
            if after is None:
                if own:
                    inp.append(Segment(bs, be, "finding", changed_labels + kept_labels))
                continue
            span = after_fields.get(key)
            if span is None:  # the field (or a parent object) was dropped
                inp.append(Segment(bs, be, "change", changed_labels or fallback))
                continue
            old, new = before[bs:be], after[span[0] : span[1]]
            if old == new:
                if kept_labels:
                    out.append(Segment(span[0], span[1], "kept", kept_labels))
                    inp.append(Segment(bs, be, "kept", kept_labels))
                continue
            o, i = _diff_segments(old, new, [], [], changed_labels or fallback)
            out += [replace(s, start=s.start + span[0], end=s.end + span[0]) for s in o]
            inp += [replace(s, start=s.start + bs, end=s.end + bs) for s in i]
        return out, inp

    def _field_key(self, finding: Any) -> str:
        if self.setup.fmt == InputFormat.CSV:
            return f"#{finding.location.column_index}"
        return str(finding.location.field_path)

    def result(
        self, report: RunReport, *, has_output: bool, page: Path, setup: RunSetup
    ) -> ReviewData:
        return ReviewData(
            report=report,
            records=self.records,
            records_with_findings=self.with_findings,
            records_hidden=self.hidden,
            category_actions={c: dict(sorted(a.items())) for c, a in sorted(self.matrix.items())},
            possible_partial=self.partial,
            has_output=has_output,
            include_input=self.include_input,
            page_path=display_path(page, setup.runtime.path_display),
        )

    def _render(self, data: Any, *, drop_columns: bool, index: int) -> tuple[str, Fields]:
        """The record as the output format writes it, with the position of each cell or value."""
        fmt = self.setup.fmt
        if fmt in LINE_FORMATS:
            text = str(data)
            return text, {"": (0, len(text))}
        fields: Fields = {}
        if fmt == InputFormat.CSV:
            cells: list[str] = []
            pos = 0
            for i, value in enumerate(data):
                if drop_columns and i in self.dropped_columns:
                    continue
                cell = self._csv_cell(value)
                if cells:
                    pos += len(self.delimiter)
                fields[f"#{i}"] = (pos, pos + len(cell))
                pos += len(cell)
                cells.append(cell)
            return self.delimiter.join(cells), fields
        parts: list[str] = []
        prefix = f"/{index}" if self.top_level_array else ""
        _dump_json(data, prefix, parts, fields, [0])
        return "".join(parts), fields

    def _csv_cell(self, value: Any) -> str:
        if value == "":
            return ""  # the csv module writes a lone empty field as "", but not inside a row
        buf = io.StringIO()
        csv.writer(buf, delimiter=self.delimiter, lineterminator="").writerow([value])
        return buf.getvalue()

    def _finding_spans(self, pairs: Iterable[tuple[Any, Any]]) -> list[Span]:
        spans: list[Span] = []
        for finding, decision in pairs:
            span = finding.location.span
            if span is not None and span[0] < MAX_RECORD_CHARS:
                end = min(span[1], MAX_RECORD_CHARS)
                spans.append((span[0], end, (_label(finding, decision),)))
        return spans

    def _decision(self, finding: Any, decision: Any) -> dict[str, Any]:
        path = finding.location.field_path
        return {
            "category": finding.category,
            "detector": finding.detector,
            "band": finding.band,
            "action": str(decision.action),
            "rule_id": decision.rule_id,
            "reason_code": str(decision.reason_code),
            "field_path": ("<redacted>" if self.redact else safe_field_path(path)) if path else "",
        }


def _label(finding: Any, decision: Any) -> str:
    rule = decision.rule_id or "engine default"
    return f"{finding.category} · {decision.action} · {rule} · {decision.reason_code}"


def _labels(pairs: Iterable[tuple[Any, Any]], *, allow: bool) -> tuple[str, ...]:
    """Sorted labels of the decisions that keep (``allow``) or change a value."""
    return tuple(sorted({_label(f, d) for f, d in pairs if (d.action == Action.ALLOW) == allow}))


def _clip(text: str, fields: Fields) -> tuple[str, Fields]:
    if len(text) <= MAX_RECORD_CHARS:
        return text, fields
    kept = {
        k: (s, min(e, MAX_RECORD_CHARS)) for k, (s, e) in fields.items() if s < MAX_RECORD_CHARS
    }
    return text[:MAX_RECORD_CHARS], kept


def _dump_json(node: Any, pointer: str, parts: list[str], fields: Fields, pos: list[int]) -> None:
    """Write ``node`` like ``json.dumps(ensure_ascii=False)`` and note where each leaf lands."""

    def emit(text: str) -> None:
        parts.append(text)
        pos[0] += len(text)

    if isinstance(node, dict):
        emit("{")
        for n, (key, value) in enumerate(node.items()):
            emit((", " if n else "") + json.dumps(key, ensure_ascii=False) + ": ")
            _dump_json(value, f"{pointer}/{pointer_escape(key)}", parts, fields, pos)
        emit("}")
    elif isinstance(node, list):
        emit("[")
        for n, value in enumerate(node):
            if n:
                emit(", ")
            _dump_json(value, f"{pointer}/{n}", parts, fields, pos)
        emit("]")
    else:
        start = pos[0]
        emit(json.dumps(node, ensure_ascii=False))
        fields[pointer] = (start, pos[0])


def _tokens(text: str) -> tuple[list[str], list[int]]:
    tokens = _TOKEN_RE.findall(text)
    offsets = [0]
    for token in tokens:
        offsets.append(offsets[-1] + len(token))
    return tokens, offsets


def _diff_segments(
    before: str,
    after: str,
    spans: list[Span],
    kept: list[Span],
    record_labels: tuple[str, ...],
) -> tuple[list[Segment], list[Segment]]:
    """Changed ranges in the output and the matching ranges in the input, per token.

    Values kept by an allow rule are marked ``kept`` where they sit in unchanged text.
    """
    a, a_off = _tokens(before)
    b, b_off = _tokens(after)
    opcodes = difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
    blocks = _merge(opcodes, a)
    out: list[Segment] = []
    inp: list[Segment] = []
    for tag, i1, i2, j1, _ in opcodes:
        if tag != "equal":
            continue
        lo, hi, shift = a_off[i1], a_off[i2], b_off[j1] - a_off[i1]
        for s, e, labels in kept:
            if lo <= s and e <= hi:
                out.append(Segment(s + shift, e + shift, "kept", labels))
                inp.append(Segment(s, e, "kept", labels))
    for i1, i2, j1, j2 in blocks:
        start, end = a_off[i1], a_off[i2]
        labels = tuple(sorted({lab for s, e, ls in spans if s < end and start < e for lab in ls}))
        labels = labels or record_labels
        kind = "change" if j2 > j1 else "delete"
        # Removing text (a date cut to its year) is deliberate; only a replacement can be partial.
        partial = kind == "change" and _looks_partial(before, start, end, labels)
        out.append(Segment(b_off[j1], b_off[j2], kind, labels, partial))
        if end > start:
            inp.append(Segment(start, end, "change", labels, partial))
    return out, inp


def _merge(
    opcodes: Iterable[tuple[str, int, int, int, int]], a: list[str]
) -> list[tuple[int, int, int, int]]:
    """Join changed blocks split by one or two punctuation or space tokens ("." in an email)."""
    blocks: list[tuple[int, int, int, int]] = []
    pending: tuple[int, int, int, int] | None = None
    for tag, i1, i2, j1, j2 in opcodes:
        if tag != "equal":
            if pending is not None and blocks and blocks[-1][1] == pending[0]:
                prev = blocks.pop()
                blocks.append((prev[0], i2, prev[2], j2))
            else:
                blocks.append((i1, i2, j1, j2))
            pending = None
            continue
        short_punct = i2 - i1 <= 2 and all(_is_punct(t) for t in a[i1:i2])
        pending = (i1, i2, j1, j2) if short_punct and blocks and blocks[-1][1] == i1 else None
    return blocks


def _is_punct(piece: str) -> bool:
    return piece.isspace() or (len(piece) == 1 and not (piece.isalnum() or piece == "_"))


def _looks_partial(text: str, start: int, end: int, labels: tuple[str, ...]) -> bool:
    """A heuristic: a replaced name or address sits right next to a capitalised word that stayed.

    Changes are compared per word, so a range never starts or ends inside a word.
    """
    if start == end:
        return False
    if not any(label.split(" · ", 1)[0] in _NAME_LIKE for label in labels):
        return False
    left = re.search(r"(\w+) $", text[max(0, start - 40) : start])
    right = re.match(r" (\w+)", text[end : end + 40])
    return any(m is not None and _is_title_word(m.group(1)) for m in (left, right))


def _is_title_word(word: str) -> bool:
    return len(word) > 1 and word[0].isupper() and word[1:].islower()


__all__ = ["ReviewData", "ReviewOptions", "ReviewRecord", "Segment", "build_review", "review_file"]
