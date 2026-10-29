"""Residual scanning of (sanitized) output. Read-only; never mutates the scanned file.

Each residual finding is classified:

* ``allowed`` — the policy decision for it is ``allow``;
* ``recognized_output`` — the text is a CipherGate marker, a pseudonym token, a configured
  replacement constant, or already has the shape of the configured generalization;
* ``unverifiable`` — the policy would date-shift it (a shifted date looks like any date);
* ``unexpected`` — everything else. Unexpected residuals in ``settings.rescan.fail_on_categories``
  (default: high-risk categories) are *gating*; in strict mode they fail the rescan.

A clean rescan is a quality gate, not proof that no sensitive data remains.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ciphergate.constants import Action
from ciphergate.detectors.base import is_ciphergate_token
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import GeneralizeParams
from ciphergate.models.report import RescanSummary
from ciphergate.pipeline.inspector import Analyzer, Evaluated, RunSetup
from ciphergate.pipeline.planner import finding_item
from ciphergate.readers import STRUCTURED_LINE_FORMATS
from ciphergate.readers.line_structure import SpanCodec, token_at
from ciphergate.transforms.generalize import matches_generalized_shape


def rescan_path(setup: RunSetup, path: Path, *, strict: bool) -> RescanSummary:
    reader = setup.new_reader(path)
    analyzer = Analyzer(setup, reader)
    policy = setup.policy
    fail_set = policy.rescan_fail_categories(untrusted=setup.ctx.is_untrusted)
    counts: Counter[str] = Counter(
        {"allowed": 0, "recognized_output": 0, "unverifiable": 0, "unexpected": 0}
    )
    unexpected: Counter[str] = Counter()
    gating: Counter[str] = Counter()
    items: list[dict[str, Any]] = []
    truncated = False
    sensitive_columns: set[int] = set()

    def analyzed() -> Iterator[tuple[ScanItem, Evaluated]]:
        yield from analyzer.analyze_header()
        for record in reader.records():
            if record.malformed:
                counts["malformed_records"] += 1
                continue
            yield from analyzer.analyze(record)

    for item, evaluated in analyzed():
        if item.in_key and item.column_index is not None and evaluated:
            sensitive_columns.add(item.column_index)
        redact = item.in_key or item.column_index in sensitive_columns
        text = item.text if item.text is not None else ""
        # Structured line values are escaped in the line: compare what the transform wrote.
        structure = STRUCTURED_LINE_FORMATS.get(setup.fmt)
        codec = (
            SpanCodec(structure, structure.parse(text, setup.runtime.max_json_depth))
            if structure is not None
            else None
        )
        for finding, decision in evaluated:
            span = finding.location.span
            piece = text[span[0] : span[1]] if span else text
            whole: str | None = None  # the decoded value of the field the finding sits in
            if codec is not None and span is not None:
                decoded = codec.decode(span[0], span[1], piece)
                piece = decoded if isinstance(decoded, str) else piece
                owner = token_at(codec.tokens, span[0], span[1])
                if owner is not None and owner.kind != "key" and isinstance(owner.value, str):
                    whole = owner.value
            if decision.action == Action.ALLOW:
                cls = "allowed"
            elif (
                is_ciphergate_token(piece)
                or piece in policy.replacement_values
                # A pattern can match part of an escaped marker (e.g. "[REDACTED:x\]" in a
                # syslog SD value); a field that holds exactly our output is recognised.
                or (whole is not None and is_ciphergate_token(whole))
                or (whole is not None and whole in policy.replacement_values)
                or (
                    decision.action == Action.GENERALIZE
                    and isinstance(decision.params, GeneralizeParams)
                    and matches_generalized_shape(piece, decision.params)
                )
            ):
                cls = "recognized_output"
            elif decision.action == Action.DATE_SHIFT:
                cls = "unverifiable"
            else:
                cls = "unexpected"
            counts[cls] += 1
            if cls != "unexpected":
                continue
            unexpected[finding.category] += 1
            is_gating = finding.category in fail_set
            if is_gating:
                gating[finding.category] += 1
            if len(items) < setup.runtime.max_report_items:
                entry = finding_item(finding, decision, redact_path=redact)
                entry["residual"] = "gating" if is_gating else "non_gating"
                items.append(entry)
            else:
                truncated = True
    return RescanSummary(
        strict=strict,
        failed=strict and sum(gating.values()) > 0,
        fail_on_categories=sorted(fail_set),
        counts=dict(counts),
        unexpected_by_category=dict(sorted(unexpected.items())),
        gating_by_category=dict(sorted(gating.items())),
        items=items,
        items_truncated=truncated,
    )
