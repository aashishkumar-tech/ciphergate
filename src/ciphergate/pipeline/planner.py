"""Pass one: analyse the whole input and aggregate a privacy-safe plan.

The plan is the single source of truth for whether apply mode may run. ``block`` or ``review``
decisions, run-level gate issues, or unavailable keys all prevent output publication.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ciphergate.constants import Action, InputFormat
from ciphergate.errors import InputLimitError
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.models.policy import DateShiftParams, PseudonymizeParams
from ciphergate.models.report import RunStatus
from ciphergate.pipeline.inspector import Analyzer, RunSetup
from ciphergate.pipeline.paths import file_digest
from ciphergate.policy.context import GateIssue, evaluate_gates
from ciphergate.policy.engine import Decision
from ciphergate.readers.base import ReadStats
from ciphergate.reporting.safe_text import safe_field_path
from ciphergate.transforms.keys import KeyProvider, KeyStatus

REDACTED_KEY = "<redacted-key>"


def redact_key_path(path: str) -> str:
    """Hide the last segment of a path whose key/header itself produced a finding."""
    if path.startswith("/"):
        head = path.rsplit("/", 1)[0]
        return safe_field_path(head) + "/" + REDACTED_KEY if head else "/" + REDACTED_KEY
    return REDACTED_KEY


def finding_item(
    finding: Finding, decision: Decision, *, redact_path: bool = False
) -> dict[str, Any]:
    loc = finding.location.to_dict()
    if "field_path" in loc:
        path = loc["field_path"]
        loc["field_path"] = redact_key_path(path) if redact_path else safe_field_path(path)
    return {
        "category": finding.category,
        "detector": finding.detector,
        "confidence": finding.confidence,
        "band": finding.band,
        "evidence": list(finding.evidence),
        "value_type": finding.value_type,
        "location": loc,
        "decision": decision.to_dict(),
    }


@dataclass
class PlanAccumulator:
    max_items: int
    max_findings: int
    total: int = 0
    by_category: Counter[str] = field(default_factory=Counter)
    by_detector: Counter[str] = field(default_factory=Counter)
    by_action: Counter[str] = field(default_factory=Counter)
    by_band: Counter[str] = field(default_factory=Counter)
    by_reason: Counter[str] = field(default_factory=Counter)
    by_rule: Counter[str] = field(default_factory=Counter)
    blocked: int = 0
    review: int = 0
    items: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    dropped_columns: dict[int, str] = field(default_factory=dict)
    records_to_drop: set[int] = field(default_factory=set)
    malformed_records: int = 0
    key_envs: set[str] = field(default_factory=set)
    # CSV columns whose header cell produced a finding: their label is never reported.
    sensitive_columns: set[int] = field(default_factory=set)

    def add(self, item: ScanItem, finding: Finding, decision: Decision) -> None:
        self.total += 1
        if self.total > self.max_findings:
            raise InputLimitError(
                f"more than {self.max_findings} findings (max_findings)", code="too_many_findings"
            )
        if item.in_key and item.column_index is not None:
            self.sensitive_columns.add(item.column_index)
        redact = item.in_key or item.column_index in self.sensitive_columns
        action = str(decision.action)
        self.by_category[finding.category] += 1
        self.by_detector[finding.detector] += 1
        self.by_action[action] += 1
        self.by_band[finding.band] += 1
        self.by_reason[str(decision.reason_code)] += 1
        if decision.rule_id:
            self.by_rule[decision.rule_id] += 1
        if decision.action == Action.BLOCK:
            self.blocked += 1
        elif decision.action == Action.REVIEW:
            self.review += 1
        elif decision.action == Action.DROP_FIELD and item.column_index is not None:
            self.dropped_columns[item.column_index] = (
                REDACTED_KEY if redact else safe_field_path(item.field_path)
            )
        elif decision.action == Action.DROP_RECORD:
            self.records_to_drop.add(item.record_index)
        if isinstance(decision.params, PseudonymizeParams | DateShiftParams):
            self.key_envs.add(decision.params.key_env)
        important = decision.action in (Action.BLOCK, Action.REVIEW)
        if len(self.items) < self.max_items:
            self.items.append(finding_item(finding, decision, redact_path=redact))
        elif important:
            # Make sure blocking items are visible even when the item list is full.
            self.items.append(finding_item(finding, decision, redact_path=redact))
            self.truncated = True
        else:
            self.truncated = True

    def summary(self) -> dict[str, Any]:
        def ordered(counter: Counter[str]) -> dict[str, int]:
            return dict(sorted(counter.items()))

        return {
            "findings_total": self.total,
            "by_category": ordered(self.by_category),
            "by_detector": ordered(self.by_detector),
            "by_action": ordered(self.by_action),
            "by_confidence_band": ordered(self.by_band),
            "by_reason_code": ordered(self.by_reason),
            "by_rule": ordered(self.by_rule),
            "blocked": self.blocked,
            "review_required": self.review,
            "records_to_drop": len(self.records_to_drop),
            "malformed_records_dropped": self.malformed_records,
        }


@dataclass
class Analysis:
    setup: RunSetup
    stats: ReadStats
    acc: PlanAccumulator
    gates: list[GateIssue]
    approvals: list[str]
    digest: str
    key_statuses: dict[str, KeyStatus]
    top_level_array: bool

    @property
    def status(self) -> RunStatus:
        if self.acc.blocked or any(g.severity == "block" for g in self.gates):
            return RunStatus.BLOCKED
        if self.acc.review or any(g.severity == "review" for g in self.gates):
            return RunStatus.REVIEW_REQUIRED
        if any(s != KeyStatus.AVAILABLE for s in self.key_statuses.values()):
            return RunStatus.CONFIGURATION_REQUIRED
        return RunStatus.READY


def analyze_file(setup: RunSetup, keys: KeyProvider) -> Analysis:
    gates, approvals = evaluate_gates(setup.policy, setup.ctx, setup.fmt)
    digest = file_digest(setup.input_path)
    reader = setup.new_reader()
    analyzer = Analyzer(setup, reader)
    acc = PlanAccumulator(
        max_items=setup.runtime.max_report_items, max_findings=setup.runtime.max_findings
    )
    for item, evaluated in analyzer.analyze_header():
        for finding, decision in evaluated:
            acc.add(item, finding, decision)
    for record in reader.records():
        if record.malformed:
            acc.malformed_records += 1
            continue
        for item, evaluated in analyzer.analyze(record):
            for finding, decision in evaluated:
                acc.add(item, finding, decision)
    key_statuses = {name: keys.status(name) for name in sorted(acc.key_envs)}
    return Analysis(
        setup=setup,
        stats=reader.stats,
        acc=acc,
        gates=gates,
        approvals=approvals,
        digest=digest,
        key_statuses=key_statuses,
        top_level_array=bool(getattr(reader, "top_level_array", False)),
    )


def is_structured(fmt: InputFormat) -> bool:
    return fmt != InputFormat.TEXT
