"""Privacy-safe run report (schema ``ciphergate.report/v1``).

A report contains counts, safe structural locations, rule IDs and reason codes. It never contains
raw values, snippets, keys, key derivations or value fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ciphergate.constants import DISCLAIMER, REPORT_SCHEMA, ExitCode


class RunStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    REVIEW_REQUIRED = "review_required"
    CONFIGURATION_REQUIRED = "configuration_required"
    SANITIZED = "sanitized"
    RESCAN_FAILED = "rescan_failed"
    PASSED = "passed"


STATUS_EXIT_CODES: dict[RunStatus, ExitCode] = {
    RunStatus.READY: ExitCode.OK,
    RunStatus.SANITIZED: ExitCode.OK,
    RunStatus.PASSED: ExitCode.OK,
    RunStatus.BLOCKED: ExitCode.BLOCKED,
    RunStatus.REVIEW_REQUIRED: ExitCode.BLOCKED,
    RunStatus.CONFIGURATION_REQUIRED: ExitCode.KEY_OR_TRANSFORM_CONFIG,
    RunStatus.RESCAN_FAILED: ExitCode.RESCAN_FAILED,
}


@dataclass
class RescanSummary:
    strict: bool
    failed: bool
    fail_on_categories: list[str]
    counts: dict[str, int]
    unexpected_by_category: dict[str, int]
    gating_by_category: dict[str, int]
    items: list[dict[str, Any]]
    items_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict": self.strict,
            "failed": self.failed,
            "fail_on_categories": self.fail_on_categories,
            "counts": self.counts,
            "unexpected_by_category": self.unexpected_by_category,
            "gating_by_category": self.gating_by_category,
            "items": self.items,
            "items_truncated": self.items_truncated,
        }


@dataclass
class RunReport:
    command: str
    status: RunStatus
    run_id: str
    timestamp: str
    version: str
    input: dict[str, Any]
    policy: dict[str, Any]
    context: dict[str, Any]
    gates: list[dict[str, Any]] = field(default_factory=list)
    transfer_approvals: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    items: list[dict[str, Any]] = field(default_factory=list)
    items_truncated: bool = False
    keys: list[dict[str, str]] = field(default_factory=list)
    changes: dict[str, Any] = field(default_factory=dict)
    parse_errors: list[dict[str, Any]] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)
    rescan: RescanSummary | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return int(STATUS_EXIT_CODES[self.status])

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "command": self.command,
            "status": str(self.status),
            "exit_code": self.exit_code,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "ciphergate_version": self.version,
            "input": self.input,
            "policy": self.policy,
            "context": self.context,
            "gates": self.gates,
            "transfer_approvals": self.transfer_approvals,
            "summary": self.summary,
            "items": self.items,
            "items_truncated": self.items_truncated,
            "keys": self.keys,
            "changes": self.changes,
            "parse_errors": self.parse_errors,
            "output": self.output,
            "rescan": self.rescan.to_dict() if self.rescan else None,
            "warnings": self.warnings,
            "disclaimer": DISCLAIMER,
        }
