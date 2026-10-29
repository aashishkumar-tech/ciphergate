"""Builds ``RunReport`` objects from analysis results (privacy-safe metadata only)."""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Any

from ciphergate import __version__
from ciphergate.constants import PSEUDONYM_VERSION
from ciphergate.models.report import RescanSummary, RunReport, RunStatus
from ciphergate.pipeline.paths import display_path
from ciphergate.pipeline.planner import Analysis


def new_run_id() -> str:
    return secrets.token_hex(8)


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(
    command: str,
    analysis: Analysis,
    *,
    status: RunStatus | None = None,
    output: dict[str, Any] | None = None,
    changes: dict[str, Any] | None = None,
    rescan: RescanSummary | None = None,
    extra_warnings: list[str] | None = None,
) -> RunReport:
    setup = analysis.setup
    policy = setup.policy
    path_mode = setup.runtime.path_display
    stats = analysis.stats
    acc = analysis.acc
    warnings = list(policy.warnings) + list(extra_warnings or [])
    if stats.blank_lines:
        action = "preserved" if policy.document.settings.preserve_blank_lines else "removed"
        warnings.append(f"{stats.blank_lines} blank line(s) {action} in output")
    summary = acc.summary()
    summary["dropped_columns"] = [acc.dropped_columns[i] for i in sorted(acc.dropped_columns)]
    return RunReport(
        command=command,
        status=status or analysis.status,
        run_id=new_run_id(),
        timestamp=utc_now(),
        version=__version__,
        input={
            "path": display_path(setup.input_path, path_mode),
            "format": str(setup.fmt),
            "bytes": stats.bytes_read,
            "records": stats.records,
            "blank_lines": stats.blank_lines,
        },
        policy={
            "name": policy.name,
            "policy_version": policy.version,
            "digest": policy.digest,
            "source": policy.source_name if path_mode != "redacted" else None,
            "strict": policy.document.settings.strict,
        },
        context=setup.ctx.to_report(),
        gates=[g.to_dict() for g in analysis.gates],
        transfer_approvals=list(analysis.approvals),
        summary=summary,
        items=acc.items,
        items_truncated=acc.truncated,
        keys=[
            {
                "key_env": name,
                "source": analysis.key_sources.get(name, "env"),
                "status": str(state),
                "transform_version": PSEUDONYM_VERSION,
            }
            for name, state in analysis.key_statuses.items()
        ],
        changes=changes or {},
        parse_errors=[{"line": line, "code": code} for line, code in stats.parse_errors[:100]],
        output=output or {"written": False},
        rescan=rescan,
        warnings=warnings,
    )
