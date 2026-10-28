"""Report serialization and atomic report-file writing."""

from __future__ import annotations

import json
from pathlib import Path

from ciphergate.models.report import RunReport
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.reporting.terminal import render_summary


def report_to_json(report: RunReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def render_report(report: RunReport, report_format: str) -> str:
    if report_format == "json":
        return report_to_json(report)
    return render_summary(report, verbose=True)


def write_report_file(report: RunReport, path: Path, report_format: str, *, force: bool) -> None:
    with AtomicOutput(path, force=force) as out:
        out.stream.write(render_report(report, report_format))
        out.publish()
