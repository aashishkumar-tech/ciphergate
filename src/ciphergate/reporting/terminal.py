"""Plain-text summaries for terminals and CI logs (no colour, no values, control chars escaped)."""

from __future__ import annotations

from typing import Any

from ciphergate.constants import DISCLAIMER, RESCAN_LIMIT
from ciphergate.models.report import RunReport
from ciphergate.pipeline.batch import BatchReport
from ciphergate.reporting.safe_text import escape_control

SUMMARY_ITEMS = 15


def _counts(data: dict[str, int]) -> str:
    return ", ".join(f"{escape_control(k)}={v}" for k, v in data.items()) or "-"


def _location(loc: dict[str, Any]) -> str:
    parts = []
    if loc.get("line") is not None:
        parts.append(f"line {loc['line']}")
    else:
        parts.append(f"record {loc.get('record')}")
    if loc.get("field_path"):
        parts.append(f"field {escape_control(str(loc['field_path']))}")
    if loc.get("span"):
        parts.append(f"chars {loc['span'][0]}-{loc['span'][1]}")
    if loc.get("in_key"):
        parts.append("(key)")
    return ", ".join(parts)


def _rescan_verdict(rescan: dict[str, Any]) -> str:
    if rescan["failed"]:
        return "FAILED, gating findings remain"
    if rescan["gating_by_category"]:
        return "NOT ENFORCED, gating findings remain but strict is off"
    return "no gating findings"


def _headline(d: dict[str, Any]) -> str:
    # Never print a bare PASSED for rescan: it reads as "this output is safe".
    if d["command"] == "rescan" and d["rescan"] and not d["rescan"]["failed"]:
        return _rescan_verdict(d["rescan"]).split(",")[0].upper()
    return str(d["status"]).upper()


def render_summary(report: RunReport, *, verbose: bool = False) -> str:
    d = report.to_dict()
    lines = [f"CipherGate {d['command']}: {_headline(d)} (exit {d['exit_code']})"]
    inp = d["input"]
    lines.append(
        f"  input:   {escape_control(str(inp['path']))} [{inp['format']}, "
        f"{inp['records']} record(s), {inp['bytes']} bytes]"
    )
    pol = d["policy"]
    lines.append(
        f"  policy:  {escape_control(pol['name'])} v{pol['policy_version']} "
        f"({pol['digest'][:19]}...)"
    )
    ctx = ", ".join(f"{k}={v['value'] or '-'}[{v['source']}]" for k, v in d["context"].items())
    lines.append(f"  context: {ctx}")
    s = d["summary"]
    lines.append(
        f"  findings: {s.get('findings_total', 0)}  blocked: {s.get('blocked', 0)}  "
        f"review: {s.get('review_required', 0)}"
    )
    if s.get("findings_total"):
        lines.append(f"    by category: {_counts(s['by_category'])}")
        lines.append(f"    by action:   {_counts(s['by_action'])}")
        lines.append(f"    by reason:   {_counts(s['by_reason_code'])}")
    if s.get("dropped_columns"):
        lines.append(f"    dropped columns: {', '.join(s['dropped_columns'])}")
    for gate in d["gates"]:
        lines.append(f"  gate [{gate['severity']}] {gate['reason_code']}: {gate['message']}")
    for approval in d["transfer_approvals"]:
        lines.append(f"  transfer approval used: {escape_control(approval)}")
    for key in d["keys"]:
        lines.append(f"  key {key['key_env']}: {key['status']}")
    for err in d["parse_errors"][:10]:
        lines.append(f"  parse error at line {err['line']}: {err['code']}")
    items = d["items"]
    important = [i for i in items if i["decision"]["action"] in ("block", "review")]
    shown = items if verbose else (important or items)[:SUMMARY_ITEMS]
    if shown:
        lines.append("  items:" if verbose else "  items (first shown; use --verbose or --report):")
    for item in shown:
        dec = item["decision"]
        rule = dec.get("rule_id") or "-"
        lines.append(
            f"    {_location(item['location'])}: {item['category']} "
            f"({item['band']}, {item['detector']}) -> {dec['action']} "
            f"[{dec['reason_code']}; rule {escape_control(rule)}]"
        )
    if d["items_truncated"]:
        lines.append("  (item list truncated; counts above are complete)")
    if d["changes"]:
        c = d["changes"]
        lines.append(
            f"  changes: records written={c.get('records_written')}, dropped="
            f"{c.get('records_dropped')}, values changed={c.get('values_changed')}, "
            f"type changes={c.get('type_changes')}"
        )
    if d["rescan"]:
        r = d["rescan"]
        lines.append(
            f"  rescan: {_rescan_verdict(r)} (strict={r['strict']}) "
            f"residuals: {_counts(r['counts'])}"
        )
        if r["gating_by_category"]:
            lines.append(f"    gating residuals: {_counts(r['gating_by_category'])}")
        lines.append(f"  rescan limit: {RESCAN_LIMIT}")
    out = d["output"]
    if out:
        if out.get("written"):
            lines.append(f"  output:  written to {escape_control(str(out.get('path')))}")
        elif out.get("withheld_reason"):
            lines.append(f"  output:  not written ({out['withheld_reason']})")
    for warning in d["warnings"]:
        lines.append(f"  warning: {escape_control(warning)}")
    lines.append(f"  note: {DISCLAIMER}")
    return "\n".join(lines) + "\n"


def render_batch_summary(report: BatchReport, *, verbose: bool = False) -> str:
    d = report.to_dict()
    s = d["summary"]
    lines = [
        f"CipherGate {d['command']} (directory): {d['status'].upper()} (exit {d['exit_code']})"
    ]
    recursive = " (recursive)" if d["input"]["recursive"] else ""
    lines.append(f"  input:   {escape_control(str(d['input']['path']))}{recursive}")
    if d["policy"]:
        lines.append(f"  policy:  {escape_control(d['policy']['name'])}")
    lines.append(
        f"  files: {s['files_total']}  ok: {s['files_ok']}  failed: {s['files_failed']}  "
        f"skipped: {s['files_skipped']}"
    )
    lines.append(
        f"  findings: {s['findings_total']}  blocked: {s['blocked']}  "
        f"review: {s['review_required']}"
    )
    for entry in d["files"]:
        detail = entry["status"]
        if "error" in entry:
            detail = f"error[{entry['error']['code']}]"
        elif verbose:
            detail += f", findings={entry['report']['summary'].get('findings_total', 0)}"
        lines.append(f"    {escape_control(entry['path'])}: {detail} (exit {entry['exit_code']})")
    for skip in d["skipped"]:
        lines.append(f"    skipped {escape_control(skip['path'])}: {skip['reason']}")
    out = d["output"]
    if out:
        if out.get("written"):
            lines.append(f"  output:  directory written to {escape_control(str(out['path']))}")
        else:
            lines.append(f"  output:  not written ({out.get('withheld_reason')})")
    for warning in d["warnings"]:
        lines.append(f"  warning: {escape_control(warning)}")
    lines.append("  note: per-file details are in the JSON report (--report).")
    lines.append(f"  note: {DISCLAIMER}")
    return "\n".join(lines) + "\n"
