"""Render a ``ReviewData`` as one self-contained HTML page.

No scripts, fonts, images or links to other sites: a Content-Security-Policy meta tag blocks every
load, so opening the page makes no network request. All text is HTML-escaped and control or
invisible characters are shown as escapes. Metrics come from the privacy-safe run report; record
text comes from the would-be output, and from the input only when the user asked for it.
"""

from __future__ import annotations

import html
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ciphergate.constants import DISCLAIMER, RESCAN_LIMIT
from ciphergate.reporting.safe_text import escape_invisible

if TYPE_CHECKING:
    from ciphergate.pipeline.review import ReviewData, ReviewRecord, Segment

TRANSFORM_ACTIONS = (
    "redact",
    "replace",
    "pseudonymize",
    "generalize",
    "date_shift",
    "drop_field",
    "drop_record",
)
_MERGEABLE = frozenset({"finding", "kept"})
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)

_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#5f5f5a;--line:#dedcd6;
--ok:#1f7a4d;--okbg:#e3f3ea;--warn:#8a5a00;--warnbg:#fdf1d8;--bad:#a1271b;--badbg:#fbe4e0;
--chg:#d7ecff;--chgink:#0b3d66;--in:#ffe1dc;--inink:#6b1309;--bar:#3b6ea8}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#20201e;--ink:#ecebe6;
--muted:#a5a49c;--line:#3a3935;--ok:#6fd19c;--okbg:#17352a;--warn:#f0c46a;--warnbg:#3b2f14;
--bad:#ff9a8c;--badbg:#45201b;--chg:#173a5c;--chgink:#cfe6ff;--in:#4a1f19;--inink:#ffd6cf;
--bar:#7aa7dc}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 10px}
h3{font-size:15px;margin:0 0 8px}
.muted{color:var(--muted)}.small{font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;
margin:12px 0}
.banner{border-radius:10px;padding:12px 16px;margin:12px 0;border:1px solid var(--line)}
.banner.bad{background:var(--badbg);color:var(--bad);font-weight:600}
.banner.warn{background:var(--warnbg);color:var(--warn)}
.banner.ok{background:var(--okbg);color:var(--ok)}
.verdict{font-size:17px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.tile .n{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.tile .l{font-size:13px;color:var(--muted)}
.tile.bad .n{color:var(--bad)}.tile.ok .n{color:var(--ok)}.tile.warn .n{color:var(--warn)}
.stack{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--line);
margin:10px 0 6px}
.stack span{display:block;height:100%}
.s-t{background:var(--ok)}.s-a{background:var(--bar)}.s-r{background:var(--warn)}
.s-b{background:var(--bad)}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:13px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.meter{background:var(--line);border-radius:3px;height:6px;min-width:60px}
.meter span{display:block;height:6px;border-radius:3px;background:var(--bar)}
pre{margin:6px 0;padding:10px;background:var(--bg);border:1px solid var(--line);
border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,
SFMono-Regular,Consolas,monospace}
mark{border-radius:3px;padding:0 1px}
mark.chg{background:var(--chg);color:var(--chgink)}
mark.in{background:var(--in);color:var(--inink)}
mark.kept{background:transparent;color:inherit;border-bottom:2px dotted var(--bar);
border-radius:0}
mark.partial{outline:2px dashed var(--warn);outline-offset:1px}
.del{color:var(--bad);font-weight:700}
.badge{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;
border:1px solid var(--line);margin-right:6px;color:var(--muted)}
.badge.bad{color:var(--bad);border-color:var(--bad)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.badge.ok{color:var(--ok);border-color:var(--ok)}
.label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
details>summary{cursor:pointer}
ul{margin:6px 0;padding-left:20px}
code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace}
"""


def _e(value: Any) -> str:
    return html.escape(escape_invisible(str(value)), quote=True)


def _pct(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def render_review_page(data: ReviewData) -> str:
    d = data.report.to_dict()
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>CipherGate review</title>",
        f"<style>{_CSS}</style></head><body><main>",
        _header(d),
        _banners(data),
        _verdict(d),
        _metrics(d, data),
        _breakdowns(d, data),
        _rescan(d),
        _gates_keys(d),
        _records(data),
        _footer(),
        "</main></body></html>\n",
    ]
    return "\n".join(p for p in parts if p)


# --------------------------------------------------------------------------- sections


def _header(d: dict[str, Any]) -> str:
    ctx = d["context"]
    context_bits = [
        f"{k.replace('_', ' ')}: <b>{_e(ctx[k]['value'])}</b> ({_e(ctx[k]['source'])})"
        for k in ("environment", "target_environment", "destination", "use_case", "domain_profile")
        if ctx.get(k, {}).get("value")
    ]
    inp = d["input"]
    return (
        "<header><h1>CipherGate review</h1>"
        f'<div class="muted">input <b>{_e(inp.get("path") or "")}</b> · format {_e(inp["format"])}'
        f" · {inp['records']} records · {inp['bytes']} bytes</div>"
        f'<div class="muted">policy <b>{_e(d["policy"]["name"])}</b> · '
        + " · ".join(context_bits)
        + f'</div><div class="muted small">generated {_e(d["timestamp"])} by CipherGate '
        f"{_e(d['ciphergate_version'])} · run {_e(d['run_id'])}</div></header>"
    )


def _banners(data: ReviewData) -> str:
    out = []
    if data.include_input:
        out.append(
            '<div class="banner bad">This page contains RAW INPUT (made with --include-input). '
            "Treat it like the original file: do not share, upload or commit it, and delete it "
            "when you are done.</div>"
        )
    if data.has_output:
        out.append(
            '<div class="banner warn">This page shows the would-be sanitized output. Treat it '
            "like the sanitized file: detectors can miss values, so read it before sharing. "
            "No sanitized file was written.</div>"
        )
    else:
        out.append(
            '<div class="banner warn">No output preview: sanitize would not write an output for '
            "this run. The decisions below show why.</div>"
        )
    return "\n".join(out)


def _verdict(d: dict[str, Any]) -> str:
    s = d["summary"]
    total = s["findings_total"]
    transformed = sum(s["by_action"].get(a, 0) for a in TRANSFORM_ACTIONS)
    status = d["status"]
    if status == "ready":
        cls, text = (
            "ok",
            (
                f"Ready: every finding has a decision. {transformed} of {total} findings "
                f"({_pct(transformed, total)}) would be transformed."
            ),
        )
        if d.get("rescan"):
            text += " The rescan found no gating findings in the would-be output."
    elif status == "rescan_failed":
        cls, text = (
            "bad",
            (
                "Not ready: the rescan found gating findings in the would-be output. "
                "sanitize would withhold it."
            ),
        )
    elif status == "blocked":
        cls, text = (
            "bad",
            (
                f"Blocked: {s['blocked']} finding(s) are not permitted for this destination. "
                "sanitize would write no output."
            ),
        )
    elif status == "review_required":
        cls, text = (
            "warn",
            (
                f"Needs review: {s['review_required']} finding(s) need a human decision. "
                "sanitize would write no output."
            ),
        )
    else:
        cls, text = "warn", "Needs configuration: a required key is missing or invalid."
    if any(g.get("severity") in ("block", "review") for g in d["gates"]) and status != "ready":
        text += " Context gates also apply (see below)."
    steps = "".join(f"<li>{_e(step['message'])}</li>" for step in d.get("next_steps", []))
    return (
        f'<div class="banner {cls}"><div class="verdict">{_e(text)}</div>'
        f'<div class="small">status {_e(status)} · exit code {d["exit_code"]} · '
        "these numbers cover only what the enabled detectors found.</div>"
        + (f'<div class="small"><b>Next steps</b><ul>{steps}</ul></div>' if steps else "")
        + "</div>"
    )


def _tile(label: str, value: str, cls: str = "", note: str = "") -> str:
    extra = f'<div class="l">{_e(note)}</div>' if note else ""
    return (
        f'<div class="tile {cls}"><div class="n">{_e(value)}</div>'
        f'<div class="l">{_e(label)}</div>{extra}</div>'
    )


def _metrics(d: dict[str, Any], data: ReviewData) -> str:
    s = d["summary"]
    by_action = s["by_action"]
    total = s["findings_total"]
    transformed = sum(by_action.get(a, 0) for a in TRANSFORM_ACTIONS)
    allowed = by_action.get("allow", 0)
    review = by_action.get("review", 0)
    blocked = by_action.get("block", 0)
    ch = d.get("changes") or {}
    rescan = d.get("rescan") or {}
    counts = rescan.get("counts", {})
    gating = sum(rescan.get("gating_by_category", {}).values())
    records = d["input"]["records"]
    # Without an output preview nothing ran: these are the planned transforms, not done ones.
    done_label = "transformed" if data.has_output else "planned transforms (not run)"
    done_cls = "ok" if data.has_output and total else ""
    tiles = [
        _tile("findings", str(total)),
        _tile(done_label, str(transformed), done_cls, _pct(transformed, total)),
        _tile("kept (allow rule)", str(allowed), "", _pct(allowed, total)),
        _tile("need review", str(review), "warn" if review else ""),
        _tile("blocked", str(blocked), "bad" if blocked else ""),
        _tile(
            "records with findings",
            f"{data.records_with_findings}/{records}",
            "",
            _pct(data.records_with_findings, records),
        ),
    ]
    if data.has_output:
        tiles += [
            _tile("values changed", str(ch.get("values_changed", 0))),
            _tile("records written", str(ch.get("records_written", 0))),
            _tile("records dropped", str(ch.get("records_dropped", 0))),
            _tile("type changes", str(ch.get("type_changes", 0))),
        ]
    if rescan:
        tiles += [
            _tile("rescan: gating", str(gating), "bad" if gating else "ok"),
            _tile(
                "rescan: unexpected",
                str(counts.get("unexpected", 0)),
                "warn" if counts.get("unexpected") else "",
            ),
            _tile("rescan: recognised output", str(counts.get("recognized_output", 0))),
        ]
    if data.has_output:
        tiles.append(
            _tile(
                "possible partial finds",
                str(data.possible_partial),
                "warn" if data.possible_partial else "",
                "heuristic, check by eye",
            )
        )
    bar = ""
    if total:
        bar = (
            '<div class="stack" role="img" aria-label="share of findings by outcome">'
            + "".join(
                f'<span class="{c}" style="width:{n / total * 100:.2f}%"></span>'
                for c, n in (
                    ("s-t", transformed),
                    ("s-a", allowed),
                    ("s-r", review),
                    ("s-b", blocked),
                )
                if n
            )
            + "</div>"
            + '<div class="legend">'
            + "".join(
                f'<span><i class="{c}"></i>{_e(label)} {n} ({_pct(n, total)})</span>'
                for c, label, n in (
                    ("s-t", done_label, transformed),
                    ("s-a", "kept", allowed),
                    ("s-r", "review", review),
                    ("s-b", "blocked", blocked),
                )
            )
            + "</div>"
        )
    dropped_cols = ch.get("dropped_columns") or s.get("dropped_columns") or []
    cols = (
        f'<p class="small muted">columns dropped: {_e(", ".join(map(str, dropped_cols)))}</p>'
        if dropped_cols
        else ""
    )
    return (
        "<h2>How the run went</h2>"
        f'<div class="tiles">{"".join(tiles)}</div>'
        f'<div class="card"><h3>Findings by outcome</h3>{bar or "<p>No findings.</p>"}{cols}'
        '<p class="small muted">Transformed means a redact, replace, pseudonymize, generalize, '
        "date_shift or drop rule applies. It does not mean every sensitive value was found: "
        f"{_e(RESCAN_LIMIT)}</p></div>"
    )


def _table(title: str, counts: dict[str, int]) -> str:
    if not counts:
        return ""
    top = max(counts.values()) or 1
    rows = "".join(
        f"<tr><td><code>{_e(k)}</code></td><td class='num'>{v}</td>"
        f"<td><div class='meter'><span style='width:{v / top * 100:.1f}%'></span></div></td></tr>"
        for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        f'<div class="card"><h3>{_e(title)}</h3><table><tr><th>name</th><th class="num">count</th>'
        f"<th></th></tr>{rows}</table></div>"
    )


def _matrix(matrix: dict[str, dict[str, int]]) -> str:
    if not matrix:
        return ""
    actions = sorted({a for row in matrix.values() for a in row})
    head = "".join(f"<th class='num'>{_e(a)}</th>" for a in actions)
    rows = []
    for category in sorted(matrix):
        row = matrix[category]
        total = sum(row.values())
        done = sum(row.get(a, 0) for a in TRANSFORM_ACTIONS)
        cells = "".join(f"<td class='num'>{row.get(a, 0) or ''}</td>" for a in actions)
        rows.append(
            f"<tr><td><code>{_e(category)}</code></td>{cells}<td class='num'>{total}</td>"
            f"<td class='num'>{_pct(done, total)}</td></tr>"
        )
    return (
        '<div class="card"><h3>Each category: what happened</h3><table>'
        f"<tr><th>category</th>{head}<th class='num'>total</th>"
        "<th class='num'>transformed</th></tr>" + "".join(rows) + "</table></div>"
    )


def _breakdowns(d: dict[str, Any], data: ReviewData) -> str:
    s = d["summary"]
    return (
        "<h2>Breakdown</h2>"
        + _matrix(data.category_actions)
        + '<div class="grid2">'
        + _table("By category", s["by_category"])
        + _table("By action", s["by_action"])
        + _table("By rule", s["by_rule"])
        + _table("By reason code", s["by_reason_code"])
        + _table("By detector", s["by_detector"])
        + _table("By confidence band", s["by_confidence_band"])
        + "</div>"
    )


def _rescan(d: dict[str, Any]) -> str:
    rescan = d.get("rescan")
    if not rescan:
        return (
            '<h2>Rescan</h2><div class="card small">No rescan ran (no output preview, or the '
            "policy disables the rescan gate).</div>"
        )
    counts = rescan.get("counts", {})
    rows = "".join(
        f"<tr><td>{_e(label)}</td><td class='num'>{counts.get(key, 0)}</td><td>{_e(note)}</td></tr>"
        for key, label, note in (
            ("recognized_output", "recognised output", "CipherGate markers or pseudonyms"),
            ("allowed", "allowed", "kept on purpose by an allow rule"),
            ("unverifiable", "unverifiable", "date-shifted values cannot be told apart"),
            ("unexpected", "unexpected", "still matches a detector after transforms"),
        )
    )
    gating = rescan.get("gating_by_category", {})
    gating_html = (
        "<p><b>Gating categories still present:</b> "
        + ", ".join(f"<code>{_e(k)}</code>: {v}" for k, v in gating.items())
        + "</p>"
        if gating
        else "<p>No gating categories remain.</p>"
    )
    return (
        "<h2>Rescan of the would-be output</h2>"
        '<div class="card"><table><tr><th>class</th><th class="num">count</th>'
        f"<th>meaning</th></tr>{rows}"
        f"</table>{gating_html}"
        f'<p class="small muted">gating categories: '
        f"{_e(', '.join(rescan.get('fail_on_categories', [])) or 'none')}. "
        f"{_e(RESCAN_LIMIT)}</p></div>"
    )


def _gates_keys(d: dict[str, Any]) -> str:
    items = []
    for gate in d["gates"]:
        items.append(
            f"<li><span class='badge warn'>{_e(gate.get('severity', ''))}</span>"
            f"<code>{_e(gate.get('reason_code', ''))}</code> {_e(gate.get('message', ''))}</li>"
        )
    for key in d["keys"]:
        cls = "ok" if key["status"] == "available" else "bad"
        items.append(
            f"<li><span class='badge {cls}'>key {_e(key['status'])}</span>"
            f"<code>{_e(key['key_env'])}</code> (value never shown)</li>"
        )
    for warning in d["warnings"]:
        items.append(f"<li><span class='badge warn'>warning</span>{_e(warning)}</li>")
    if d["parse_errors"]:
        items.append(
            f"<li><span class='badge bad'>parse errors</span>{len(d['parse_errors'])} line(s)</li>"
        )
    if not items:
        return ""
    return f'<h2>Gates, keys and warnings</h2><div class="card"><ul>{"".join(items)}</ul></div>'


def _records(data: ReviewData) -> str:
    if not data.records:
        return '<h2>Records</h2><div class="card small">No records with findings.</div>'
    hidden = (
        f'<p class="small muted">{data.records_hidden} more record(s) with findings are not '
        "shown; the counts above include them.</p>"
        if data.records_hidden
        else ""
    )
    intro = (
        '<p class="small muted">Only records with findings are shown. Hover a highlight to see '
        "its category, action, rule and reason code. A dashed outline marks a possible partial "
        "find: a replaced name or address sits next to a capitalised word that was left, so "
        "part of the name may remain. It is a hint, not a check.</p>"
    )
    return "<h2>Records</h2>" + intro + "".join(_record(r) for r in data.records) + hidden


def _record(r: ReviewRecord) -> str:
    where = f"record {r.index + 1}" + (f" · line {r.line}" if r.line is not None else "")
    actions = sorted({x["action"] for x in r.decisions})
    badges = "".join(
        f"<span class='badge {'bad' if a == 'block' else 'warn' if a == 'review' else ''}'>"
        f"{_e(a)}</span>"
        for a in actions
    )
    if any(s.partial for s in r.out_segments):
        badges += "<span class='badge warn'>possible partial find</span>"
    if r.truncated:
        badges += "<span class='badge'>cut to fit</span>"
    body = []
    if r.dropped:
        body.append(
            '<div class="label">output</div><pre>(record dropped by a drop_record rule)</pre>'
        )
    elif r.after is not None:
        body.append(
            '<div class="label">output</div><pre>'
            + _marked(r.after, r.out_segments, "chg")
            + "</pre>"
        )
    if r.before is not None:
        body.append(
            '<div class="label">input (raw)</div><pre>'
            + _marked(r.before, r.in_segments, "in")
            + "</pre>"
        )
    rows = "".join(
        "<tr>"
        f"<td><code>{_e(x['category'])}</code></td><td>{_e(x['action'])}</td>"
        f"<td><code>{_e(x['rule_id'] or 'engine default')}</code></td>"
        f"<td><code>{_e(x['reason_code'])}</code></td><td>{_e(x['band'])}</td>"
        f"<td>{_e(x['detector'])}</td><td><code>{_e(x['field_path'])}</code></td>"
        "</tr>"
        for x in r.decisions
    )
    table = (
        "<table><tr><th>category</th><th>action</th><th>rule</th><th>reason</th>"
        f"<th>confidence</th><th>detector</th><th>field</th></tr>{rows}</table>"
    )
    return (
        f'<div class="card"><h3>{_e(where)} {badges}</h3>{"".join(body)}'
        f"<details><summary class='small'>{len(r.decisions)} decision(s)</summary>{table}"
        "</details></div>"
    )


def _marked(text: str, segments: list[Segment], cls: str) -> str:
    out: list[str] = []
    pos = 0
    for seg in _coalesce(segments):
        if seg.start < pos:
            continue
        out.append(_e_text(text[pos : seg.start]))
        title = _e("; ".join(seg.labels) or "changed")
        if seg.kind == "delete":
            out.append(f'<span class="del" title="removed here: {title}">⌫</span>')
        else:
            kind = "kept" if seg.kind == "kept" else cls
            extra = " partial" if seg.partial else ""
            out.append(f'<mark class="{kind}{extra}" title="{title}">')
            out.append(_e_text(text[seg.start : seg.end]))
            out.append("</mark>")
        pos = max(pos, seg.end)
    out.append(_e_text(text[pos:]))
    return "".join(out)


def _e_text(text: str) -> str:
    return html.escape(escape_invisible(text, keep_tabs=True), quote=False)


def _coalesce(segments: list[Segment]) -> list[Segment]:
    """Sort and merge overlapping finding or kept ranges so the marks never nest."""
    merged: list[Segment] = []
    for seg in sorted(segments, key=lambda s: (s.start, s.end)):
        if (
            merged
            and seg.kind in _MERGEABLE
            and merged[-1].kind in _MERGEABLE
            and seg.start < merged[-1].end
        ):
            last = merged.pop()
            labels = tuple(dict.fromkeys(last.labels + seg.labels))
            merged.append(replace(last, end=max(last.end, seg.end), labels=labels))
        else:
            merged.append(seg)
    return merged


def _footer() -> str:
    return (
        '<h2>About this page</h2><div class="card small muted">'
        "<p>Made locally by <code>ciphergate review</code>. It has no scripts and loads nothing "
        "from the network. The metrics come from the same privacy-safe report as "
        "<code>ciphergate plan</code>; the report never contains input values.</p>"
        f"<p>{_e(DISCLAIMER)}</p></div>"
    )
