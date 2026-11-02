"""Render a ``ReviewData`` as one self-contained HTML page laid out as a trace.

Left: a tree with the run, its steps (with measured timings) and every record with findings.
Right: the selected item's details. Selection uses hidden radio buttons and CSS only, so the page
has no scripts; a Content-Security-Policy meta tag blocks every load, so opening the page makes no
network request. All text is HTML-escaped and control or invisible characters are shown as
escapes. Metrics come from the privacy-safe run report; record text comes from the would-be
output, and from the input only when the user asked for it.
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
:root{--bg:#f6f6f4;--panel:#fff;--ink:#1c1c1a;--muted:#6a6a63;--line:#e3e1db;--hover:#f0efea;
--sel:#e8eefc;--selink:#1d3f8f;--ok:#1f7a4d;--okbg:#e4f4eb;--warn:#8a5a00;--warnbg:#fcf1d9;
--bad:#a1271b;--badbg:#fbe5e1;--info:#2f5fa7;--chg:#d9ecff;--chgink:#0b3d66;--in:#ffe2dd;
--inink:#6b1309;--code:#f7f7f5}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;
--muted:#9f9e96;--line:#34332f;--hover:#262624;--sel:#1f2b45;--selink:#b9cdf7;--ok:#6fd19c;
--okbg:#163327;--warn:#f0c46a;--warnbg:#382c12;--bad:#ff9a8c;--badbg:#421f1a;--info:#8db4ec;
--chg:#173a5c;--chgink:#cfe6ff;--in:#4a1f19;--inink:#ffd6cf;--code:#171716}}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",
sans-serif;display:flex;flex-direction:column}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px}
.top{background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px;
display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center}
.top .name{font-weight:700;font-size:15px}
.top .meta{color:var(--muted);font-size:13px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:1px 9px;border-radius:999px;
border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.pill.ok{background:var(--okbg);color:var(--ok);border-color:transparent}
.pill.warn{background:var(--warnbg);color:var(--warn);border-color:transparent}
.pill.bad{background:var(--badbg);color:var(--bad);border-color:transparent}
.rawwarn{background:var(--badbg);color:var(--bad);font-weight:600;padding:8px 16px;
border-bottom:1px solid var(--line)}
.trace{flex:1;min-height:0;display:flex}
.sel{position:absolute;opacity:0;pointer-events:none}
.layout{flex:1;min-height:0;display:grid;grid-template-columns:minmax(260px,340px) 1fr}
.tree{border-right:1px solid var(--line);background:var(--panel);overflow:auto;padding:8px 0}
.sect{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
padding:12px 14px 4px}
.node{display:flex;align-items:center;gap:8px;padding:5px 14px;cursor:pointer;
border-left:3px solid transparent}
.node:hover{background:var(--hover)}
.node .lbl{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.node .rt{color:var(--muted);font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}
.d1{padding-left:30px}.d2{padding-left:48px}
.dot{width:8px;height:8px;border-radius:50%;flex:none;background:var(--muted)}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--bad)}
.dot.info{background:var(--info)}.dot.skip{background:transparent;border:1px solid var(--muted)}
.chips{display:flex;gap:4px;overflow:hidden}
.chip{font-size:11px;padding:0 6px;border-radius:4px;background:var(--hover);color:var(--muted);
white-space:nowrap}
.panes{overflow:auto;min-width:0}
.pane{display:none;padding:18px 22px 48px;max-width:1100px}
.pane h2{font-size:17px;margin:0 0 2px}
.crumb{color:var(--muted);font-size:12px;margin-bottom:12px}
.pane h3{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
margin:20px 0 6px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.verdict{border-radius:8px;padding:12px 14px;font-weight:600;font-size:15px}
.verdict.ok{background:var(--okbg);color:var(--ok)}.verdict.warn{background:var(--warnbg);
color:var(--warn)}.verdict.bad{background:var(--badbg);color:var(--bad)}
.verdict .sub{font-weight:400;font-size:12.5px;margin-top:4px}
.note{background:var(--warnbg);color:var(--warn);border-radius:8px;padding:8px 12px;
font-size:13px;margin:10px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile .n{font-size:22px;font-weight:700;font-variant-numeric:tabular-nums}
.tile .l{font-size:12px;color:var(--muted)}
.tile.bad .n{color:var(--bad)}.tile.ok .n{color:var(--ok)}.tile.warn .n{color:var(--warn)}
.stack{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line);
margin:4px 0 8px}
.stack span{display:block;height:100%}
.s-t{background:var(--ok)}.s-a{background:var(--info)}.s-r{background:var(--warn)}
.s-b{background:var(--bad)}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;font-size:13px;margin:0}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.meter{background:var(--line);border-radius:3px;height:6px;min-width:50px}
.meter span{display:block;height:6px;border-radius:3px;background:var(--info)}
.io{border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:10px}
.io .hd{display:flex;justify-content:space-between;background:var(--hover);padding:6px 12px;
font-size:12px;font-weight:600;color:var(--muted)}
.io pre{margin:0;padding:10px 12px;background:var(--code);white-space:pre-wrap;
overflow-wrap:anywhere;line-height:1.6}
.io .empty{padding:10px 12px;color:var(--muted);font-size:13px}
mark{border-radius:3px;padding:0 2px}
mark.chg{background:var(--chg);color:var(--chgink)}
mark.in{background:var(--in);color:var(--inink)}
mark.kept{background:transparent;color:inherit;border-bottom:2px dotted var(--info);
border-radius:0;padding:0}
mark.partial{outline:2px dashed var(--warn);outline-offset:1px}
.del{color:var(--bad);font-weight:700}
.legendrow{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted);margin:6px 0}
ul{margin:4px 0;padding-left:20px}
.muted{color:var(--muted)}.small{font-size:12.5px}
@media (max-width:800px){.trace{display:block}.layout{display:block}
.tree{max-height:45vh;border-right:0;border-bottom:1px solid var(--line)}.pane{padding:14px 16px}}
"""


def _e(value: Any) -> str:
    return html.escape(escape_invisible(str(value)), quote=True)


def _pct(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def _secs(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value * 1000:.0f} ms" if value < 1 else f"{value:.2f} s"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


# --------------------------------------------------------------------------- page


def render_review_page(data: ReviewData) -> str:
    d = data.report.to_dict()
    nodes = _nodes(d, data)
    ids = [node_id for node_id, _, _ in nodes]
    selection_css = "".join(
        f"#s-{i}:checked~.layout label[for=s-{i}]{{background:var(--sel);color:var(--selink);"
        f"border-left-color:var(--selink)}}#s-{i}:checked~.layout #p-{i}{{display:block}}"
        for i in ids
    )
    radios = "".join(
        f'<input class="sel" type="radio" name="sel" id="s-{i}"{" checked" if n == 0 else ""}>'
        for n, i in enumerate(ids)
    )
    tree = "".join(label for _, label, _ in nodes)
    panes = "".join(pane for _, _, pane in nodes)
    raw = (
        '<div class="rawwarn">This page contains RAW INPUT (made with --include-input). Treat it '
        "like the original file: do not share, upload or commit it, and delete it when you are "
        "done.</div>"
        if data.include_input
        else ""
    )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
            '<meta name="referrer" content="no-referrer">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            "<title>CipherGate review</title>",
            f"<style>{_CSS}{selection_css}</style></head><body>",
            _topbar(d, data),
            raw,
            f'<div class="trace">{radios}<div class="layout">',
            f'<nav class="tree" aria-label="trace">{tree}</nav>',
            f'<div class="panes">{panes}</div>',
            "</div></div></body></html>\n",
        ]
    )


def _status(d: dict[str, Any]) -> tuple[str, str]:
    return {
        "ready": ("ok", "ready"),
        "rescan_failed": ("bad", "rescan failed"),
        "blocked": ("bad", "blocked"),
        "review_required": ("warn", "needs review"),
    }.get(d["status"], ("warn", "needs configuration"))


def _topbar(d: dict[str, Any], data: ReviewData) -> str:
    cls, text = _status(d)
    inp = d["input"]
    return (
        '<header class="top"><span class="name">CipherGate review</span>'
        f'<span class="pill {cls}">{_e(text)}</span>'
        f'<span class="meta mono">{_e(inp.get("path") or "")}</span>'
        f'<span class="meta">policy {_e(d["policy"]["name"])}</span>'
        f'<span class="meta">{_context_line(d)}</span>'
        f'<span class="meta">exit {d["exit_code"]} · {_secs(sum(data.timings.values()))}</span>'
        f'<span class="meta">{_e(d["timestamp"])} · v{_e(d["ciphergate_version"])}</span></header>'
    )


def _context_line(d: dict[str, Any]) -> str:
    ctx = d["context"]
    env = ctx.get("environment", {}).get("value") or "?"
    dest = ctx.get("destination", {}).get("value") or "?"
    target = ctx.get("target_environment", {}).get("value")
    return _e(f"{env} → {target} / {dest}" if target else f"{env} → {dest}")


# --------------------------------------------------------------------------- tree


def _node(node_id: str, depth: int, dot: str, label: str, right: str, extra: str = "") -> str:
    return (
        f'<label class="node d{depth}" for="s-{node_id}"><span class="dot {dot}"></span>'
        f'<span class="lbl">{_e(label)}</span>{extra}<span class="rt">{_e(right)}</span></label>'
    )


def _pane(node_id: str, title: str, crumb: str, body: str) -> str:
    return (
        f'<section class="pane" id="p-{node_id}"><h2>{_e(title)}</h2>'
        f'<div class="crumb">{_e(crumb)}</div>{body}</section>'
    )


def _nodes(d: dict[str, Any], data: ReviewData) -> list[tuple[str, str, str]]:
    s = d["summary"]
    t = data.timings
    total = s["findings_total"]
    transformed = sum(s["by_action"].get(a, 0) for a in TRANSFORM_ACTIONS)
    run_cls, _ = _status(d)
    rescan = d.get("rescan") or {}
    gating = sum(rescan.get("gating_by_category", {}).values())
    stops = s["blocked"] + s["review_required"]
    decide_dot = "bad" if s["blocked"] else "warn" if s["review_required"] else "ok"
    nodes: list[tuple[str, str, str]] = [
        (
            "run",
            '<div class="sect">Run</div>'
            + _node("run", 0, run_cls, "review run", _secs(sum(t.values()))),
            _pane("run", "review run", "overview: how the run went", _run_pane(d, data)),
        ),
        (
            "plan",
            _node("plan", 1, decide_dot, "plan pass", _secs(t.get("plan"))),
            _pane("plan", "plan pass", "review run / plan pass", _plan_pane(d, t)),
        ),
        (
            "read",
            _node("read", 2, "ok", "read input", _plural(d["input"]["records"], "record")),
            _pane("read", "read input", "review run / plan pass / read input", _read_pane(d)),
        ),
        (
            "detect",
            _node("detect", 2, "info" if total else "skip", "detect", _plural(total, "finding")),
            _pane("detect", "detect", "review run / plan pass / detect", _detect_pane(d, data)),
        ),
        (
            "decide",
            _node(
                "decide",
                2,
                decide_dot,
                "decide (policy)",
                f"{stops} stop" if stops else f"{transformed} to transform",
            ),
            _pane(
                "decide",
                "decide (policy)",
                "review run / plan pass / decide",
                _decide_pane(d, data),
            ),
        ),
        (
            "transform",
            _node(
                "transform",
                1,
                "ok" if data.has_output else "skip",
                "transform",
                _secs(t.get("transform")) if data.has_output else "skipped",
            ),
            _pane("transform", "transform", "review run / transform", _transform_pane(d, data)),
        ),
        (
            "rescan",
            _node(
                "rescan",
                1,
                ("bad" if gating else "ok") if rescan else "skip",
                "rescan",
                _secs(t.get("rescan")) if rescan else "skipped",
            ),
            _pane("rescan", "rescan", "review run / rescan", _rescan_pane(d)),
        ),
        (
            "output",
            _node("output", 1, "skip", "output", "not written"),
            _pane("output", "output", "review run / output", _output_pane(data)),
        ),
    ]
    tail = f'<div class="sect">Records with findings ({data.records_with_findings})</div>'
    if not data.records:
        tail += '<div class="sect" style="text-transform:none">none</div>'
    for n, record in enumerate(data.records):
        node_id = f"r{n}"
        label = (tail if n == 0 else "") + _record_node(node_id, record)
        nodes.append((node_id, label, _record_pane(node_id, record)))
    extra = ""
    if not data.records:
        extra = tail
    elif data.records_hidden:
        extra = (
            f'<div class="sect" style="text-transform:none">+{data.records_hidden} more not '
            "shown (counted in the totals)</div>"
        )
    if extra:
        node_id, label, pane = nodes[-1]
        nodes[-1] = (node_id, label + extra, pane)
    return nodes


def _worst(record: ReviewRecord) -> str:
    actions = {x["action"] for x in record.decisions}
    if "block" in actions:
        return "bad"
    if "review" in actions:
        return "warn"
    if actions & set(TRANSFORM_ACTIONS):
        return "ok"
    return "info"


def _record_node(node_id: str, record: ReviewRecord) -> str:
    where = f"line {record.line}" if record.line is not None else f"record {record.index + 1}"
    cats = list(dict.fromkeys(x["category"].split(".")[-1] for x in record.decisions))
    chips = "".join(f'<span class="chip">{_e(c)}</span>' for c in cats[:2])
    if len(cats) > 2:
        chips += f'<span class="chip">+{len(cats) - 2}</span>'
    if any(s.partial for s in record.out_segments):
        chips += '<span class="chip" style="color:var(--warn)">partial?</span>'
    return _node(
        node_id,
        1,
        _worst(record),
        where,
        str(len(record.decisions)),
        f'<span class="chips">{chips}</span>',
    )


# --------------------------------------------------------------------------- panes


def _tile(label: str, value: str, cls: str = "", note: str = "") -> str:
    extra = f'<div class="l">{_e(note)}</div>' if note else ""
    return (
        f'<div class="tile {cls}"><div class="n">{_e(value)}</div>'
        f'<div class="l">{_e(label)}</div>{extra}</div>'
    )


def _verdict(d: dict[str, Any]) -> str:
    s = d["summary"]
    total = s["findings_total"]
    transformed = sum(s["by_action"].get(a, 0) for a in TRANSFORM_ACTIONS)
    status = d["status"]
    if status == "ready":
        cls, text = (
            "ok",
            f"Ready: every finding has a decision. {transformed} of {total} findings "
            f"({_pct(transformed, total)}) would be transformed.",
        )
        if d.get("rescan"):
            text += " The rescan found no gating findings in the would-be output."
    elif status == "rescan_failed":
        cls, text = (
            "bad",
            "Not ready: the rescan found gating findings in the would-be output. "
            "sanitize would withhold it.",
        )
    elif status == "blocked":
        cls, text = (
            "bad",
            f"Blocked: {s['blocked']} finding(s) are not permitted for this destination. "
            "sanitize would write no output.",
        )
    elif status == "review_required":
        cls, text = (
            "warn",
            f"Needs review: {s['review_required']} finding(s) need a human decision. "
            "sanitize would write no output.",
        )
    else:
        cls, text = "warn", "Needs configuration: a required key is missing or invalid."
    if any(g.get("severity") in ("block", "review") for g in d["gates"]) and status != "ready":
        text += " Context gates also apply (see decide)."
    return (
        f'<div class="verdict {cls}">{_e(text)}<div class="sub">status {_e(status)} · exit code '
        f"{d['exit_code']} · these numbers cover only what the enabled detectors found.</div></div>"
    )


def _run_pane(d: dict[str, Any], data: ReviewData) -> str:
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
            _tile("records dropped", str(ch.get("records_dropped", 0))),
        ]
    if rescan:
        tiles += [
            _tile("rescan: gating", str(gating), "bad" if gating else "ok"),
            _tile(
                "rescan: unexpected",
                str(counts.get("unexpected", 0)),
                "warn" if counts.get("unexpected") else "",
            ),
        ]
    if data.has_output:
        tiles.append(
            _tile(
                "possible partial finds",
                str(data.possible_partial),
                "warn" if data.possible_partial else "",
                "hint, check by eye",
            )
        )
    note = (
        '<div class="note">This page shows the would-be sanitized output. Treat it like the '
        "sanitized file: detectors can miss values, so read it before sharing. No sanitized file "
        "was written.</div>"
        if data.has_output
        else '<div class="note">No output preview: sanitize would not write an output for this '
        "run. Open decide and the records to see why.</div>"
    )
    bar = ""
    if total:
        parts = (
            ("s-t", done_label, transformed),
            ("s-a", "kept", allowed),
            ("s-r", "review", review),
            ("s-b", "blocked", blocked),
        )
        bar = (
            '<h3>Findings by outcome</h3><div class="stack" role="img" '
            'aria-label="share of findings by outcome">'
            + "".join(
                f'<span class="{c}" style="width:{n / total * 100:.2f}%"></span>'
                for c, _, n in parts
                if n
            )
            + '</div><div class="legend">'
            + "".join(
                f'<span><i class="{c}"></i>{_e(label)} {n} ({_pct(n, total)})</span>'
                for c, label, n in parts
            )
            + "</div>"
        )
    steps = "".join(f"<li>{_e(step['message'])}</li>" for step in d.get("next_steps", []))
    return (
        _verdict(d)
        + note
        + f'<h3>Metrics</h3><div class="tiles">{"".join(tiles)}</div>'
        + bar
        + (f"<h3>Next steps</h3><div class='box'><ul>{steps}</ul></div>" if steps else "")
        + _gates_keys(d)
        + '<h3>Limits</h3><div class="box small muted">'
        + "<p>Transformed means a redact, replace, pseudonymize, generalize, date_shift or drop "
        f"rule applies. It does not mean every sensitive value was found: {_e(RESCAN_LIMIT)}</p>"
        + "<p>Made locally by <code>ciphergate review</code>. The page has no scripts and loads "
        "nothing from the network. The metrics come from the same privacy-safe report as "
        "<code>ciphergate plan</code>.</p>" + f"<p>{_e(DISCLAIMER)}</p></div>"
    )


def _plan_pane(d: dict[str, Any], t: dict[str, float]) -> str:
    s = d["summary"]
    collect = (
        f"<p class='small muted'>Collecting the per-record view took {_secs(t['collect'])}.</p>"
        if "collect" in t
        else ""
    )
    return (
        "<p class='small muted'>One pass over the input: each record is read, scanned by the "
        "detectors, and every finding gets a policy decision. These three steps run together, so "
        "they share one timing.</p>"
        + _kv(
            [
                ("time", _secs(t.get("plan"))),
                ("records", str(d["input"]["records"])),
                ("findings", str(s["findings_total"])),
                ("blocked", str(s["blocked"])),
                ("need review", str(s["review_required"])),
                ("status", d["status"]),
            ]
        )
        + collect
    )


def _read_pane(d: dict[str, Any]) -> str:
    inp = d["input"]
    errors = d["parse_errors"]
    body = _kv(
        [
            ("file", inp.get("path") or ""),
            ("format", inp["format"]),
            ("bytes", str(inp["bytes"])),
            ("records", str(inp["records"])),
            ("blank lines", str(inp.get("blank_lines", 0))),
            ("parse errors", str(len(errors))),
        ]
    )
    if errors:
        body += "<h3>Parse errors</h3>" + _rows_table(
            ["line", "code"], [[str(e["line"]), e["code"]] for e in errors[:50]]
        )
    return body


def _detect_pane(d: dict[str, Any], data: ReviewData) -> str:
    s = d["summary"]
    return (
        _kv(
            [
                ("findings", str(s["findings_total"])),
                ("records with findings", f"{data.records_with_findings}/{d['input']['records']}"),
            ]
        )
        + '<div class="grid2" style="margin-top:12px">'
        + _table("By category", s["by_category"])
        + _table("By detector", s["by_detector"])
        + _table("By confidence band", s["by_confidence_band"])
        + "</div>"
    )


def _decide_pane(d: dict[str, Any], data: ReviewData) -> str:
    s = d["summary"]
    p = d["policy"]
    ctx_rows = [
        (k.replace("_", " "), f"{v.get('value') or '-'} ({v.get('source')})")
        for k, v in d["context"].items()
    ]
    return (
        _kv([("policy", f"{p['name']} v{p['policy_version']}"), ("digest", p["digest"]), *ctx_rows])
        + _matrix(data.category_actions)
        + '<div class="grid2" style="margin-top:12px">'
        + _table("By action", s["by_action"])
        + _table("By rule", s["by_rule"])
        + _table("By reason code", s["by_reason_code"])
        + "</div>"
        + _gates_keys(d)
    )


def _transform_pane(d: dict[str, Any], data: ReviewData) -> str:
    if not data.has_output:
        return (
            '<div class="note">No output preview: the plan did not reach ready, so nothing was '
            "transformed. The counts on the run page are planned transforms (not run).</div>"
        )
    ch = d.get("changes") or {}
    dropped = ch.get("dropped_columns") or []
    return (
        "<p class='small muted'>Second pass: approved actions are applied to a temporary file "
        "that is rescanned and then removed. It is never published.</p>"
        + _kv(
            [
                ("time", _secs(data.timings.get("transform"))),
                ("records written", str(ch.get("records_written", 0))),
                ("records dropped", str(ch.get("records_dropped", 0))),
                ("values changed", str(ch.get("values_changed", 0))),
                ("type changes", str(ch.get("type_changes", 0))),
                ("columns dropped", ", ".join(map(str, dropped)) or "none"),
            ]
        )
    )


def _rescan_pane(d: dict[str, Any]) -> str:
    rescan = d.get("rescan")
    if not rescan:
        return (
            '<div class="note">No rescan ran (no output preview, or the policy disables the '
            "rescan gate).</div>"
        )
    counts = rescan.get("counts", {})
    rows = [
        [label, str(counts.get(key, 0)), note]
        for key, label, note in (
            ("recognized_output", "recognised output", "CipherGate markers or pseudonyms"),
            ("allowed", "allowed", "kept on purpose by an allow rule"),
            ("unverifiable", "unverifiable", "date-shifted values cannot be told apart"),
            ("unexpected", "unexpected", "still matches a detector after transforms"),
        )
    ]
    gating = rescan.get("gating_by_category", {})
    gating_html = (
        "<p><b>Gating categories still present:</b> "
        + ", ".join(f"<code>{_e(k)}</code>: {v}" for k, v in gating.items())
        + "</p>"
        if gating
        else "<p>No gating categories remain.</p>"
    )
    categories = ", ".join(rescan.get("fail_on_categories", [])) or "none"
    return (
        _rows_table(["class", "count", "meaning"], rows, num_cols={1})
        + gating_html
        + f"<p class='small muted'>gating categories: {_e(categories)}.</p>"
        + f"<p class='small muted'>{_e(RESCAN_LIMIT)}</p>"
    )


def _output_pane(data: ReviewData) -> str:
    held = "the would-be output" if data.has_output else "the plan only"
    if data.include_input:
        held += " and the raw input"
    return _kv(
        [
            ("sanitized file", "not written (review only)"),
            ("this page holds", held),
            ("page", data.page_path or ""),
        ]
    ) + (
        "<p class='small muted'>Run <code>ciphergate sanitize --apply</code> to write the output; "
        "use <code>sanitize</code> and <code>rescan</code> as the CI gate.</p>"
    )


def _gates_keys(d: dict[str, Any]) -> str:
    items = []
    for gate in d["gates"]:
        items.append(
            f"<li><span class='pill warn'>{_e(gate.get('severity', ''))}</span> "
            f"<code>{_e(gate.get('reason_code', ''))}</code> {_e(gate.get('message', ''))}</li>"
        )
    for key in d["keys"]:
        cls = "ok" if key["status"] == "available" else "bad"
        items.append(
            f"<li><span class='pill {cls}'>key {_e(key['status'])}</span> "
            f"<code>{_e(key['key_env'])}</code> (value never shown)</li>"
        )
    for warning in d["warnings"]:
        items.append(f"<li><span class='pill warn'>warning</span> {_e(warning)}</li>")
    if not items:
        return ""
    return f'<h3>Gates, keys and warnings</h3><div class="box"><ul>{"".join(items)}</ul></div>'


_LEGEND = (
    '<div class="legendrow"><span><mark class="chg">changed</mark> changed by a '
    'rule</span><span><mark class="kept">kept</mark> kept by an allow rule</span>'
    "<span><span class='del'>⌫</span> text removed</span><span><mark class=\"chg partial\">"
    "dashed</mark> possible partial find: a replaced name or address next to a "
    "capitalised word that stayed (a hint, not a check)</span></div>"
)


def _record_pane(node_id: str, r: ReviewRecord) -> str:
    where = f"record {r.index + 1}" + (f" · line {r.line}" if r.line is not None else "")
    badges = []
    if any(s.partial for s in r.out_segments):
        badges.append("<span class='pill warn'>possible partial find</span>")
    if r.truncated:
        badges.append("<span class='pill'>cut to fit</span>")
    if r.dropped:
        output = '<div class="empty">(record dropped by a drop_record rule)</div>'
    elif r.after is not None:
        output = "<pre>" + _marked(r.after, r.out_segments, "chg") + "</pre>"
    else:
        output = '<div class="empty">No output: the run is not ready (see decide).</div>'
    if r.before is not None:
        inp = "<pre>" + _marked(r.before, r.in_segments, "in") + "</pre>"
    else:
        inp = (
            '<div class="empty">Not included. Re-run with --include-input to see it here; the '
            "page then holds raw data.</div>"
        )
    rows = [
        [
            x["category"],
            x["action"],
            x["rule_id"] or "engine default",
            x["reason_code"],
            x["band"],
            x["detector"],
            x["field_path"],
        ]
        for x in r.decisions
    ]
    body = (
        f"<div>{' '.join(badges)}</div>"
        + _LEGEND
        + '<div class="io"><div class="hd"><span>Input</span></div>'
        + inp
        + "</div>"
        + '<div class="io"><div class="hd"><span>Output</span><span>hover a highlight for its '
        "rule</span></div>"
        + output
        + "</div><h3>Decisions</h3>"
        + _rows_table(
            ["category", "action", "rule", "reason", "confidence", "detector", "field"],
            rows,
            code_cols={0, 2, 3, 6},
        )
    )
    return _pane(node_id, where, "records with findings / " + where, body)


# --------------------------------------------------------------------------- building blocks


def _kv(rows: list[tuple[str, str]]) -> str:
    return (
        '<dl class="kv box">'
        + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in rows)
        + "</dl>"
    )


def _rows_table(
    head: list[str],
    rows: list[list[str]],
    *,
    num_cols: set[int] | None = None,
    code_cols: set[int] | None = None,
) -> str:
    nums = num_cols or set()
    codes = code_cols or set()

    def cell(i: int, value: str) -> str:
        text = f"<code>{_e(value)}</code>" if i in codes and value else _e(value)
        return f"<td class='num'>{text}</td>" if i in nums else f"<td>{text}</td>"

    header = "".join(
        f"<th class='num'>{_e(h)}</th>" if i in nums else f"<th>{_e(h)}</th>"
        for i, h in enumerate(head)
    )
    body = "".join(
        "<tr>" + "".join(cell(i, v) for i, v in enumerate(row)) + "</tr>" for row in rows
    )
    return f'<div class="box"><table><tr>{header}</tr>{body}</table></div>'


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
        f'<div class="box"><h3 style="margin-top:0">{_e(title)}</h3><table><tr><th>name</th>'
        f"<th class='num'>count</th><th></th></tr>{rows}</table></div>"
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
        "<h3>Each category: what happened</h3><div class='box'><table>"
        f"<tr><th>category</th>{head}<th class='num'>total</th>"
        "<th class='num'>transformed</th></tr>" + "".join(rows) + "</table></div>"
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
