"""``ciphergate review``: the local HTML page, its metrics and its write safety."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate.cli import app
from ciphergate.models.report import RescanSummary
from ciphergate.pipeline import review
from ciphergate.pipeline.review import ReviewOptions, _diff_segments, review_file
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import EXAMPLES, MINIMAL_POLICY, POLICIES, SYNTHETIC_SECRETS, ctx

runner = CliRunner()
LOG_ARGS = ("-p", POLICIES / "developer_logs.yml", "--environment", "dev")
LOG_ARGS += ("--destination", "local_dev")
PRD_ARGS = ("-p", POLICIES / "prd_external_ai.yml", "--environment", "prd")
PRD_ARGS += ("--target-environment", "external", "--destination", "external_ai")
DEV = ctx("dev", "dev", "local_dev")


def invoke(*args: str | Path, env: dict[str, str] | None = None):
    return runner.invoke(app, [str(a) for a in args], env=env)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def marks(page: str, cls: str) -> list[str]:
    return re.findall(rf'<mark class="{cls}[^"]*" title="[^"]*">(.*?)</mark>', page)


def test_review_writes_a_page_without_input_values(tmp_path: Path) -> None:
    source = EXAMPLES / "sample.log"
    before = digest(source)
    page = tmp_path / "review.html"
    r = invoke("review", source, *LOG_ARGS, "-o", page)
    assert r.exit_code == 0
    text = page.read_text(encoding="utf-8")
    for secret in SYNTHETIC_SECRETS:
        assert secret not in text
    assert "[REDACTED:pii.email]" in marks(text, "chg")
    assert "[REDACTED:credential.secret]" in marks(text, "chg")
    assert "api-1.prod.internal" in marks(text, "kept")  # kept on purpose by an allow rule
    assert "RAW INPUT" not in text and "would-be sanitized output" in text
    assert digest(source) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["review.html"]  # no sanitized file


def test_include_input_adds_the_raw_input_with_a_warning(tmp_path: Path) -> None:
    page = tmp_path / "review.html"
    r = invoke("review", EXAMPLES / "sample.log", *LOG_ARGS, "-o", page, "--include-input")
    assert r.exit_code == 0
    text = page.read_text(encoding="utf-8")
    assert "This page contains RAW INPUT" in text
    assert "alice.test@example.com" in marks(text, "in")
    assert "RAW INPUT" in r.stderr


def test_review_refuses_overwrite_and_aliases(tmp_path: Path) -> None:
    page = tmp_path / "review.html"
    page.write_text("keep", encoding="utf-8")
    r = invoke("review", EXAMPLES / "sample.log", *LOG_ARGS, "-o", page)
    assert r.exit_code == 5 and page.read_text(encoding="utf-8") == "keep"
    assert (
        invoke("review", EXAMPLES / "sample.log", *LOG_ARGS, "-o", page, "--force").exit_code == 0
    )
    assert page.read_text(encoding="utf-8").startswith("<!doctype html>")
    source = tmp_path / "app.log"
    source.write_bytes((EXAMPLES / "sample.log").read_bytes())
    before = digest(source)
    assert invoke("review", source, *LOG_ARGS, "-o", source, "--force").exit_code == 5
    assert digest(source) == before
    policy = tmp_path / "p.yml"
    policy.write_bytes((POLICIES / "developer_logs.yml").read_bytes())
    args = ("-p", policy, "--environment", "dev", "--destination", "local_dev")
    assert invoke("review", source, *args, "-o", policy, "--force").exit_code == 5


def test_review_rejects_directories_and_stdio(tmp_path: Path) -> None:
    assert invoke("review", EXAMPLES, *LOG_ARGS, "-o", tmp_path / "r.html").exit_code == 2
    assert invoke("review", "-", *LOG_ARGS, "-o", tmp_path / "r.html").exit_code == 2
    assert invoke("review", EXAMPLES / "sample.log", *LOG_ARGS, "-o", "-").exit_code == 2


def test_run_without_output_shows_the_plan_and_keeps_its_exit_code(
    tmp_path: Path, no_key_env: None
) -> None:
    page = tmp_path / "review.html"
    r = invoke("review", EXAMPLES / "sample.csv", *PRD_ARGS, "-o", page)
    assert r.exit_code == 6  # the key is missing, as in plan
    text = page.read_text(encoding="utf-8")
    assert "No output preview" in text and "planned transforms (not run)" in text
    assert "CIPHERGATE_HMAC_KEY" in text and "value never shown" in text
    for secret in SYNTHETIC_SECRETS:
        assert secret not in text
    assert not marks(text, "chg")


def test_blocked_run_with_input_marks_the_findings(tmp_path: Path) -> None:
    page = tmp_path / "review.html"
    blocked = tmp_path / "app.log"
    blocked.write_text("deploy token=TEST_ONLY_NOT_A_CREDENTIAL\n", encoding="utf-8")
    r = invoke("review", blocked, *PRD_ARGS, "-o", page, "--include-input")
    assert r.exit_code == 1
    text = page.read_text(encoding="utf-8")
    assert "Blocked:" in text
    assert any("TEST_ONLY_NOT_A_CREDENTIAL" in m for m in marks(text, "in"))


@pytest.mark.parametrize("name", ["sample.csv", "sample.json", "sample.jsonl"])
def test_structured_formats_label_each_field(tmp_path: Path, name: str, keys: KeyProvider) -> None:
    from ciphergate import load_policy

    policy = load_policy(POLICIES / "test_dataset.yml")
    options = ReviewOptions(include_input=True, keys=keys)
    data = review_file(EXAMPLES / name, tmp_path / "r.html", policy, DEV, options)
    summary = data.report.summary
    assert data.has_output and data.report.exit_code == 0
    assert sum(sum(a.values()) for a in data.category_actions.values()) == summary["findings_total"]
    for record in data.records:
        assert record.after is not None and record.before is not None
        for seg in record.out_segments:
            if seg.kind == "change":
                # each change is labelled by its own field's decision, not the whole record's
                assert len({label.split(" · ")[0] for label in seg.labels}) <= 2
    if name != "sample.jsonl":  # the JSONL sample has no names
        text = (tmp_path / "r.html").read_text(encoding="utf-8")
        assert "Test Person" in marks(text, "chg")
        assert {"Alice", "Example"} <= set(marks(text, "in")) or "Alice Example" in marks(
            text, "in"
        )


def test_metrics_match_the_report(tmp_path: Path) -> None:
    from ciphergate import load_policy

    policy = load_policy(POLICIES / "developer_logs.yml")
    data = review_file(EXAMPLES / "sample.log", tmp_path / "r.html", policy, DEV)
    d = data.report.to_dict()
    text = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert d["summary"]["findings_total"] == 7 and data.records_with_findings == 5
    assert '<div class="n">7</div><div class="l">findings</div>' in text
    assert '<div class="n">4</div><div class="l">transformed</div>' in text
    assert '<div class="n">5/6</div><div class="l">records with findings</div>' in text
    assert f'<div class="n">{d["changes"]["values_changed"]}</div>' in text
    assert d["output"] == {"written": False, "path": None, "withheld_reason": "review_only"}
    assert "rescan only sees what the enabled detectors match" in text


def test_rescan_failure_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ciphergate import load_policy

    failed = RescanSummary(
        True, True, ["pii.email"], {"unexpected": 1}, {"pii.email": 1}, {"pii.email": 1}, []
    )
    monkeypatch.setattr(review, "rescan_path", lambda *a, **k: failed)
    policy = load_policy(POLICIES / "developer_logs.yml")
    data = review_file(EXAMPLES / "sample.log", tmp_path / "r.html", policy, DEV)
    assert data.report.exit_code == 7
    text = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Not ready: the rescan found gating findings" in text
    assert "<code>pii.email</code>: 1" in text


def test_many_and_long_records_are_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_text
) -> None:
    monkeypatch.setattr(review, "MAX_RECORDS", 2)
    source = tmp_path / "app.log"
    lines = [f"user{i}.test@example.com logged in" for i in range(5)]
    lines.append("x" * 5000 + " carol.test@example.com")
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
    data = review_file(source, tmp_path / "r.html", policy_text(MINIMAL_POLICY), DEV)
    assert data.records_with_findings == 6 and data.records_hidden == 4
    assert len(data.records) == 2
    monkeypatch.setattr(review, "MAX_RECORDS", 500)
    data = review_file(source, tmp_path / "r2.html", policy_text(MINIMAL_POLICY), DEV)
    assert data.records[-1].truncated and len(data.records[-1].after or "") <= 4000
    assert "cut to fit" in (tmp_path / "r2.html").read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_page_is_owner_only(tmp_path: Path) -> None:
    page = tmp_path / "review.html"
    assert invoke("review", EXAMPLES / "sample.log", *LOG_ARGS, "-o", page).exit_code == 0
    assert page.stat().st_mode & 0o077 == 0


# --------------------------------------------------------------------------- change marking


def kinds(before: str, after: str, labels: tuple[str, ...]) -> list[tuple[str, str, bool]]:
    out, _ = _diff_segments(before, after, [], [], labels)
    return [(s.kind, after[s.start : s.end], s.partial) for s in out]


NAME = ("pii.person_name · redact · r · explicit_policy_match",)


def test_a_name_half_left_in_place_is_flagged_as_partial() -> None:
    assert kinds("by James Smith today", "by James [REDACTED:pii.person_name] today", NAME) == [
        ("change", "[REDACTED:pii.person_name]", True)
    ]
    assert not kinds(
        "by Jo Smith today", "by Jo [REDACTED] today", ("pii.email · redact · r · c",)
    )[0][2]


def test_whole_replacements_and_cuts_are_not_flagged() -> None:
    assert kinds("by Alice Example today", "by Test Person today", NAME) == [
        ("change", "Test Person", False)
    ]
    assert kinds("mail a.b@example.com now", "mail [REDACTED:pii.email] now", ("x",)) == [
        ("change", "[REDACTED:pii.email]", False)
    ]
    assert kinds("1990-04-12", "1990", ("pii.date_of_birth · generalize · r · c",)) == [
        ("delete", "", False)
    ]


def test_page_is_a_trace_with_steps_records_and_timings(tmp_path: Path) -> None:
    from ciphergate import load_policy

    policy = load_policy(POLICIES / "developer_logs.yml")
    data = review_file(EXAMPLES / "sample.log", tmp_path / "r.html", policy, DEV)
    text = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert set(data.timings) == {"plan", "transform", "rescan"}
    assert all(v >= 0 for v in data.timings.values())
    assert 'id="s-run" checked>' in text and text.count(" checked>") == 1
    for step in ("run", "plan", "read", "detect", "decide", "transform", "rescan", "output"):
        assert f'for="s-{step}"' in text
        assert f'id="p-{step}"' in text
    assert len(re.findall(r'for="s-r[0-9]+"', text)) == len(data.records) == 5
    assert "#s-r0:checked~.layout #p-r0{display:block}" in text


def test_blocked_trace_marks_transform_and_rescan_skipped(tmp_path: Path) -> None:
    from ciphergate import load_policy

    source = tmp_path / "app.log"
    source.write_text("deploy token=TEST_ONLY_NOT_A_CREDENTIAL\n", encoding="utf-8")
    policy = load_policy(POLICIES / "prd_external_ai.yml")
    data = review_file(source, tmp_path / "r.html", policy, ctx("prd", "external", "external_ai"))
    text = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert set(data.timings) == {"plan", "collect"}
    assert text.count('<span class="rt">skipped</span>') == 2
    assert "TEST_ONLY_NOT_A_CREDENTIAL" not in text
