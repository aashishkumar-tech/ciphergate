"""Allowlist mode: ``settings.unrecognized_values`` protects every value nothing recognised."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.errors import InputFormatError, PolicyValidationError
from ciphergate.pipeline.sanitizer import inspect_file, plan_file, rescan_file, sanitize_file
from ciphergate.policy.validator import load_policy_text

BASE = """
policy_version: 1
name: {name}
context: {{environment: prd, target_environment: external, destination: external_ai}}
settings:
  unrecognized_values: {mode}
  scan_json_keys: true
keep:
  field_names: [status, kind]
  field_paths: ["/meta/*"]
rules:
  - id: redact-pii
    priority: 200
    match: {{categories: ["pii.*"]}}
    action: redact
    reason: remove_identifier
  - id: keep-state
    priority: 300
    match: {{field_names: [state], categories: [location.coarse]}}
    action: allow
    reason: state_is_needed
classifications:
  - {{id: st, field_names: [state], category: location.coarse}}
"""

DOC = {
    "meta": {"source": "SYNTHETIC_TEST_DATA"},
    "items": [
        {
            "status": "active",
            "kind": "visit",
            "state": "CA",
            "code": "TEST_ONLY_CODE_9",
            "display": "TEST_ONLY_CONDITION_X",
            "score": 8.1,
            "flag": True,
            "empty": "",
            "nothing": None,
            "note": "call +1 202 555 0143 about TEST_ONLY_SECRETNOTE",
            "email": "patient.one@example.com",
        }
    ],
}
RAW = [
    "TEST_ONLY_CODE_9",
    "TEST_ONLY_CONDITION_X",
    "TEST_ONLY_SECRETNOTE",
    "202 555 0143",
    "patient.one@example.com",
]


def policy(mode: str = "redact", name: str = "allowlist"):  # type: ignore[no-untyped-def]
    return load_policy_text(BASE.format(mode=mode, name=name))


@pytest.fixture
def doc(tmp_path: Path) -> Path:
    path = tmp_path / "in.json"
    path.write_text(json.dumps(DOC), encoding="utf-8")
    return path


def test_off_by_default_leaves_unrecognized_values(doc: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    report = sanitize_file(doc, out, policy("off", "off-mode"))
    assert str(report.status) == "sanitized"
    item = json.loads(out.read_text(encoding="utf-8"))["items"][0]
    assert item["code"] == "TEST_ONLY_CODE_9"  # the old behaviour: unknown fields pass


def test_redact_mode_keeps_only_listed_fields(doc: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    report = sanitize_file(doc, out, policy())
    assert str(report.status) == "sanitized"
    data = json.loads(out.read_text(encoding="utf-8"))
    item = data["items"][0]
    marker = "[REDACTED:unknown.sensitive_candidate]"
    assert item["status"] == "active" and item["kind"] == "visit"  # keep.field_names
    assert data["meta"]["source"] == "SYNTHETIC_TEST_DATA"  # keep.field_paths
    assert item["state"] == "CA"  # an explicit allow decision still stands
    assert item["code"] == marker and item["display"] == marker
    assert item["score"] == marker and item["flag"] == marker  # numbers and booleans too
    assert item["empty"] == "" and item["nothing"] is None  # nothing to protect
    # A value with only a partial (span) finding is protected whole.
    assert item["note"] == marker
    assert item["email"] == "[REDACTED:pii.email]"
    text = out.read_text(encoding="utf-8") + json.dumps(report.to_dict())
    for raw in RAW:
        assert raw not in text
    decisions = {
        i["location"]["field_path"]: i["decision"]
        for i in report.items
        if i["detector"] == "unrecognized_value"
    }
    assert decisions["/items/0/code"]["rule_id"] == "settings:unrecognized_values"
    assert decisions["/items/0/code"]["reason_code"] == "unrecognized_value_not_kept"
    assert "/items/0/status" not in decisions and "/items/0/state" not in decisions


def test_keep_does_not_disable_detectors(tmp_path: Path) -> None:
    path = tmp_path / "in.json"
    path.write_text(json.dumps({"status": "mail patient.one@example.com"}), encoding="utf-8")
    out = tmp_path / "out.json"
    sanitize_file(path, out, policy())
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "mail [REDACTED:pii.email]"


def test_rescan_of_output_is_clean(doc: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    sanitize_file(doc, out, policy())
    rescan = rescan_file(out, policy())
    assert str(rescan.status) != "rescan_failed"
    assert not [i for i in rescan.items if i["detector"] == "unrecognized_value"]


@pytest.mark.parametrize(("mode", "status"), [("review", "review_required"), ("block", "blocked")])
def test_review_and_block_withhold_output(
    doc: Path, tmp_path: Path, mode: str, status: str
) -> None:
    out = tmp_path / "out.json"
    report = sanitize_file(doc, out, policy(mode, f"{mode}-mode"))
    assert str(report.status) == status
    assert not out.exists()
    assert str(plan_file(doc, policy(mode, f"{mode}-mode")).status) == status


def test_inspect_reports_counts_without_values(doc: Path) -> None:
    report = inspect_file(doc, policy())
    data = json.dumps(report.to_dict())
    assert (
        report.summary["by_category"]["unknown.sensitive_candidate"] == 5
    )  # code, display, score, flag, note
    for raw in RAW:
        assert raw not in data


def test_json_keys_are_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "in.json"
    path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    report = inspect_file(path, policy())
    assert report.items == []


def test_csv_columns_and_header(tmp_path: Path) -> None:
    path = tmp_path / "in.csv"
    path.write_text("status,code\nactive,TEST_ONLY_CODE_9\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    report = sanitize_file(path, out, policy())
    assert str(report.status) == "sanitized"
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines == ["status,code", "active,[REDACTED:unknown.sensitive_candidate]"]


def test_jsonl_records(tmp_path: Path) -> None:
    path = tmp_path / "in.jsonl"
    path.write_text('{"status": "a", "code": "X1"}\n{"status": "b", "code": "X2"}\n', "utf-8")
    out = tmp_path / "out.jsonl"
    sanitize_file(path, out, policy())
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert [r["code"] for r in rows] == ["[REDACTED:unknown.sensitive_candidate]"] * 2
    assert [r["status"] for r in rows] == ["a", "b"]


@pytest.mark.parametrize(("suffix", "body"), [(".log", "a line\n"), (".txt", "x=1\n")])
def test_line_formats_fail_closed(tmp_path: Path, suffix: str, body: str) -> None:
    path = tmp_path / f"in{suffix}"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(InputFormatError) as err:
        inspect_file(path, policy())
    assert err.value.code == "unrecognized_values_unsupported_format"
    assert not (tmp_path / "out").exists()


def test_keep_without_mode_warns() -> None:
    p = load_policy_text(BASE.format(mode="off", name="warn"))
    assert any("keep has no effect" in w for w in p.warnings)


# ----------------------------------------------------------------------------- layering


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_later_layer_cannot_turn_mode_off(tmp_path: Path) -> None:
    write(tmp_path / "base.yml", BASE.format(mode="redact", name="base"))
    site = write(
        tmp_path / "site.yml",
        'policy_version: 1\nname: site\nextends: ["base.yml"]\n'
        'settings:\n  unrecognized_values: "off"\n',
    )
    with pytest.raises(PolicyValidationError) as err:
        load_policy(site)
    assert "layer_weakens_setting" in {i.code for i in err.value.issues}


def test_later_layer_can_tighten_mode(tmp_path: Path) -> None:
    write(tmp_path / "base.yml", BASE.format(mode="redact", name="base"))
    site = write(
        tmp_path / "site.yml",
        'policy_version: 1\nname: site\nextends: ["base.yml"]\n'
        "settings:\n  unrecognized_values: block\n",
    )
    assert load_policy(site).document.settings.unrecognized_values == "block"


def test_keep_added_after_mode_is_on_warns(tmp_path: Path) -> None:
    write(tmp_path / "base.yml", BASE.format(mode="redact", name="base"))
    site = write(
        tmp_path / "site.yml",
        'policy_version: 1\nname: site\nextends: ["base.yml"]\nkeep:\n  field_names: [code]\n',
    )
    p = load_policy(site)
    assert "code" in p.document.keep.field_names and "status" in p.document.keep.field_names
    assert any("keep exempts 1 field selector" in w for w in p.warnings)


def test_mode_and_keep_in_same_layer_do_not_warn(tmp_path: Path) -> None:
    write(tmp_path / "base.yml", BASE.format(mode="off", name="base").split("keep:")[0])
    site = write(
        tmp_path / "site.yml",
        'policy_version: 1\nname: site\nextends: ["base.yml"]\n'
        "settings:\n  unrecognized_values: redact\nkeep:\n  field_names: [status]\n",
    )
    assert not any("keep exempts" in w for w in load_policy(site).warnings)
