"""Field-name heuristics fall back to the nearest named ancestors of a nested JSON value."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.detectors.field_names import (
    PARENT_CONTEXT_EVIDENCE,
    FieldNameDetector,
    ancestor_names,
)
from ciphergate.detectors.registry import DetectorSet
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import DetectorSettings
from ciphergate.pipeline.sanitizer import plan_file, sanitize_file
from ciphergate.policy.validator import load_policy_text
from tests.conftest import POLICIES


def at(path: str, value: object = "TEST_ONLY_VALUE") -> ScanItem:
    leaf = path.rsplit("/", 1)[-1]
    if leaf.isdigit():  # the JSON reader gives array items their parent's name
        parent = path.rsplit("/", 2)[-2]
        name: str | None = parent
    else:
        name = leaf
    return ScanItem(record_index=0, line=None, field_path=path, field_name=name, value=value)


@pytest.mark.parametrize(
    ("path", "category", "via"),
    [
        ("/patients/0/name/first", "pii.person_name", "name"),
        ("/patients/0/medical/diagnoses/0/description", "health.phi", "diagnoses"),
        ("/patients/1/encounters/0/lab_results/3/value", "health.phi", "lab_results"),
        ("/user/contact/address/country", "pii.address", "address"),
        ("/emergency_contact/phone/0/number", "pii.phone", "phone"),
        ("/person/date_of_birth/day", "pii.date_of_birth", "date_of_birth"),
    ],
)
def test_parent_name_classifies_generic_child(path: str, category: str, via: str) -> None:
    (finding,) = FieldNameDetector().detect(at(path))
    assert finding.category == category
    assert finding.field_name == via
    assert PARENT_CONTEXT_EVIDENCE in finding.evidence
    assert finding.location.field_path == path


def test_parent_context_has_lower_confidence_than_own_name() -> None:
    (own,) = FieldNameDetector().detect(at("/a/diagnosis"))
    (inherited,) = FieldNameDetector().detect(at("/a/diagnosis/text"))
    assert inherited.confidence < own.confidence


def test_own_name_wins_over_parent() -> None:
    (finding,) = FieldNameDetector().detect(at("/patient/name/email"))
    assert finding.category == "pii.email"
    assert PARENT_CONTEXT_EVIDENCE not in finding.evidence


@pytest.mark.parametrize(
    "path",
    [
        "/token/expires_in",  # credentials are not inherited (would block harmless children)
        "/credentials/region",
        "/request/host/port",  # telemetry is not inherited
        "/login/attempts",  # customer identifiers are not inherited
        "/name/a/b/c",  # only the 2 nearest named ancestors count
        "/settings/display/theme",
        "/patients/0/sex",  # 'patients' is not a term; the record container is not PHI
        "name_first",  # CSV/plain paths have no ancestors
    ],
)
def test_no_parent_context(path: str) -> None:
    assert FieldNameDetector().detect(at(path)) == []


def test_array_indices_are_skipped_and_pointer_escapes_decoded() -> None:
    assert ancestor_names("/patients/0/diagnoses/12/code") == ["diagnoses", "patients"]
    assert ancestor_names("/a~1b/x~0y/leaf") == ["x~y", "a/b"]
    assert ancestor_names("/leaf") == []
    assert ancestor_names("column") == []


def test_list_of_device_identifiers_is_classified() -> None:
    (finding,) = FieldNameDetector().detect(at("/patients/0/device_identifiers/0"))
    assert finding.category == "pii.device_identifier"


def test_empty_and_marker_values_are_not_flagged() -> None:
    detector = FieldNameDetector()
    assert detector.detect(at("/name/first", "")) == []
    assert detector.detect(at("/name/first", None)) == []
    assert detector.detect(at("/name/first", "[REDACTED:pii.person_name]")) == []


def test_policy_classification_overrides_parent_context() -> None:
    policy = load_policy_text(
        """
policy_version: 1
name: keep-state
classifications:
  - {id: st, field_names: [state], category: location.coarse}
"""
    )
    found = DetectorSet(policy.document.detectors, policy.document).scan(
        at("/contact/address/state", "CA")
    )
    assert [f.category for f in found] == ["location.coarse"]
    without = DetectorSet(DetectorSettings()).scan(at("/contact/address/state", "CA"))
    assert [f.category for f in without] == ["pii.address"]


def test_disabling_field_name_disables_parent_context() -> None:
    settings = DetectorSettings(disabled=["field_name"])
    assert DetectorSet(settings).scan(at("/name/first", "Testfirst")) == []


# ------------------------------------------------------------------ pipeline (healthcare packs)

NESTED = {
    "patients": [
        {
            "name": {"first": "Testfirst", "last": "Testlast"},
            "medical": {
                "diagnoses": [{"icd10": "Z00.00", "description": "TEST_ONLY_CONDITION"}],
                "vitals": {"heart_rate": 72},
            },
            "encounters": [{"lab_results": [{"test": "TEST_PANEL", "value": 5.4}]}],
            "device_identifiers": ["DEV-TEST-0001"],
        }
    ]
}
RAW = ["Testfirst", "Testlast", "TEST_ONLY_CONDITION", "TEST_PANEL", "DEV-TEST-0001", "Z00.00"]


def write_nested(tmp_path: Path) -> Path:
    source = tmp_path / "patients.json"
    source.write_text(json.dumps(NESTED), encoding="utf-8")
    return source


def test_nested_clinical_values_follow_external_block_rule(tmp_path: Path) -> None:
    """A diagnosis inside an object is blocked for external AI like a flat ``diagnoses`` field."""
    source = write_nested(tmp_path)
    plan = plan_file(source, load_policy(POLICIES / "hospital_us_override.yml"))
    assert str(plan.status) == "blocked"
    blocked = {
        i["location"]["field_path"]: i["decision"]["rule_id"]
        for i in plan.items
        if i["decision"]["action"] == "block"
    }
    assert blocked["/patients/0/medical/diagnoses/0/description"] == (
        "baseline-block-clinical-values-external"
    )


def test_nested_values_redacted_after_explicit_relaxation(tmp_path: Path) -> None:
    source = write_nested(tmp_path)
    (tmp_path / "base.yml").write_bytes((POLICIES / "hospital_us_override.yml").read_bytes())
    site = tmp_path / "site.yml"
    site.write_text(
        """
policy_version: 1
name: site
extends: ["base.yml"]
rules:
  - id: redact-clinical
    priority: 900
    match:
      destinations: [external_ai]
      categories: [health.phi]
      field_names: [diagnosis, diagnoses, lab_results, vitals, allergies, medications]
    action: redact
    relaxes: [baseline-block-clinical-values-external, baseline-review-clinical-values]
    reason: clinical_values_removed
""",
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    report = sanitize_file(source, out, load_policy(site))
    assert str(report.status) == "sanitized"
    text = out.read_text(encoding="utf-8")
    report_text = json.dumps(report.to_dict())
    for raw in RAW:
        assert raw not in text
        assert raw not in report_text
    data = json.loads(text)["patients"][0]
    assert data["name"]["first"] == "[REDACTED:pii.person_name]"
    assert data["medical"]["vitals"]["heart_rate"] == "[REDACTED:health.phi]"
    assert data["device_identifiers"] == ["[REDACTED:pii.device_identifier]"]
