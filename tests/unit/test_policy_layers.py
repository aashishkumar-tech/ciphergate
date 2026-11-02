"""Policy layering (`extends`): merge rules, no quiet weakening, provenance and the digest."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.config import RuntimeSettings
from ciphergate.constants import Destination, Environment, InputFormat, TargetEnvironment
from ciphergate.errors import PolicyValidationError
from ciphergate.models.context import ContextInput
from ciphergate.models.finding import Finding, Location
from ciphergate.pipeline.sanitizer import SanitizeOptions, plan_file, sanitize_file
from ciphergate.policy import layers
from ciphergate.policy.context import resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.validator import load_policy_text
from tests.conftest import POLICIES, ctx

HEAD = "policy_version: 1\nname: child\n"


def load(text: str):  # type: ignore[no-untyped-def]
    return load_policy_text(text, source_name="child.yml")


def codes(text: str) -> set[str]:
    with pytest.raises(PolicyValidationError) as exc:
        load(text)
    return {i.code for i in exc.value.issues} | {exc.value.code}


@pytest.fixture
def packs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A private copy of the shipped policies directory whose packs a test may change."""
    root = tmp_path / "policies"
    shutil.copytree(POLICIES, root)
    monkeypatch.setattr(layers, "bundled_policies_dir", lambda: root)
    return root / "packs"


# --------------------------------------------------------------------------- shipped packs


def test_hospital_template_resolves_three_layers() -> None:
    policy = load_policy(POLICIES / "hospital_us_override.yml")
    assert [x.name for x in policy.layers] == [
        "healthcare_baseline",
        "us_hipaa",
        "hospital-us-override",
    ]
    assert [x.kind for x in policy.layers] == ["pack", "pack", "policy"]
    own = policy.layers[-1].digest
    assert policy.digest.startswith("sha256:") and policy.digest != own
    assert any("relaxes default 'location.*'" in w for w in policy.warnings)
    assert {r.layer for r in policy.rules} == {
        "healthcare_baseline",
        "us_hipaa",
        "hospital-us-override",
    }


def test_single_file_policy_has_no_layers() -> None:
    policy = load_policy(POLICIES / "healthcare_template.yml")
    assert policy.layers == ()
    assert all(r.layer is None for r in policy.rules)


def test_pack_names_are_the_shipped_files() -> None:
    assert layers.pack_names() == sorted(p.stem for p in (POLICIES / "packs").glob("*.yml"))
    assert {"healthcare_baseline", "us_hipaa"} <= set(layers.pack_names())


@pytest.mark.parametrize("name", ["healthcare_baseline", "us_hipaa", "eu_gdpr", "india_dpdp"])
def test_packs_say_template_and_make_no_compliance_claim(name: str) -> None:
    text = (POLICIES / "packs" / f"{name}.yml").read_text(encoding="utf-8")
    assert "TEMPLATE REQUIRING REVIEW" in text
    lowered = " ".join(text.lower().replace("#", " ").split())  # ignore comment line wraps
    for claim in ("compliant", "compliance with", "guaranteed", "anonymized", "anonymised"):
        assert claim not in lowered
    assert "not legal or compliance advice" in lowered or name == "healthcare_baseline"
    if name == "us_hipaa":
        assert "does NOT perform Safe Harbor or" in text and "Expert Determination" in text


def test_diamond_extends_uses_a_pack_once() -> None:
    policy = load(HEAD + "extends: [us_hipaa, healthcare_baseline]\n")
    assert [x.name for x in policy.layers] == ["healthcare_baseline", "us_hipaa", "child"]


# --------------------------------------------------------------------------- resolution errors


def test_unknown_pack_is_rejected() -> None:
    assert "unknown_pack" in codes(HEAD + "extends: [no_such_pack]\n")


@pytest.mark.parametrize("name", ["../packs/us_hipaa", "packs/us_hipaa", "/etc/passwd"])
def test_pack_names_cannot_be_paths(name: str) -> None:
    with pytest.raises(PolicyValidationError):
        load(HEAD + f"extends: ['{name}']\n")


def test_cycle_is_rejected(packs: Path) -> None:
    (packs / "loop_a.yml").write_text("policy_version: 1\nname: a\nextends: [loop_b]\n")
    (packs / "loop_b.yml").write_text("policy_version: 1\nname: b\nextends: [loop_a]\n")
    assert "layer_cycle" in codes(HEAD + "extends: [loop_a]\n")


def test_depth_is_limited(packs: Path) -> None:
    for i in range(6):
        parent = f"extends: [deep_{i + 1}]\n" if i < 5 else ""
        (packs / f"deep_{i}.yml").write_text(f"policy_version: 1\nname: d{i}\n{parent}")
    assert "layer_depth" in codes(HEAD + "extends: [deep_0]\n")


def test_invalid_pack_reports_its_layer(packs: Path) -> None:
    (packs / "broken.yml").write_text("policy_version: 1\nname: broken\nsurprise: 1\n")
    with pytest.raises(PolicyValidationError) as exc:
        load(HEAD + "extends: [broken]\n")
    assert any(i.location.startswith("pack[broken].") for i in exc.value.issues)


def test_relaxes_without_extends_is_rejected() -> None:
    text = (
        HEAD + "context: {destination: local_dev}\nrules:\n  - id: r\n"
        "    match: {categories: [pii.email]}\n    action: redact\n    relaxes: [other]\n"
    )
    assert "unknown_relaxes" in codes(text)


def test_digest_changes_when_a_pack_changes(packs: Path) -> None:
    text = HEAD + "extends: [us_hipaa]\n"
    before = load(text).digest
    pack = packs / "healthcare_baseline.yml"
    pack.write_text(pack.read_text(encoding="utf-8") + "# reviewed again\n", encoding="utf-8")
    after = load(text).digest
    assert before != after


# --------------------------------------------------------------------------- no quiet weakening


@pytest.mark.parametrize(
    ("snippet", "code"),
    [
        ("settings: {strict: false}\n", "layer_weakens_setting"),
        ("settings: {scan_json_keys: false}\n", "layer_weakens_setting"),
        ("settings: {rescan: {enabled: false}}\n", "layer_weakens_setting"),
        ("requirements: {destination: false}\n", "layer_weakens_setting"),
        ("detectors: {disabled: [email_regex]}\n", "layer_weakens_detectors"),
        ("context: {domain_profile: general}\n", "layer_context_conflict"),
        ("context: {allow_cli_override: [domain_profile]}\n", "layer_weakens_context"),
    ],
)
def test_later_layer_cannot_weaken_settings(snippet: str, code: str) -> None:
    assert code in codes(HEAD + "extends: [healthcare_baseline]\n" + snippet)


def test_review_cannot_drop_to_a_weaker_setting_when_parent_blocks(packs: Path) -> None:
    (packs / "blocky.yml").write_text(
        "policy_version: 1\nname: blocky\nsettings: {unknown_sensitive_behavior: block}\n"
    )
    text = HEAD + "extends: [blocky]\nsettings: {unknown_sensitive_behavior: review}\n"
    assert "layer_weakens_setting" in codes(text)


def test_stricter_values_are_accepted() -> None:
    policy = load(
        HEAD + "extends: [healthcare_baseline]\n"
        "settings: {unknown_sensitive_behavior: block, rescan: {fail_on_categories: "
        "[network.telemetry]}}\n"
    )
    settings = policy.document.settings
    assert settings.unknown_sensitive_behavior == "block"
    fail_on = set(settings.rescan.fail_on_categories or [])
    assert "network.telemetry" in fail_on and "pii.email" in fail_on  # high-risk floor kept


def test_rule_ids_cannot_be_redefined() -> None:
    text = (
        HEAD + "extends: [healthcare_baseline]\nrules:\n  - id: baseline-redact-identifiers\n"
        "    match: {categories: [pii.email]}\n    action: redact\n"
    )
    assert "duplicate_id" in codes(text)


WEAKER_RULE = """extends: [healthcare_baseline]
rules:
  - id: keep-diagnosis
    priority: 900
    match:
      categories: [health.phi]
      field_names: [diagnosis]
    action: redact
"""


def test_outranking_a_block_with_a_weaker_action_is_rejected() -> None:
    assert "layer_weakens_rule" in codes(HEAD + WEAKER_RULE)


def test_relaxes_makes_the_weakening_explicit_and_warns() -> None:
    text = (
        HEAD
        + WEAKER_RULE
        + "    relaxes:\n      - baseline-block-clinical-values-external\n"
        + "      - baseline-review-clinical-values\n"
    )
    policy = load(text)
    relaxed = [w for w in policy.warnings if "relaxes rule" in w]
    assert len(relaxed) == 2
    assert all("from layer 'healthcare_baseline'" in w for w in relaxed)


def test_hard_rules_can_never_be_relaxed() -> None:
    text = (
        HEAD + "extends: [healthcare_baseline]\nrules:\n  - id: soft-credentials\n"
        "    hard: true\n    priority: 5000\n    match: {categories: [credential.secret]}\n"
        "    action: redact\n    relaxes: [baseline-block-credentials]\n"
    )
    assert "layer_weakens_rule" in codes(text)


def test_relaxes_must_name_an_earlier_rule() -> None:
    text = HEAD + WEAKER_RULE + "    relaxes: [not-a-rule]\n"
    assert "unknown_relaxes" in codes(text)


def test_a_swap_between_transforms_needs_no_relaxes() -> None:
    policy = load(
        HEAD + "extends: [healthcare_baseline]\nrules:\n  - id: pseudonymize-email\n"
        "    priority: 500\n    match: {categories: [pii.email]}\n    action: pseudonymize\n"
        "    params: {scope: field}\n"
    )
    assert "CIPHERGATE_HMAC_KEY" in policy.required_keys


def test_allow_over_an_earlier_default_needs_relaxes() -> None:
    rule = (
        "extends: [healthcare_baseline]\nrules:\n  - id: keep-city\n    priority: 300\n"
        "    match: {categories: [location.coarse]}\n    action: allow\n"
    )
    assert "layer_weakens_default" in codes(HEAD + rule)
    policy = load(HEAD + rule + "    relaxes: ['defaults:location.*']\n")
    assert any("relaxes default 'location.*'" in w for w in policy.warnings)


def test_a_later_default_cannot_weaken_an_earlier_one() -> None:
    text = HEAD + "extends: [healthcare_baseline]\ndefaults:\n  location.coarse: {action: allow}\n"
    assert "layer_weakens_default" in codes(text)
    stricter = (
        HEAD + "extends: [healthcare_baseline]\ndefaults:\n  location.coarse: {action: block}\n"
    )
    assert load(stricter).default_for("location.coarse").action == "block"  # type: ignore[union-attr]


# --------------------------------------------------------------------------- engine provenance


def test_decisions_name_the_layer() -> None:
    policy = load_policy(POLICIES / "hospital_us_override.yml")
    engine = PolicyEngine(policy)
    context = resolve_context(policy, ContextInput())
    finding = Finding(
        category="pii.age",
        detector="policy_classification",
        confidence=0.9,
        evidence=("field_name_match",),
        location=Location(0, 2, "#age"),
        field_name="age",
        value_type="string",
    )
    decision = engine.decide(finding, context, InputFormat.CSV)
    assert decision.rule_id == "us-age-band" and decision.layer == "us_hipaa"
    assert decision.to_dict()["layer"] == "us_hipaa"


# --------------------------------------------------------------------------- environment matrix

CSV = "patient_id,diagnosis,age\nTEST_ONLY_PT_001,TEST_ONLY_CONDITION,93\n"


@pytest.mark.parametrize(
    ("env", "target", "dest", "status"),
    [
        ("prd", "external", "external_ai", "blocked"),
        ("prd", "prd", "approved_internal", "review_required"),
        ("dev", "dev", "local_dev", "review_required"),
    ],
)
def test_us_pack_blocks_clinical_values_only_toward_external(
    tmp_path: Path, env: str, target: str, dest: str, status: str
) -> None:
    source = tmp_path / "visits.csv"
    source.write_text(CSV, encoding="utf-8")
    policy = load_policy(POLICIES / "packs" / "us_hipaa.yml")
    report = plan_file(source, policy, ctx(env, target, dest))
    assert str(report.status) == status
    diagnosis = [i for i in report.items if i["location"].get("field_path") == "diagnosis"]
    assert diagnosis and all(i["decision"]["layer"] == "healthcare_baseline" for i in diagnosis)


def test_layered_report_lists_layers_and_hides_own_path_when_redacted(tmp_path: Path) -> None:
    source = tmp_path / "visits.csv"
    source.write_text("age,state\n93,CA\n", encoding="utf-8")
    policy = load_policy(POLICIES / "hospital_us_override.yml")
    out = tmp_path / "out.csv"
    report = sanitize_file(source, out, policy)
    assert str(report.status) == "sanitized"
    assert out.read_text(encoding="utf-8").splitlines()[1] == "90+,CA"
    data = report.to_dict()
    names = [x["name"] for x in data["policy"]["layers"]]
    assert names == ["healthcare_baseline", "us_hipaa", "hospital-us-override"]
    assert data["policy"]["digest"] == policy.digest
    redacted = sanitize_file(
        source,
        tmp_path / "out2.csv",
        policy,
        options=SanitizeOptions(runtime=RuntimeSettings(path_display="redacted")),
    )
    sources = [x["source"] for x in redacted.to_dict()["policy"]["layers"]]
    assert sources == ["packs/healthcare_baseline.yml", "packs/us_hipaa.yml", None]


def test_context_types_are_enums() -> None:
    # Guard the ctx helper used above against silently passing strings.
    c = ctx("prd", "external", "external_ai")
    assert c.environment is Environment.PRD
    assert c.target_environment is TargetEnvironment.EXTERNAL
    assert c.destination is Destination.EXTERNAL_AI


def test_terminal_and_review_page_show_the_layer(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from ciphergate.cli import app
    from ciphergate.pipeline.review import ReviewOptions, review_file

    source = tmp_path / "visits.csv"
    source.write_text("age,state\n93,CA\n", encoding="utf-8")
    policy_path = POLICIES / "hospital_us_override.yml"
    r = CliRunner().invoke(app, ["plan", str(source), "--policy", str(policy_path), "--verbose"])
    assert r.exit_code == 0
    assert "rule us-age-band (us_hipaa)" in r.stdout
    page = tmp_path / "review.html"
    review_file(source, page, load_policy(policy_path), None, ReviewOptions())
    assert "us-age-band (us_hipaa)" in page.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- EU and India packs

EU_CSV = "codice_fiscale,religion,age,note\nRSSMRA85T10A562S,TEST_ONLY_BELIEF,47,ok\n"


@pytest.mark.parametrize(
    ("dest", "status", "action"),
    [("external_ai", "blocked", "block"), ("approved_internal", "review_required", "review")],
)
def test_eu_pack_special_categories_depend_on_destination(
    tmp_path: Path, dest: str, status: str, action: str
) -> None:
    source = tmp_path / "eu.csv"
    source.write_text(EU_CSV, encoding="utf-8")
    policy = load_policy(POLICIES / "packs" / "eu_gdpr.yml")
    report = plan_file(source, policy, ctx("prd", "prd", dest))
    assert str(report.status) == status
    religion = [i for i in report.items if i["location"].get("field_path") == "religion"]
    assert religion and {i["decision"]["action"] for i in religion} == {action}
    assert {i["decision"]["layer"] for i in religion} == {"eu-gdpr"}
    cf = [i for i in report.items if i["detector"] == "custom:eu-it-codice-fiscale"]
    assert cf and cf[0]["category"] == "pii.government_id"


def test_eu_pack_redacts_identifiers_and_bands_age(tmp_path: Path) -> None:
    source = tmp_path / "eu.csv"
    source.write_text("codice_fiscale,age\nRSSMRA85T10A562S,93\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    policy = load_policy(POLICIES / "packs" / "eu_gdpr.yml")
    report = sanitize_file(source, out, policy, ctx("prd", "external", "external_ai"))
    assert str(report.status) == "sanitized"
    assert out.read_text(encoding="utf-8").splitlines()[1] == "[REDACTED:pii.government_id],90+"


def test_india_pack_finds_grouped_aadhaar_abha_and_pan(tmp_path: Path) -> None:
    source = tmp_path / "app.log"
    source.write_text(
        "lookup aadhaar=2345 6789 0123 pan=ABCPE1234F abha=91-1234-5678-9012 addr=test.only@sbx\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.log"
    policy = load_policy(POLICIES / "packs" / "india_dpdp.yml")
    report = sanitize_file(source, out, policy, ctx("prd", "external", "external_ai"))
    assert str(report.status) == "sanitized"
    text = out.read_text(encoding="utf-8")
    assert text == (
        "lookup aadhaar=[REDACTED:pii.government_id] pan=[REDACTED:pii.government_id] "
        "abha=[REDACTED:health.phi] addr=[REDACTED:health.phi]\n"
    )
    # The grouped Aadhaar and ABHA numbers also look like phone numbers; the more confident
    # finding names the redaction marker.
    detectors = {i["detector"] for i in report.items}
    assert {"custom:in-aadhaar-grouped", "custom:in-pan", "custom:in-abha-number"} <= detectors
    assert "custom:in-abha-address" in detectors


@pytest.mark.parametrize("value", ["234567890123", "ABCQE1234F", "abc@abdmx"])
def test_india_pack_value_patterns_are_narrow(tmp_path: Path, value: str) -> None:
    # Unseparated 12 digits, a PAN with an invalid holder-type letter, a non-ABDM domain.
    source = tmp_path / "app.log"
    source.write_text(f"ref {value}\n", encoding="utf-8")
    policy = load_policy(POLICIES / "packs" / "india_dpdp.yml")
    report = plan_file(source, policy, ctx("dev", "dev", "local_dev"))
    assert not any(i["detector"].startswith("custom:in-") for i in report.items)


def test_india_pack_blocks_sensitive_fields_externally(tmp_path: Path) -> None:
    source = tmp_path / "in.csv"
    source.write_text("pincode,caste\n110001,TEST_ONLY_VALUE\n", encoding="utf-8")
    policy = load_policy(POLICIES / "packs" / "india_dpdp.yml")
    report = plan_file(source, policy, ctx("prd", "external", "external_ai"))
    assert str(report.status) == "blocked"
    caste = [i for i in report.items if i["location"].get("field_path") == "caste"]
    assert caste and caste[0]["decision"]["rule_id"] == "in-block-sensitive-external"


def test_one_policy_can_extend_several_jurisdictions() -> None:
    policy = load(HEAD + "extends: [us_hipaa, eu_gdpr, india_dpdp]\n")
    assert [x.name for x in policy.layers] == [
        "healthcare_baseline",
        "us_hipaa",
        "eu_gdpr",
        "india_dpdp",
        "child",
    ]
