"""Optional Presidio NER detector (#7). Runs without Presidio installed: the engine is faked."""

from __future__ import annotations

import subprocess
import sys
import types
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from ciphergate.constants import InputFormat
from ciphergate.detectors import presidio_ner
from ciphergate.detectors.presidio_ner import PresidioDetector, load_analyzer
from ciphergate.detectors.registry import DetectorSet
from ciphergate.errors import DetectionError, DetectorUnavailableError, PolicyValidationError
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import PresidioSettings
from ciphergate.pipeline.sanitizer import SanitizeOptions, inspect_file, sanitize_file
from ciphergate.policy.validator import load_policy_text
from tests.conftest import MINIMAL_POLICY, ctx

NAME = "Testa Fakename"  # synthetic
TEXT = f"ticket opened by {NAME} in Springfield"

NER_POLICY = MINIMAL_POLICY.replace(
    "settings: {strict: false}\n",
    "settings: {strict: false}\n"
    "detectors:\n"
    "  presidio: {enabled: true, model: en_core_web_sm, min_score: 0.5}\n",
).replace(
    "defaults:\n",
    "  - id: redact-coarse-location\n"
    "    priority: 100\n"
    "    match: {categories: [location.coarse]}\n"
    "    action: redact\n"
    "defaults:\n",
)


@dataclass
class Result:
    entity_type: str
    start: int
    end: int
    score: float


class FakeAnalyzer:
    def __init__(self, results: list[Result] | None = None, error: Exception | None = None):
        self.results = results
        self.error = error
        self.calls: list[dict[str, object]] = []

    def analyze(self, **kwargs: object) -> list[Result]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.results is not None:
            return self.results
        text = str(kwargs["text"])
        out = []
        if NAME in text:
            out.append(Result("PERSON", text.index(NAME), text.index(NAME) + len(NAME), 0.85))
        if "Springfield" in text:
            i = text.index("Springfield")
            out.append(Result("LOCATION", i, i + len("Springfield"), 0.7))
        return out


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    load_analyzer.cache_clear()
    yield
    load_analyzer.cache_clear()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeAnalyzer:
    analyzer = FakeAnalyzer()
    monkeypatch.setattr(presidio_ner, "load_analyzer", lambda language, model: analyzer)
    return analyzer


def _item(value: object) -> ScanItem:
    return ScanItem(record_index=0, line=1, field_path="", field_name=None, value=value)


# --------------------------------------------------------------------------- off by default


def test_disabled_by_default_and_not_imported() -> None:
    policy = load_policy_text(MINIMAL_POLICY)
    assert "presidio_ner" not in DetectorSet(policy.document.detectors, policy.document).ids
    code = (
        "import sys\n"
        "from ciphergate.policy.validator import load_policy\n"
        "from ciphergate.pipeline.sanitizer import inspect_file\n"
        "from ciphergate.models.context import ContextInput\n"
        "p = load_policy(sys.argv[1])\n"
        "inspect_file(sys.argv[2], p, ContextInput(environment='dev', destination='local_dev'))\n"
        "assert 'ciphergate.detectors.presidio_ner' not in sys.modules\n"
        "assert 'presidio_analyzer' not in sys.modules and 'spacy' not in sys.modules\n"
    )
    root = Path(__file__).resolve().parents[2]
    r = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(root / "policies" / "developer_logs.yml"),
            str(root / "examples" / "sample.log"),
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert r.returncode == 0, r.stderr.decode(errors="replace")[-500:]


# --------------------------------------------------------------------------- availability


def test_missing_package_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(presidio_ner, "_installed", lambda module: False)
    with pytest.raises(DetectorUnavailableError) as exc:
        PresidioDetector(PresidioSettings(enabled=True))
    assert exc.value.code == "ner_not_installed" and int(exc.value.exit_code) == 6


def test_missing_model_fails_before_presidio_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(presidio_ner, "_installed", lambda module: module == presidio_ner.PACKAGE)
    imported: list[str] = []
    monkeypatch.setattr(presidio_ner.importlib, "import_module", imported.append)
    with pytest.raises(DetectorUnavailableError) as exc:
        PresidioDetector(PresidioSettings(enabled=True, model="en_core_web_sm"))
    assert exc.value.code == "ner_model_missing"
    assert imported == []  # Presidio (which would download the model) was never constructed


@pytest.mark.skipif(
    presidio_ner._installed(presidio_ner.PACKAGE), reason="presidio installed in this env"
)
def test_real_environment_without_extra_fails(tmp_path: Path) -> None:
    src = tmp_path / "in.log"
    src.write_text(TEXT + "\n", encoding="utf-8")
    out = tmp_path / "out.log"
    policy = load_policy_text(NER_POLICY)
    with pytest.raises(DetectorUnavailableError) as exc:
        sanitize_file(src, out, policy, ctx(), SanitizeOptions(apply=True))
    assert exc.value.code == "ner_not_installed"
    assert not out.exists()


def _fake_presidio(monkeypatch: pytest.MonkeyPatch, *, fail: bool) -> dict[str, object]:
    seen: dict[str, object] = {}

    class Provider:
        def __init__(self, nlp_configuration: dict[str, object]) -> None:
            seen["config"] = nlp_configuration

        def create_engine(self) -> str:
            if fail:
                raise RuntimeError(f"cannot load model for {NAME}")
            return "engine"

    class Engine:
        def __init__(self, nlp_engine: str, supported_languages: list[str]) -> None:
            seen["engine"] = (nlp_engine, supported_languages)

    analyzer_mod = types.ModuleType("presidio_analyzer")
    analyzer_mod.AnalyzerEngine = Engine  # type: ignore[attr-defined]
    nlp_mod = types.ModuleType("presidio_analyzer.nlp_engine")
    nlp_mod.NlpEngineProvider = Provider  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", analyzer_mod)
    monkeypatch.setitem(sys.modules, "presidio_analyzer.nlp_engine", nlp_mod)
    monkeypatch.setattr(presidio_ner, "_installed", lambda module: True)
    return seen


def test_construction_uses_the_installed_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _fake_presidio(monkeypatch, fail=False)
    engine = load_analyzer("en", "en_core_web_sm")
    assert isinstance(engine, object) and seen["engine"] == ("engine", ["en"])
    assert seen["config"] == {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }


def test_construction_error_message_is_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_presidio(monkeypatch, fail=True)
    with pytest.raises(DetectorUnavailableError) as exc:
        load_analyzer("en", "en_core_web_sm")
    assert exc.value.code == "ner_init_failed"
    assert NAME not in str(exc.value) and exc.value.__cause__ is None


# --------------------------------------------------------------------------- detection


def test_findings_map_entities_and_carry_no_values(fake: FakeAnalyzer) -> None:
    det = PresidioDetector(PresidioSettings(enabled=True, min_score=0.5))
    findings = det.detect(_item(TEXT))
    assert [(f.category, f.location.span) for f in findings] == [
        ("pii.person_name", (TEXT.index(NAME), TEXT.index(NAME) + len(NAME))),
        ("location.coarse", (TEXT.index("Springfield"), len(TEXT))),
    ]
    assert all(f.detector == "presidio_ner" for f in findings)
    assert findings[0].evidence == ("ner_entity", "entity:person")
    assert NAME not in repr(findings) and "Springfield" not in repr(findings)
    call = fake.calls[0]
    assert call["language"] == "en" and call["score_threshold"] == 0.5
    assert sorted(call["entities"]) == ["LOCATION", "PERSON"]  # type: ignore[arg-type]


def test_unmapped_bad_spans_and_own_tokens_are_ignored(fake: FakeAnalyzer) -> None:
    text = "seen [REDACTED:pii.person_name] and Mx Other"
    fake.results = [
        Result("PERSON", 5, 31, 0.9),  # CipherGate marker
        Result("NRP", 36, 44, 0.9),  # not mapped by the policy
        Result("PERSON", 40, 99, 0.9),  # span outside the text
        Result("PERSON", 36, 44, 0.9),
    ]
    det = PresidioDetector(PresidioSettings(enabled=True))
    assert [f.location.span for f in det.detect(_item(text))] == [(36, 44)]


def test_non_text_values_are_not_sent(fake: FakeAnalyzer) -> None:
    det = PresidioDetector(PresidioSettings(enabled=True))
    for value in (None, True, 12345, "", "x", "1234-5678"):
        assert det.detect(_item(value)) == []
    assert fake.calls == []


def test_analyzer_errors_are_replaced(fake: FakeAnalyzer) -> None:
    fake.error = ValueError(f"bad token near {NAME}")
    det = PresidioDetector(PresidioSettings(enabled=True))
    with pytest.raises(DetectionError) as exc:
        det.detect(_item(TEXT))
    assert exc.value.code == "ner_failed" and NAME not in str(exc.value)


def test_pipeline_redacts_and_policy_still_decides(fake: FakeAnalyzer, tmp_path: Path) -> None:
    src = tmp_path / "in.log"
    src.write_text(TEXT + "\n", encoding="utf-8")
    out = tmp_path / "out.log"
    policy = load_policy_text(NER_POLICY)
    report = sanitize_file(src, out, policy, ctx(), SanitizeOptions(apply=True))
    assert report.ok
    text = out.read_text(encoding="utf-8")
    assert NAME not in text and "Springfield" not in text
    assert "[REDACTED:pii.person_name]" in text
    assert report.summary["by_detector"].get("presidio_ner") == 2
    assert NAME not in str(report.to_dict())

    blocking = load_policy_text(
        NER_POLICY.replace(
            "rules:\n",
            "rules:\n"
            "  - id: block-ner-names\n"
            "    priority: 500\n"
            "    match: {detectors: [presidio_ner], categories: [pii.person_name]}\n"
            "    action: block\n",
        )
    )
    blocked = inspect_file(src, blocking, ctx(), fmt=InputFormat.TEXT)
    assert blocked.exit_code == 1


# --------------------------------------------------------------------------- validation


def test_validation_warns_and_checks_categories() -> None:
    policy = load_policy_text(NER_POLICY)
    assert any("presidio" in w for w in policy.warnings)
    with pytest.raises(PolicyValidationError) as exc:
        load_policy_text(
            NER_POLICY.replace(
                "min_score: 0.5}", "min_score: 0.5, entities: {PERSON: pii.not_a_category}}"
            )
        )
    assert any(i.code == "unknown_category" for i in exc.value.issues)
    for bad in ("entities: {person: pii.person_name}", "entities: {}", "model: ../evil"):
        with pytest.raises(PolicyValidationError):
            load_policy_text(NER_POLICY.replace("min_score: 0.5}", f"min_score: 0.5, {bad}}}"))


def test_rule_cannot_reference_ner_when_disabled() -> None:
    text = MINIMAL_POLICY.replace(
        "match: {categories: [credential.secret]}",
        "match: {categories: [credential.secret], detectors: [presidio_ner]}",
    )
    with pytest.raises(PolicyValidationError):
        load_policy_text(text)
