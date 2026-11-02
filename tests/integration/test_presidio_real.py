"""The optional NER detector against a real Presidio install (skipped unless one is present).

The unit tests in ``tests/unit/test_presidio_ner.py`` use a fake engine. These run the real
``presidio-analyzer`` with the small ``en_core_web_sm`` spaCy model. Install both yourself to run
them (CI does this in the ``ner`` job); CipherGate never downloads a model. The NER model is
statistical, so the assertions use common, clearly person-like synthetic names and check that
something was found, not exact scores.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate.cli import app
from ciphergate.detectors import presidio_ner
from ciphergate.detectors.presidio_ner import PresidioDetector, load_analyzer
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import PresidioSettings
from tests.conftest import MINIMAL_POLICY

MODEL = "en_core_web_sm"
# CI sets this so a broken install fails the job instead of silently skipping every test.
REQUIRED = os.environ.get("CIPHERGATE_REQUIRE_NER") == "1"

pytestmark = [
    pytest.mark.skipif(
        not REQUIRED and importlib.util.find_spec("presidio_analyzer") is None,
        reason="optional 'ner' extra (presidio-analyzer) not installed",
    ),
    pytest.mark.skipif(
        not REQUIRED and importlib.util.find_spec(MODEL) is None,
        reason=f"spaCy model {MODEL} not installed",
    ),
]

NAME = "John Smith"  # synthetic; a common name the small model recognises reliably
TEXT = f"ticket opened by {NAME} in London after the export failed\n"

NER_POLICY = MINIMAL_POLICY.replace(
    "settings: {strict: false}\n",
    "settings: {strict: false}\n"
    "detectors:\n"
    f"  presidio: {{enabled: true, model: {MODEL}, min_score: 0.5}}\n",
).replace(
    "defaults:\n",
    "  - id: redact-coarse-location\n"
    "    priority: 100\n"
    "    match: {categories: [location.coarse]}\n"
    "    action: redact\n"
    "defaults:\n",
)

runner = CliRunner()


@pytest.fixture
def fresh_analyzer() -> Iterator[None]:
    # Build the engine inside each test, so the no-network test covers construction too.
    load_analyzer.cache_clear()
    yield
    load_analyzer.cache_clear()


def _item(text: str) -> ScanItem:
    return ScanItem(record_index=0, line=1, field_path="", field_name=None, value=text)


def test_real_engine_finds_a_person_and_a_place(fresh_analyzer: None) -> None:
    detector = PresidioDetector(PresidioSettings(enabled=True, model=MODEL, min_score=0.5))
    findings = detector.detect(_item(TEXT))
    spans = {
        TEXT[f.location.span[0] : f.location.span[1]]: f.category
        for f in findings
        if f.location.span
    }
    assert spans.get(NAME) == "pii.person_name"
    assert spans.get("London") == "location.coarse"
    assert all(f.detector == "presidio_ner" and 0 < f.confidence <= 1 for f in findings)


def test_real_engine_ignores_text_without_entities(fresh_analyzer: None) -> None:
    detector = PresidioDetector(PresidioSettings(enabled=True, model=MODEL, min_score=0.5))
    assert detector.detect(_item("export failed with status 500 after 3 retries")) == []


def test_sanitize_with_real_ner_removes_the_name_offline(
    fresh_analyzer: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def deny(*_: object, **__: object) -> None:
        raise AssertionError("network access attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, deny)

    policy = tmp_path / "ner.yml"
    policy.write_text(NER_POLICY, encoding="utf-8")
    src = tmp_path / "app.log"
    src.write_text(TEXT, encoding="utf-8")
    out, report = tmp_path / "out.log", tmp_path / "report.json"
    r = runner.invoke(
        app,
        [
            *("sanitize", str(src), "--policy", str(policy), "-o", str(out)),
            *("--report", str(report), "--apply"),
        ],
    )
    assert r.exit_code == 0, r.stdout
    sanitized = out.read_text(encoding="utf-8")
    assert NAME not in sanitized and "London" not in sanitized
    assert "[REDACTED:pii.person_name]" in sanitized
    assert "export failed" in sanitized  # the debugging context survives
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["by_category"].get("pii.person_name", 0) >= 1
    for text in (r.stdout, report.read_text(encoding="utf-8")):
        assert NAME not in text and "London" not in text


def test_missing_model_fails_closed_with_the_real_package(
    fresh_analyzer: None, tmp_path: Path
) -> None:
    policy = tmp_path / "ner.yml"
    policy.write_text(NER_POLICY.replace(MODEL, "en_core_web_not_installed"), encoding="utf-8")
    src = tmp_path / "app.log"
    src.write_text(TEXT, encoding="utf-8")
    out = tmp_path / "out.log"
    args = ["sanitize", str(src), "--policy", str(policy), "-o", str(out), "--apply"]
    r = runner.invoke(app, args)
    assert r.exit_code == 6 and "ner_model_missing" in r.stdout + r.stderr
    assert not out.exists()
    assert presidio_ner._installed("presidio_analyzer")
