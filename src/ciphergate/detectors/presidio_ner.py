"""Optional local NER detector backed by Microsoft Presidio (``pip install 'ciphergate[ner]'``).

Off by default; enabled only by ``detectors.presidio.enabled: true`` in the policy. Safety:

* Never downloads anything. Presidio's spaCy engine downloads a missing model on first use, so
  the configured spaCy model package must already be importable; otherwise the run fails with
  ``ner_model_missing`` before Presidio is imported or constructed. (CipherGate does not import
  network libraries at all, so it cannot police third-party code beyond this check.)
* Missing package or model fails the run (exit 6); it never silently runs without NER.
* Like every detector it only reports candidates (entity type, score, span). It cannot allow a
  value: decisions stay with the policy engine, so explicit block/review rules still win.
* Presidio errors are replaced by a fixed message; its exception text is never shown.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
from typing import Any

from ciphergate.detectors.base import is_ciphergate_token, make_finding
from ciphergate.errors import DetectionError, DetectorUnavailableError
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.models.policy import PresidioSettings

DETECTOR_ID = "presidio_ner"
PACKAGE = "presidio_analyzer"


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


@functools.lru_cache(maxsize=4)
def load_analyzer(language: str, model: str) -> Any:
    """Build (once per process) a Presidio AnalyzerEngine on an already-installed spaCy model."""
    if not _installed(PACKAGE):
        raise DetectorUnavailableError(
            "detectors.presidio is enabled but the optional NER extra is not installed "
            "(pip install 'ciphergate[ner]')",
            code="ner_not_installed",
        )
    if not _installed(model):
        raise DetectorUnavailableError(
            "detectors.presidio is enabled but its spaCy model is not installed; CipherGate "
            "never downloads models, install it yourself (see docs/detector-coverage.md)",
            code="ner_model_missing",
        )
    try:
        analyzer_mod = importlib.import_module(PACKAGE)
        nlp_mod = importlib.import_module(f"{PACKAGE}.nlp_engine")
        provider = nlp_mod.NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": model}],
            }
        )
        return analyzer_mod.AnalyzerEngine(
            nlp_engine=provider.create_engine(), supported_languages=[language]
        )
    except DetectorUnavailableError:
        raise
    except Exception:  # noqa: BLE001 - third-party messages may contain anything; replace them
        raise DetectorUnavailableError(
            "the optional NER detector could not be initialised", code="ner_init_failed"
        ) from None


class PresidioDetector:
    id = DETECTOR_ID

    def __init__(self, settings: PresidioSettings, analyzer: Any | None = None) -> None:
        self.settings = settings
        self.entities = dict(settings.entities)
        self.analyzer = analyzer or load_analyzer(settings.language, settings.model)

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text or len(text) < 2 or not any(c.isalpha() for c in text):
            return []
        try:
            results = self.analyzer.analyze(
                text=text,
                language=self.settings.language,
                entities=list(self.entities),
                score_threshold=self.settings.min_score,
            )
        except Exception:  # noqa: BLE001 - never forward third-party messages (may echo input)
            raise DetectionError("the optional NER detector failed", code="ner_failed") from None
        out: list[Finding] = []
        for result in results:
            category = self.entities.get(str(result.entity_type))
            start, end = int(result.start), int(result.end)
            if category is None or not 0 <= start < end <= len(text):
                continue
            if is_ciphergate_token(text[start:end].strip("\"'")):
                continue
            out.append(
                make_finding(
                    item,
                    category=category,
                    detector=self.id,
                    confidence=float(result.score),
                    evidence=("ner_entity", f"entity:{str(result.entity_type).lower()}"),
                    span=(start, end),
                )
            )
        return out
