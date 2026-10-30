"""Builds the per-run detector set from policy settings (no global mutable registry)."""

from __future__ import annotations

from dataclasses import dataclass

from ciphergate.detectors.base import Detector, make_finding
from ciphergate.detectors.custom_regex import CustomRegexDetector
from ciphergate.detectors.dates import DateDetector
from ciphergate.detectors.email import EmailDetector, is_reserved_email_domain
from ciphergate.detectors.field_names import FieldNameDetector, PolicyClassificationDetector
from ciphergate.detectors.iban import IbanDetector
from ciphergate.detectors.ip_address import IPAddressDetector
from ciphergate.detectors.mac_address import MacAddressDetector
from ciphergate.detectors.network import InternalHostDetector
from ciphergate.detectors.payment_card import PaymentCardDetector
from ciphergate.detectors.phone import PhoneDetector
from ciphergate.detectors.secrets import PEM_BEGIN_RE, PEM_END_RE, SecretDetector
from ciphergate.detectors.ssn import SsnDetector
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.models.policy import DetectorSettings, PolicyDocument

BUILTIN_DETECTOR_IDS: tuple[str, ...] = (
    "field_name",
    "secret_pattern",
    "luhn_card",
    "ip_address",
    "date_pattern",
    "email_regex",
    "internal_host",
    "phone_pattern",
    "mac_address",
    "iban",
    "ssn_pattern",
)

# Phone matching is the least specific pattern; drop phone spans that overlap these detectors.
_PHONE_SUPPRESSORS = frozenset(
    {
        "luhn_card",
        "ip_address",
        "date_pattern",
        "secret_pattern",
        "mac_address",
        "iban",
        "ssn_pattern",
    }
)


FIELD_CONTEXT_DETECTORS = frozenset({"field_name", "policy_classification"})


@dataclass(slots=True)
class TextBlockState:
    """Cross-line state for text/log input (multi-line PEM private key blocks)."""

    in_private_key_block: bool = False


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


class DetectorSet:
    def __init__(self, settings: DetectorSettings, document: PolicyDocument | None = None) -> None:
        disabled = set(settings.disabled)
        detectors: list[Detector] = []
        factories: dict[str, Detector] = {
            "field_name": FieldNameDetector(),
            "secret_pattern": SecretDetector(),
            "luhn_card": PaymentCardDetector(),
            "ip_address": IPAddressDetector(),
            "date_pattern": DateDetector(emit_generic=settings.dates_emit_generic),
            "email_regex": EmailDetector(),
            "internal_host": InternalHostDetector(settings.internal_host_suffixes),
            "phone_pattern": PhoneDetector(),
            "mac_address": MacAddressDetector(),
            "iban": IbanDetector(),
            "ssn_pattern": SsnDetector(),
        }
        for detector_id in BUILTIN_DETECTOR_IDS:
            if detector_id not in disabled:
                detectors.append(factories[detector_id])
        if document is not None and document.classifications:
            detectors.append(PolicyClassificationDetector(document.classifications))
        detectors.extend(CustomRegexDetector(spec) for spec in settings.custom)
        if settings.presidio.enabled:
            # Imported lazily: the base install never imports the optional NER code path.
            from ciphergate.detectors.presidio_ner import PresidioDetector  # noqa: PLC0415

            detectors.append(PresidioDetector(settings.presidio))
        self.detectors = tuple(detectors)
        self.ids = tuple(d.id for d in detectors)

    def scan(self, item: ScanItem) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(item))
        return self._post_process(findings)

    def scan_field_context(self, item: ScanItem) -> list[Finding]:
        """Only the detectors that judge a value by its field name/path (logfmt keys)."""
        findings: list[Finding] = []
        for detector in self.detectors:
            if detector.id in FIELD_CONTEXT_DETECTORS:
                findings.extend(detector.detect(item))
        return findings

    def scan_text_line(self, item: ScanItem, state: TextBlockState) -> list[Finding]:
        """Scan one text/log line, tracking multi-line private key blocks across lines."""
        text = item.text or ""
        findings = self.scan(item)
        if "secret_pattern" not in self.ids:
            return findings
        if state.in_private_key_block:
            findings = [f for f in findings if f.category != "credential.secret"]
            findings.append(
                make_finding(
                    item,
                    category="credential.secret",
                    detector="secret_pattern",
                    confidence=0.99,
                    evidence=("pattern_match", "family:private_key_block"),
                    span=(0, len(text)) if text else None,
                )
            )
            if PEM_END_RE.search(text):
                state.in_private_key_block = False
            return self._post_process(findings)
        begins = list(PEM_BEGIN_RE.finditer(text))
        begin = begins[-1] if begins else None
        if begin is not None and not PEM_END_RE.search(text, begin.end()):
            state.in_private_key_block = True
        return findings

    def post_process(self, findings: list[Finding]) -> list[Finding]:
        """Phone suppression and de-duplication (used for combined logfmt findings)."""
        return self._post_process(findings)

    @staticmethod
    def dedupe(findings: list[Finding]) -> list[Finding]:
        """Drop exact duplicates (same category, detector and span), keeping order."""
        out: list[Finding] = []
        seen: set[tuple[str, str, tuple[int, int] | None]] = set()
        for f in findings:
            key = (f.category, f.detector, f.location.span)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    @staticmethod
    def _post_process(findings: list[Finding]) -> list[Finding]:
        if not findings:
            return findings
        strong = [
            f.location.span
            for f in findings
            if f.detector in _PHONE_SUPPRESSORS and f.location.span is not None
        ] + [
            f.location.span
            for f in findings
            if f.category == "pii.email"
            and f.location.span is not None
            # Field-context findings cover a whole value; they must not hide a phone inside it.
            and f.detector not in FIELD_CONTEXT_DETECTORS
        ]
        out: list[Finding] = []
        seen: set[tuple[str, str, tuple[int, int] | None]] = set()
        for f in findings:
            span = f.location.span
            if (
                f.detector == "phone_pattern"
                and span is not None
                and any(_overlaps(span, s) for s in strong)
            ):
                continue
            key = (f.category, f.detector, span)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


def unsafe_replacement_reason(value: str) -> str | None:
    """Why a configured replacement constant looks like a real identifier or secret, if it does."""
    probe = ScanItem(record_index=0, line=None, field_path="", field_name=None, value=value)
    secrets = SecretDetector().detect(probe)
    if secrets:
        return f"looks like a credential ({secrets[0].evidence[-1]})"
    if PaymentCardDetector().detect(probe):
        return "looks like a payment card number"
    if IbanDetector().detect(probe):
        return "looks like a real IBAN"
    if MacAddressDetector().detect(probe):
        return "looks like a real MAC address"
    if SsnDetector().detect(probe):
        return "looks like a real government identifier"
    for f in EmailDetector().detect(probe):
        if "reserved_domain" not in f.evidence:
            return "email replacements must use a reserved domain such as example.invalid"
    for f in IPAddressDetector().detect(probe):
        if "documentation_range" not in f.evidence:
            return "IP replacements must use a documentation range (192.0.2.0/24, 2001:db8::/32)"
    for f in PhoneDetector().detect(probe):
        if f.confidence >= 0.5:
            return "looks like a real phone number; use an obviously synthetic value"
    return None


__all__ = [
    "BUILTIN_DETECTOR_IDS",
    "DetectorSet",
    "TextBlockState",
    "is_reserved_email_domain",
    "unsafe_replacement_reason",
]
