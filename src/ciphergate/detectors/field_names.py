"""Field-name heuristics and policy-declared field classifications.

Matching is token-based on a normalized name (camelCase/kebab-case/spaces -> snake_case, lowercase).
A term matches when the normalized name equals it, or — for suffix-capable terms — ends with
``_<term>``. The longest matching term wins, so ``server_ip_address`` is an IP address rather
than a postal address. Names like ``token_count``, ``key_name`` or ``monkey`` deliberately do not
match: this is a heuristic, not a universal dictionary.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from ciphergate.detectors.base import is_ciphergate_token, make_finding
from ciphergate.models.finding import Finding, ScanItem
from ciphergate.models.policy import Classification

_CAMEL_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


def normalize_field_name(name: str) -> str:
    s = _CAMEL_2.sub(r"\1_\2", name)
    s = _CAMEL_1.sub(r"\1_\2", s)
    return _NON_ALNUM.sub("_", s).strip("_").lower()


@dataclass(frozen=True, slots=True)
class _Term:
    term: str
    category: str
    confidence: float
    suffix: bool


def _terms(category: str, confidence: float, suffix: str = "", exact: str = "") -> list[_Term]:
    out = [_Term(t, category, confidence, True) for t in suffix.split()]
    out += [_Term(t, category, confidence, False) for t in exact.split()]
    return out


_TERMS: list[_Term] = [
    *_terms(
        "credential.secret",
        0.85,
        suffix="password passwd passphrase pwd secret api_key apikey access_token refresh_token "
        "auth_token id_token bearer_token session_token private_key client_secret secret_key "
        "access_key authorization credentials connection_string conn_str x_api_key",
    ),
    *_terms("credential.secret", 0.6, exact="token"),
    *_terms(
        "pii.email", 0.8, suffix="email e_mail email_address mail_address", exact="emails mail"
    ),
    *_terms(
        "pii.phone",
        0.75,
        suffix="phone phone_number mobile mobile_number telephone contact_number fax cell_phone",
        exact="tel msisdn phones",
    ),
    *_terms(
        "pii.person_name",
        0.7,
        suffix="first_name last_name full_name given_name family_name surname middle_name "
        "patient_name employee_name customer_name contact_name maiden_name",
    ),
    *_terms("pii.person_name", 0.45, exact="name"),
    *_terms("pii.date_of_birth", 0.85, suffix="dob date_of_birth birth_date birthdate birthday"),
    *_terms(
        "pii.payment_card",
        0.85,
        suffix="card_number cc_number credit_card credit_card_number cvv cvc card_cvv",
        exact="pan",
    ),
    *_terms(
        "pii.bank_account",
        0.8,
        suffix="bank_account bank_account_number account_number iban routing_number sort_code",
    ),
    *_terms(
        "pii.government_id",
        0.85,
        suffix="ssn social_security_number national_id tax_id passport_number drivers_license "
        "national_insurance_number",
        exact="passport nino",
    ),
    *_terms(
        "health.phi",
        0.75,
        suffix="diagnosis medication medications medical_record medical_record_number patient_id "
        "icd_code procedure_code allergies prescription clinical_notes",
        exact="mrn patient condition claim claim_id",
    ),
    *_terms(
        "pii.precise_location",
        0.75,
        suffix="latitude longitude gps coordinates geo_location geolocation",
        exact="lat lon lng",
    ),
    *_terms(
        "pii.address",
        0.7,
        suffix="address street street_address home_address mailing_address postal_address",
        exact="postal_code zip zip_code postcode",
    ),
    *_terms(
        "pii.ip_address",
        0.8,
        suffix="ip ip_address client_ip remote_addr ipv4 ipv6 source_ip x_forwarded_for",
    ),
    *_terms(
        "pii.device_identifier",
        0.7,
        suffix="device_id mac_address imei advertising_id idfa serial_number device_token",
    ),
    *_terms(
        "pii.customer_identifier",
        0.7,
        suffix="user_id customer_id account_id member_id subscriber_id username user_name "
        "remote_user",
        exact="login",
    ),
    *_terms(
        "employment.sensitive",
        0.7,
        suffix="employee_id salary performance_rating hr_case_id",
    ),
    *_terms(
        "financial.sensitive",
        0.6,
        suffix="balance account_balance credit_score transaction_amount income",
    ),
    *_terms(
        "network.telemetry",
        0.6,
        suffix="trace_id request_id session_id span_id correlation_id hostname",
        exact="host",
    ),
]


def classify_field_name(name: str) -> _Term | None:
    normalized = normalize_field_name(name)
    if not normalized:
        return None
    best: _Term | None = None
    for term in _TERMS:
        hit = normalized == term.term or (term.suffix and normalized.endswith("_" + term.term))
        if hit and (best is None or len(term.term) > len(best.term)):
            best = term
    return best


def _has_protectable_value(item: ScanItem) -> bool:
    if item.is_empty:
        return False
    return not (isinstance(item.value, str) and is_ciphergate_token(item.value))


class FieldNameDetector:
    id = "field_name"

    def detect(self, item: ScanItem) -> list[Finding]:
        if item.in_key or not item.field_name or not _has_protectable_value(item):
            return []
        term = classify_field_name(item.field_name)
        if term is None:
            return []
        evidence = (
            ("field_name_match",)
            if not term.suffix or normalize_field_name(item.field_name) == term.term
            else ("field_name_match", "field_name_suffix")
        )
        return [
            make_finding(
                item,
                category=term.category,
                detector=self.id,
                confidence=term.confidence,
                evidence=evidence,
            )
        ]


class PolicyClassificationDetector:
    """Emits findings for fields the policy explicitly classifies (e.g. ``admission_date``)."""

    id = "policy_classification"

    def __init__(self, classifications: list[Classification]) -> None:
        self._rules = [
            (
                c,
                frozenset(normalize_field_name(n) for n in c.field_names),
                tuple(c.field_paths),
            )
            for c in classifications
        ]

    def detect(self, item: ScanItem) -> list[Finding]:
        if item.in_key or not self._rules or not _has_protectable_value(item):
            return []
        normalized = normalize_field_name(item.field_name) if item.field_name else ""
        out: list[Finding] = []
        for rule, names, paths in self._rules:
            by_name = bool(normalized) and normalized in names
            by_path = any(fnmatch.fnmatchcase(item.field_path, p) for p in paths)
            if by_name or by_path:
                out.append(
                    make_finding(
                        item,
                        category=rule.category,
                        detector=self.id,
                        confidence=rule.confidence,
                        evidence=("policy_classification", f"classification:{rule.id}"),
                    )
                )
        return out
