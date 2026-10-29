"""Stable identifiers shared across CipherGate: context values, categories, actions, codes."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Environment(StrEnum):
    """Where the source data originated (policy context only; never verified)."""

    DEV = "dev"
    STG = "stg"
    PRD = "prd"
    UNKNOWN = "unknown"


class TargetEnvironment(StrEnum):
    """Where the output will be used, when that is an application environment."""

    DEV = "dev"
    STG = "stg"
    PRD = "prd"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class Destination(StrEnum):
    """The actual intended recipient/channel of the output."""

    LOCAL_DEV = "local_dev"
    APPROVED_INTERNAL = "approved_internal"
    STAGING_TEST = "staging_test"
    PRODUCTION_MONITORING = "production_monitoring"
    EXTERNAL_VENDOR = "external_vendor"
    EXTERNAL_AI = "external_ai"
    PUBLIC_REPOSITORY = "public_repository"
    UNKNOWN = "unknown"


# Destinations that receive data outside the organisation's control, or whose trust is unknown.
UNTRUSTED_DESTINATIONS: frozenset[Destination] = frozenset(
    {
        Destination.EXTERNAL_VENDOR,
        Destination.EXTERNAL_AI,
        Destination.PUBLIC_REPOSITORY,
        Destination.UNKNOWN,
    }
)
NON_PRODUCTION_DESTINATIONS: frozenset[Destination] = frozenset(
    {Destination.LOCAL_DEV, Destination.STAGING_TEST}
)


class DomainProfile(StrEnum):
    DEVELOPER_LOGS = "developer_logs"
    TEST_DATASET = "test_dataset"
    HEALTHCARE = "healthcare"
    FINANCIAL = "financial"
    GENERAL = "general"


class UseCase(StrEnum):
    DEBUGGING = "debugging"
    ANALYTICS = "analytics"
    TRAINING = "training"
    EXTERNAL_LLM = "external_llm"
    SUPPORT_BUNDLE = "support_bundle"
    TEST_FIXTURE = "test_fixture"
    MONITORING = "monitoring"
    INCIDENT_RESPONSE = "incident_response"


class InputFormat(StrEnum):
    CSV = "csv"
    JSON = "json"
    JSONL = "jsonl"
    TEXT = "text"
    LOGFMT = "logfmt"
    JSONLOG = "jsonlog"
    ACCESSLOG = "accesslog"
    SYSLOG = "syslog"
    STACKTRACE = "stacktrace"


# Line-oriented formats: each line is scanned as text and rewritten span by span.
LINE_FORMATS = frozenset(
    {
        InputFormat.TEXT,
        InputFormat.LOGFMT,
        InputFormat.JSONLOG,
        InputFormat.ACCESSLOG,
        InputFormat.SYSLOG,
        InputFormat.STACKTRACE,
    }
)

# Findings for stack-trace frames and source lines (--format stacktrace); not a DetectorSet member.
STACK_TRACE_DETECTOR = "stack_trace"


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    REPLACE = "replace"
    PSEUDONYMIZE = "pseudonymize"
    GENERALIZE = "generalize"
    DATE_SHIFT = "date_shift"
    DROP_FIELD = "drop_field"
    DROP_RECORD = "drop_record"
    BLOCK = "block"
    REVIEW = "review"


# Higher rank = more protective. Used to combine several decisions on the same value.
ACTION_RANK: dict[Action, int] = {
    Action.BLOCK: 100,
    Action.REVIEW: 90,
    Action.DROP_RECORD: 80,
    Action.DROP_FIELD: 70,
    Action.REDACT: 60,
    Action.REPLACE: 50,
    Action.PSEUDONYMIZE: 40,
    Action.GENERALIZE: 30,
    Action.DATE_SHIFT: 20,
    Action.ALLOW: 0,
}

# Actions that change a value in place (as opposed to removing it or stopping the run).
VALUE_TRANSFORM_ACTIONS: frozenset[Action] = frozenset(
    {Action.REDACT, Action.REPLACE, Action.PSEUDONYMIZE, Action.GENERALIZE, Action.DATE_SHIFT}
)

CREDENTIAL_CATEGORY = "credential.secret"
UNKNOWN_CANDIDATE_CATEGORY = "unknown.sensitive_candidate"

BUILTIN_CATEGORIES: frozenset[str] = frozenset(
    {
        "credential.secret",
        "pii.email",
        "pii.phone",
        "pii.person_name",
        "pii.government_id",
        "pii.payment_card",
        "pii.bank_account",
        "pii.address",
        "pii.date_of_birth",
        "pii.precise_location",
        "pii.ip_address",
        "pii.device_identifier",
        "pii.customer_identifier",
        "health.phi",
        "financial.sensitive",
        "employment.sensitive",
        "network.telemetry",
        "proprietary.source",
        "security.internal",
        "location.coarse",
        "identifier.generic",
        "unknown.sensitive_candidate",
        "date.generic",
    }
)

# Categories for which an `allow` toward an untrusted destination requires explicit acknowledgement,
# and which the residual rescan gate fails on by default.
HIGH_RISK_CATEGORIES: frozenset[str] = frozenset(
    {
        "credential.secret",
        "pii.email",
        "pii.phone",
        "pii.person_name",
        "pii.government_id",
        "pii.payment_card",
        "pii.bank_account",
        "pii.address",
        "pii.date_of_birth",
        "pii.precise_location",
        "pii.customer_identifier",
        "health.phi",
        "financial.sensitive",
        "employment.sensitive",
        "unknown.sensitive_candidate",
    }
)

# Custom categories in these families are treated as high-risk too (e.g. ``pii.member_number``).
HIGH_RISK_FAMILIES: frozenset[str] = frozenset(
    {"credential", "pii", "health", "financial", "employment", "unknown"}
)

# Detectors that must stay enabled for strict or untrusted-destination runs (credential coverage).
CREDENTIAL_DETECTORS: frozenset[str] = frozenset({"secret_pattern", "field_name"})

# Actions permitted for credential findings. Everything else is a hard-constraint violation.
CREDENTIAL_PERMITTED_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.BLOCK,
        Action.REVIEW,
        Action.REDACT,
        Action.REPLACE,
        Action.PSEUDONYMIZE,
        Action.DROP_FIELD,
        Action.DROP_RECORD,
    }
)


class ReasonCode(StrEnum):
    """Stable, machine-readable reason codes. They never contain values."""

    CREDENTIAL_DETECTED_HARD_BLOCK = "credential_detected_hard_block"
    EXPLICIT_HARD_BLOCK = "explicit_hard_block"
    ENVIRONMENT_GUARDRAIL = "environment_guardrail"
    EXPLICIT_POLICY_MATCH = "explicit_policy_match"
    PROFILE_DEFAULT = "profile_default"
    FIELD_NAME_SENSITIVE = "field_name_sensitive"
    VALUE_PATTERN_MATCH = "value_pattern_match"
    CONFIDENCE_BELOW_RULE_THRESHOLD = "confidence_below_rule_threshold"
    NO_APPLICABLE_RULE_REQUIRES_REVIEW = "no_applicable_rule_requires_review"
    NO_APPLICABLE_RULE_BLOCKS = "no_applicable_rule_blocks"
    HIGH_RISK_ALLOW_REQUIRES_ACKNOWLEDGEMENT = "high_risk_allow_requires_acknowledgement"
    UNSUPPORTED_TRANSFORM = "unsupported_transform"
    DESTINATION_REQUIRED_BUT_MISSING = "destination_required_but_missing"
    ENVIRONMENT_REQUIRED_BUT_MISSING = "environment_required_but_missing"
    TARGET_ENVIRONMENT_REQUIRED_BUT_MISSING = "target_environment_required_but_missing"
    ENVIRONMENT_CONTEXT_CONFLICT = "environment_context_conflict"
    UNSUPPORTED_ENVIRONMENT = "unsupported_environment"
    UNKNOWN_CONTEXT_REQUIRES_REVIEW = "unknown_context_requires_review"
    PRD_TO_NONPRODUCTION_BLOCKED = "prd_to_nonproduction_transfer_blocked"
    PRD_TO_NONPRODUCTION_APPROVED = "prd_to_nonproduction_transfer_approved"
    STRICT_POLICY_REQUIRED = "strict_policy_required_for_destination"
    RESCAN_REQUIRED = "rescan_required_for_destination"
    CREDENTIAL_DETECTION_REQUIRED = "credential_detection_required"
    KEY_SCAN_REQUIRED = "json_key_scan_required"
    POLICY_CONFLICT = "policy_conflict"
    KEY_MISSING = "key_missing"
    KEY_INVALID = "key_invalid"
    PARSE_ERROR = "parse_error"
    SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
    RESIDUAL_FINDING = "residual_finding"


class ExitCode(IntEnum):
    OK = 0
    BLOCKED = 1
    USAGE = 2
    POLICY_INVALID = 3
    INPUT_ERROR = 4
    OUTPUT_ERROR = 5
    KEY_OR_TRANSFORM_CONFIG = 6
    RESCAN_FAILED = 7
    INTERNAL = 8
    INTERRUPTED = 130


def confidence_band(confidence: float) -> str:
    """Named band for a confidence estimate. Bands are engineering estimates, not probabilities."""
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


REPORT_SCHEMA = "ciphergate.report/v1"
PSEUDONYM_VERSION = "pz1"
DEFAULT_KEY_ENV = "CIPHERGATE_HMAC_KEY"
MIN_KEY_BYTES = 32

DISCLAIMER = (
    "A successful run means the configured processing completed under the selected policy. "
    "It does not prove that the output contains no sensitive information; "
    "detectors can miss values."
)
