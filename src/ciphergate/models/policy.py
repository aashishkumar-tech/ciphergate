"""Typed, strict schema for human-authored YAML policies (``policy_version: 1``).

Unknown keys are rejected everywhere except inside ``metadata``. Semantic checks that span
several fields (conflicts, risky allowances, key references) live in
``ciphergate.policy.validator``.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ciphergate.constants import (
    DEFAULT_KEY_ENV,
    Action,
    Destination,
    DomainProfile,
    Environment,
    InputFormat,
    TargetEnvironment,
    UseCase,
)

SLUG_RE = r"^[a-z0-9][a-z0-9_.-]{0,63}$"
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z0-9_]+$")
CATEGORY_SELECTOR_RE = re.compile(r"^(\*|[a-z][a-z0-9_]*\.\*|[a-z][a-z0-9_]*\.[a-z0-9_]+)$")
ENV_VAR_RE = r"^[A-Z_][A-Z0-9_]{0,127}$"
MARKER_RE = re.compile(r"^\[[A-Z][A-Z0-9_]{0,31}(?::(?:\{category\}|[a-z0-9_.]{1,48}))?\]$")
PREFIX_RE = r"^([a-z][a-z0-9_]{0,31})?$"

Slug = Annotated[str, Field(pattern=SLUG_RE)]
EnvVarName = Annotated[str, Field(pattern=ENV_VAR_RE)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


# --------------------------------------------------------------------------- action parameters


class EmptyParams(StrictModel):
    """Actions that take no parameters."""


class RedactParams(StrictModel):
    marker: str = "[REDACTED:{category}]"

    @field_validator("marker")
    @classmethod
    def _marker_shape(cls, value: str) -> str:
        if not MARKER_RE.match(value):
            raise ValueError(
                "marker must look like [WORD] or [WORD:{category}] / [WORD:label] "
                "(uppercase word, ASCII only) so rescans can recognise it"
            )
        return value


class ReplaceParams(StrictModel):
    value: str | int | float | bool | None

    @field_validator("value")
    @classmethod
    def _bounded(cls, value: str | int | float | bool | None) -> str | int | float | bool | None:
        if isinstance(value, str) and (len(value) > 256 or any(c in value for c in "\r\n\x00")):
            raise ValueError("replacement strings must be at most 256 characters without newlines")
        return value


class PseudonymizeParams(StrictModel):
    key_env: EnvVarName = DEFAULT_KEY_ENV
    scope: Literal["field", "category", "entity"]
    entity: Slug | None = None
    prefix: Annotated[str, Field(pattern=PREFIX_RE)] = ""
    normalize: Literal["nfc", "casefold_nfc", "none"] = "nfc"
    namespace: Slug | None = None

    @model_validator(mode="after")
    def _entity_scope(self) -> PseudonymizeParams:
        if self.scope == "entity" and not self.entity:
            raise ValueError("scope 'entity' requires an 'entity' name")
        if self.scope != "entity" and self.entity:
            raise ValueError("'entity' is only valid with scope 'entity'")
        return self


class GeneralizeParams(StrictModel):
    strategy: Literal["year", "year_month", "age_band", "round_coordinates", "numeric_bin"]
    band_size: Annotated[int, Field(ge=1, le=100)] = 10
    max_age: Annotated[int, Field(ge=1, le=200)] = 120
    decimals: Annotated[int, Field(ge=0, le=4)] = 1
    bins: list[float] | None = None

    @model_validator(mode="after")
    def _bins(self) -> GeneralizeParams:
        if self.strategy == "numeric_bin":
            if not self.bins or len(self.bins) < 2:
                raise ValueError("numeric_bin requires 'bins' with at least two increasing edges")
            if any(b >= a for a, b in zip(self.bins[1:], self.bins, strict=False)):
                raise ValueError("'bins' edges must be strictly increasing")
        elif self.bins is not None:
            raise ValueError("'bins' is only valid with strategy numeric_bin")
        return self


class DateShiftParams(StrictModel):
    key_env: EnvVarName = DEFAULT_KEY_ENV
    max_days: Annotated[int, Field(ge=1, le=3650)]
    scope: Literal["dataset", "entity"] = "dataset"
    entity_field: str | None = None
    formats: list[str] = Field(default_factory=lambda: ["iso"])
    namespace: Slug | None = None

    @model_validator(mode="after")
    def _entity(self) -> DateShiftParams:
        if self.scope == "entity" and not self.entity_field:
            raise ValueError("scope 'entity' requires 'entity_field'")
        if self.scope != "entity" and self.entity_field:
            raise ValueError("'entity_field' is only valid with scope 'entity'")
        if not self.formats:
            raise ValueError("'formats' must not be empty")
        for fmt in self.formats:
            if fmt != "iso" and ("%" not in fmt or len(fmt) > 64):
                raise ValueError("formats must be 'iso' or an explicit strptime pattern")
        return self


ActionParams = (
    EmptyParams
    | RedactParams
    | ReplaceParams
    | PseudonymizeParams
    | GeneralizeParams
    | DateShiftParams
)

PARAM_MODELS: dict[Action, type[StrictModel]] = {
    Action.ALLOW: EmptyParams,
    Action.REDACT: RedactParams,
    Action.REPLACE: ReplaceParams,
    Action.PSEUDONYMIZE: PseudonymizeParams,
    Action.GENERALIZE: GeneralizeParams,
    Action.DATE_SHIFT: DateShiftParams,
    Action.DROP_FIELD: EmptyParams,
    Action.DROP_RECORD: EmptyParams,
    Action.BLOCK: EmptyParams,
    Action.REVIEW: EmptyParams,
}

_REJECTED_ACTIONS = {
    "tokenize": "reversible tokenization is not supported in this release (no token vault); "
    "use 'pseudonymize' for one-way keyed pseudonyms",
    "detokenize": "reversible tokenization is not supported in this release",
    "mask": "partial masking is not supported; use 'redact' or 'replace'",
    "encrypt": "encryption is not supported in this release",
}


def _check_action(value: Any) -> Any:
    if isinstance(value, str) and value in _REJECTED_ACTIONS:
        raise ValueError(_REJECTED_ACTIONS[value])
    return value


# --------------------------------------------------------------------------- policy sections


ContextOverrideField = Literal[
    "environment", "target_environment", "destination", "domain_profile", "use_case"
]


class PolicyContext(StrictModel):
    environment: Environment | None = None
    target_environment: TargetEnvironment | None = None
    destination: Destination | None = None
    domain_profile: DomainProfile | None = None
    use_case: UseCase | None = None
    allow_cli_override: list[ContextOverrideField] = Field(default_factory=list)


class Requirements(StrictModel):
    environment: bool = True
    target_environment: bool = False
    destination: bool = True


class RescanSettings(StrictModel):
    enabled: bool = True
    fail_on_categories: list[str] | None = None


class PolicySettings(StrictModel):
    strict: bool = True
    unknown_sensitive_behavior: Literal["review", "block"] = "review"
    fail_on_parse_error: bool = True
    malformed_record_action: Literal["drop_record"] | None = None
    report_raw_values: Literal[False] = False
    scan_json_keys: bool = False
    csv_duplicate_headers: Literal["reject", "disambiguate"] = "reject"
    preserve_blank_lines: bool = False
    rescan: RescanSettings = Field(default_factory=RescanSettings)

    @field_validator("report_raw_values", mode="before")
    @classmethod
    def _no_raw(cls, value: Any) -> Any:
        if value is True:
            raise ValueError("reporting raw values is not supported; reports never contain values")
        return value

    @model_validator(mode="after")
    def _parse_errors(self) -> PolicySettings:
        if not self.fail_on_parse_error and self.malformed_record_action is None:
            raise ValueError(
                "fail_on_parse_error: false requires an explicit malformed_record_action "
                "(currently only 'drop_record')"
            )
        if self.fail_on_parse_error and self.malformed_record_action is not None:
            raise ValueError(
                "malformed_record_action is only valid when fail_on_parse_error is false"
            )
        return self


class CustomDetector(StrictModel):
    id: Slug
    category: str
    pattern: Annotated[str, Field(min_length=1, max_length=512)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.8
    ignore_case: bool = False


class DetectorSettings(StrictModel):
    disabled: list[str] = Field(default_factory=list)
    dates_emit_generic: bool = False
    internal_host_suffixes: list[str] = Field(
        default_factory=lambda: [
            ".internal",
            ".local",
            ".corp",
            ".lan",
            ".intranet",
            ".localdomain",
        ]
    )
    custom: list[CustomDetector] = Field(default_factory=list)
    reject_risky_regex: bool = True

    @field_validator("internal_host_suffixes")
    @classmethod
    def _suffixes(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(r"\.[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){0,3}", item):
                raise ValueError("internal_host_suffixes entries must look like '.internal'")
        return value


class Classification(StrictModel):
    """Policy-declared field classification: tells the field detector what a field contains."""

    id: Slug
    field_names: list[str] = Field(default_factory=list)
    field_paths: list[str] = Field(default_factory=list)
    category: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.9

    @model_validator(mode="after")
    def _has_selector(self) -> Classification:
        if not self.field_names and not self.field_paths:
            raise ValueError("a classification needs field_names or field_paths")
        return self


class RuleMatch(StrictModel):
    categories: list[str] | None = None
    detectors: list[str] | None = None
    field_names: list[str] | None = None
    field_paths: list[str] | None = None
    field_regex: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    environments: list[Environment] | None = None
    target_environments: list[TargetEnvironment] | None = None
    destinations: list[Destination] | None = None
    domain_profiles: list[DomainProfile] | None = None
    use_cases: list[UseCase] | None = None
    formats: list[InputFormat] | None = None
    min_confidence: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    max_confidence: Annotated[float, Field(ge=0.0, le=1.0)] | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> RuleMatch:
        for name, value in self:
            if isinstance(value, list) and not value:
                raise ValueError(f"selector '{name}' must not be an empty list (omit it instead)")
        if all(value is None for _, value in self):
            raise ValueError(
                "a rule must declare at least one selector; match-everything is unsafe"
            )
        if (
            self.min_confidence is not None
            and self.max_confidence is not None
            and self.min_confidence > self.max_confidence
        ):
            raise ValueError("min_confidence must not exceed max_confidence")
        return self


class Rule(StrictModel):
    id: Slug
    description: Annotated[str, Field(max_length=500)] | None = None
    priority: Annotated[int, Field(ge=0, le=10_000)] = 100
    hard: bool = False
    guardrail: bool = False
    match: RuleMatch
    action: Action
    params: dict[str, Any] = Field(default_factory=dict)
    reason: Slug | None = None
    acknowledge_risk: bool = False

    @field_validator("action", mode="before")
    @classmethod
    def _rejected_actions(cls, value: Any) -> Any:
        return _check_action(value)


class DefaultAction(StrictModel):
    action: Action
    params: dict[str, Any] = Field(default_factory=dict)
    reason: Slug | None = None

    @field_validator("action", mode="before")
    @classmethod
    def _rejected_actions(cls, value: Any) -> Any:
        return _check_action(value)


class TransferApproval(StrictModel):
    reviewed_by: Annotated[str, Field(min_length=1, max_length=200)]
    reference: Annotated[str, Field(min_length=1, max_length=200)]
    approved_on: dt.date


class Transfer(StrictModel):
    """Explicit, reviewed approval lifting the built-in PRD -> non-production transfer block."""

    id: Slug
    from_environments: Annotated[list[Environment], Field(min_length=1)]
    to_target_environments: list[TargetEnvironment] = Field(default_factory=list)
    to_destinations: list[Destination] = Field(default_factory=list)
    approval: TransferApproval

    @model_validator(mode="after")
    def _has_target(self) -> Transfer:
        if not self.to_target_environments and not self.to_destinations:
            raise ValueError("a transfer needs to_target_environments or to_destinations")
        return self


class PolicyDocument(StrictModel):
    policy_version: Literal[1]
    name: Slug
    metadata: dict[str, Any] = Field(default_factory=dict)
    context: PolicyContext = Field(default_factory=PolicyContext)
    requirements: Requirements = Field(default_factory=Requirements)
    settings: PolicySettings = Field(default_factory=PolicySettings)
    detectors: DetectorSettings = Field(default_factory=DetectorSettings)
    custom_categories: list[str] = Field(default_factory=list)
    classifications: list[Classification] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    defaults: dict[str, DefaultAction] = Field(default_factory=dict)
    transfers: list[Transfer] = Field(default_factory=list)

    @field_validator("policy_version", mode="before")
    @classmethod
    def _version(cls, value: Any) -> Any:
        if value != 1:
            raise ValueError("unsupported policy_version; this release supports policy_version: 1")
        return value
