"""Run context: source environment, target environment, destination, profile, use case."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ciphergate.constants import (
    UNTRUSTED_DESTINATIONS,
    Destination,
    DomainProfile,
    Environment,
    TargetEnvironment,
    UseCase,
)

ContextField = Literal[
    "environment", "target_environment", "destination", "domain_profile", "use_case"
]
CONTEXT_FIELDS: tuple[ContextField, ...] = (
    "environment",
    "target_environment",
    "destination",
    "domain_profile",
    "use_case",
)
ContextSource = Literal["policy", "cli", "cli_override", "unset"]


@dataclass(frozen=True, slots=True)
class ContextInput:
    """Context supplied by the caller (CLI flags or API). ``None`` means not supplied."""

    environment: Environment | None = None
    target_environment: TargetEnvironment | None = None
    destination: Destination | None = None
    domain_profile: DomainProfile | None = None
    use_case: UseCase | None = None


@dataclass(frozen=True, slots=True)
class EffectiveContext:
    """Context after combining policy pins with caller input. ``None`` means missing."""

    environment: Environment | None = None
    target_environment: TargetEnvironment | None = None
    destination: Destination | None = None
    domain_profile: DomainProfile | None = None
    use_case: UseCase | None = None
    sources: dict[str, ContextSource] = field(default_factory=dict)

    @property
    def is_untrusted(self) -> bool:
        """True unless the recipient is known and internal. A missing destination is untrusted."""
        return (
            self.destination is None
            or self.destination in UNTRUSTED_DESTINATIONS
            or self.target_environment in (TargetEnvironment.EXTERNAL, TargetEnvironment.UNKNOWN)
        )

    def get(self, name: ContextField) -> str | None:
        value = getattr(self, name)
        return None if value is None else str(value)

    def to_report(self) -> dict[str, dict[str, str | None]]:
        return {
            name: {"value": self.get(name), "source": self.sources.get(name, "unset")}
            for name in CONTEXT_FIELDS
        }
