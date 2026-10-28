"""Context resolution (policy pins vs. caller input) and run-level environment guardrails.

Environment values are *declared* context. CipherGate cannot verify that data really came from the
stated environment; CI pipelines should source these values from controlled configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ciphergate.constants import (
    CREDENTIAL_DETECTORS,
    NON_PRODUCTION_DESTINATIONS,
    Destination,
    Environment,
    InputFormat,
    ReasonCode,
    TargetEnvironment,
)
from ciphergate.errors import ContextError
from ciphergate.models.context import (
    CONTEXT_FIELDS,
    ContextInput,
    ContextSource,
    EffectiveContext,
)
from ciphergate.policy.validator import Policy


@dataclass(frozen=True, slots=True)
class GateIssue:
    reason_code: ReasonCode
    severity: Literal["block", "review"]
    message: str
    field: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "reason_code": str(self.reason_code),
            "severity": self.severity,
            "field": self.field,
            "message": self.message,
        }


def resolve_context(policy: Policy, given: ContextInput | None = None) -> EffectiveContext:
    """Combine policy-pinned context with caller input; conflicts fail unless overridable."""
    given = given or ContextInput()
    pins = policy.document.context
    values: dict[str, object] = {}
    sources: dict[str, ContextSource] = {}
    for name in CONTEXT_FIELDS:
        pinned = getattr(pins, name)
        supplied = getattr(given, name)
        if pinned is not None and supplied is not None and pinned != supplied:
            if name not in pins.allow_cli_override:
                raise ContextError(
                    f"'{name}' supplied by the caller conflicts with the value pinned by the "
                    "policy; "
                    "use a policy for that context or add it to context.allow_cli_override",
                    code=str(ReasonCode.ENVIRONMENT_CONTEXT_CONFLICT),
                )
            values[name], sources[name] = supplied, "cli_override"
        elif pinned is not None:
            values[name], sources[name] = pinned, "policy"
        elif supplied is not None:
            values[name], sources[name] = supplied, "cli"
        else:
            values[name], sources[name] = None, "unset"
    return EffectiveContext(sources=sources, **values)  # type: ignore[arg-type]


def _approval_matches(policy: Policy, ctx: EffectiveContext) -> str | None:
    """An approval must name every context dimension the run supplies (no implicit widening)."""
    for transfer in policy.document.transfers:
        if ctx.environment not in transfer.from_environments:
            continue
        if ctx.target_environment is not None and (
            ctx.target_environment not in transfer.to_target_environments
        ):
            continue
        if ctx.destination is not None and ctx.destination not in transfer.to_destinations:
            continue
        return transfer.id
    return None


def evaluate_gates(
    policy: Policy, ctx: EffectiveContext, fmt: InputFormat | None = None
) -> tuple[list[GateIssue], list[str]]:
    """Run-level checks that no rule can override. Returns (issues, approvals_used).

    A missing destination counts as untrusted: it never relaxes the strict/rescan requirements.
    """
    doc = policy.document
    issues: list[GateIssue] = []
    approvals: list[str] = []
    req = doc.requirements

    if req.environment and ctx.environment is None:
        issues.append(
            GateIssue(
                ReasonCode.ENVIRONMENT_REQUIRED_BUT_MISSING,
                "block",
                "source environment is required (--environment)",
                "environment",
            )
        )
    if req.target_environment and ctx.target_environment is None:
        issues.append(
            GateIssue(
                ReasonCode.TARGET_ENVIRONMENT_REQUIRED_BUT_MISSING,
                "block",
                "target environment is required (--target-environment)",
                "target_environment",
            )
        )
    if req.destination and ctx.destination is None:
        issues.append(
            GateIssue(
                ReasonCode.DESTINATION_REQUIRED_BUT_MISSING,
                "block",
                "destination is required (--destination)",
                "destination",
            )
        )

    if doc.settings.strict:
        for name, unknown in (
            ("environment", Environment.UNKNOWN),
            ("target_environment", TargetEnvironment.UNKNOWN),
            ("destination", Destination.UNKNOWN),
        ):
            if getattr(ctx, name) == unknown:
                issues.append(
                    GateIssue(
                        ReasonCode.UNKNOWN_CONTEXT_REQUIRES_REVIEW,
                        "review",
                        f"{name} is 'unknown'; strict policies require known "
                        "context before release",
                        name,
                    )
                )

    prd_to_nonprod = ctx.environment == Environment.PRD and (
        ctx.target_environment in (TargetEnvironment.DEV, TargetEnvironment.STG)
        or ctx.destination in NON_PRODUCTION_DESTINATIONS
    )
    if prd_to_nonprod:
        approval = _approval_matches(policy, ctx)
        if approval is None:
            issues.append(
                GateIssue(
                    ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED,
                    "block",
                    "production-origin data headed to a non-production target is blocked "
                    "unless the "
                    "policy contains a reviewed 'transfers' approval for this context",
                )
            )
        else:
            approvals.append(approval)

    untrusted = ctx.is_untrusted or ctx.target_environment == TargetEnvironment.PRD
    if untrusted and not doc.settings.strict:
        issues.append(
            GateIssue(
                ReasonCode.STRICT_POLICY_REQUIRED,
                "block",
                "external, unknown, missing or production targets require a strict policy",
            )
        )
    if untrusted and not doc.settings.rescan.enabled:
        issues.append(
            GateIssue(
                ReasonCode.RESCAN_REQUIRED,
                "block",
                "external, unknown, missing or production targets require the rescan gate",
            )
        )
    if untrusted and CREDENTIAL_DETECTORS & set(doc.detectors.disabled):
        issues.append(
            GateIssue(
                ReasonCode.CREDENTIAL_DETECTION_REQUIRED,
                "block",
                "secret_pattern/field_name detectors must stay enabled for this target",
            )
        )
    if (
        ctx.is_untrusted
        and fmt in (InputFormat.JSON, InputFormat.JSONL)
        and not doc.settings.scan_json_keys
    ):
        issues.append(
            GateIssue(
                ReasonCode.KEY_SCAN_REQUIRED,
                "block",
                "JSON keys are not scanned (settings.scan_json_keys: false); keys can carry "
                "data and must be scanned for an untrusted or missing destination",
            )
        )
    return issues, approvals
