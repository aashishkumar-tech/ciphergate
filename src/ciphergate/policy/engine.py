"""The policy engine: (finding, context, format) -> Decision. Deterministic and side-effect free.

See ``ciphergate.policy.precedence`` for the precedence levels. After a rule/default/fallback is
selected, engine hard constraints are applied; they cannot be overridden by any rule:

* credentials are never allowed (nor generalized/date-shifted) — forced to ``block``;
* an ``allow`` of a high-risk category toward an untrusted or missing destination (or an
  external/unknown target environment) without
  ``acknowledge_risk`` becomes ``review``;
* transforms that cannot apply to the location (e.g. ``drop_field`` on a text line, value
  transforms on JSON keys/CSV header cells) become ``review`` with ``unsupported_transform``, or
  ``block`` when the finding is a credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ciphergate.constants import (
    CREDENTIAL_CATEGORY,
    CREDENTIAL_PERMITTED_ACTIONS,
    VALUE_TRANSFORM_ACTIONS,
    Action,
    InputFormat,
    ReasonCode,
)
from ciphergate.models.context import EffectiveContext
from ciphergate.models.finding import Finding
from ciphergate.models.policy import ActionParams, EmptyParams
from ciphergate.policy.precedence import (
    LEVEL_DEFAULT,
    LEVEL_FALLBACK,
    LEVEL_GUARDRAIL,
    LEVEL_HARD_CONSTRAINT,
    LEVEL_HARD_RULE,
    LEVEL_NAMES,
)
from ciphergate.policy.validator import (
    MATCH_CONFIDENCE_ONLY,
    MATCH_YES,
    CompiledRule,
    Policy,
)


@dataclass(frozen=True, slots=True)
class Decision:
    action: Action
    reason_code: ReasonCode
    level: int
    rule_id: str | None = None
    rule_reason: str | None = None
    params: ActionParams = field(default_factory=EmptyParams)
    matched_on: tuple[str, ...] = ()
    overridden_rule_id: str | None = None

    @property
    def requires_review(self) -> bool:
        return self.action == Action.REVIEW

    @property
    def level_name(self) -> str:
        return LEVEL_NAMES[self.level]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "action": str(self.action),
            "reason_code": str(self.reason_code),
            "precedence": self.level_name,
            "rule_id": self.rule_id,
        }
        if self.rule_reason:
            data["rule_reason"] = self.rule_reason
        if self.matched_on:
            data["matched_on"] = list(self.matched_on)
        if self.overridden_rule_id:
            data["overridden_rule_id"] = self.overridden_rule_id
        data["requires_review"] = self.requires_review
        return data


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(self, finding: Finding, ctx: EffectiveContext, fmt: InputFormat) -> Decision:
        decision = self._select(finding, ctx, fmt)
        return self._apply_hard_constraints(decision, finding, ctx, fmt)

    def _select(self, finding: Finding, ctx: EffectiveContext, fmt: InputFormat) -> Decision:
        matched: list[CompiledRule] = []
        confidence_miss = False
        for rule in self.policy.rules:
            result = rule.evaluate(finding, ctx, fmt)
            if result == MATCH_YES:
                matched.append(rule)
            elif result == MATCH_CONFIDENCE_ONLY:
                confidence_miss = True
        if matched:
            level = min(r.level for r in matched)
            at_level = [r for r in matched if r.level == level]
            priority = max(r.rule.priority for r in at_level)
            top = [r for r in at_level if r.rule.priority == priority]
            if len({(r.rule.action, r.params.model_dump_json()) for r in top}) > 1:
                # Unreachable for validated policies; fail closed rather than pick by order.
                return Decision(
                    Action.BLOCK,
                    ReasonCode.POLICY_CONFLICT,
                    LEVEL_HARD_CONSTRAINT,
                    rule_id=",".join(sorted(r.id for r in top)),
                )
            chosen = top[0]
            if level == LEVEL_HARD_RULE and chosen.rule.action == Action.BLOCK:
                reason = (
                    ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK
                    if finding.category == CREDENTIAL_CATEGORY
                    else ReasonCode.EXPLICIT_HARD_BLOCK
                )
            elif level == LEVEL_GUARDRAIL:
                reason = ReasonCode.ENVIRONMENT_GUARDRAIL
            else:
                reason = ReasonCode.EXPLICIT_POLICY_MATCH
            return Decision(
                action=chosen.rule.action,
                reason_code=reason,
                level=level,
                rule_id=chosen.id,
                rule_reason=chosen.rule.reason,
                params=chosen.params,
                matched_on=chosen.selectors(),
            )
        default = self.policy.default_for(finding.category)
        if default is not None:
            return Decision(
                action=default.action,
                reason_code=ReasonCode.PROFILE_DEFAULT,
                level=LEVEL_DEFAULT,
                rule_id=f"defaults:{default.selector}",
                rule_reason=default.reason,
                params=default.params,
            )
        behavior = Action(self.policy.document.settings.unknown_sensitive_behavior)
        if confidence_miss:
            reason = ReasonCode.CONFIDENCE_BELOW_RULE_THRESHOLD
        elif behavior == Action.BLOCK:
            reason = ReasonCode.NO_APPLICABLE_RULE_BLOCKS
        else:
            reason = ReasonCode.NO_APPLICABLE_RULE_REQUIRES_REVIEW
        return Decision(action=behavior, reason_code=reason, level=LEVEL_FALLBACK)

    def _apply_hard_constraints(
        self, decision: Decision, finding: Finding, ctx: EffectiveContext, fmt: InputFormat
    ) -> Decision:
        if finding.category == CREDENTIAL_CATEGORY and (
            decision.action not in CREDENTIAL_PERMITTED_ACTIONS
        ):
            return Decision(
                Action.BLOCK,
                ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK,
                LEVEL_HARD_CONSTRAINT,
                overridden_rule_id=decision.rule_id,
            )
        if decision.action == Action.ALLOW and finding.category in self.policy.high_risk:
            untrusted = ctx.is_untrusted
            rule = next((r for r in self.policy.rules if r.id == decision.rule_id), None)
            acknowledged = rule is not None and rule.rule.acknowledge_risk
            if untrusted and not acknowledged:
                return Decision(
                    Action.REVIEW,
                    ReasonCode.HIGH_RISK_ALLOW_REQUIRES_ACKNOWLEDGEMENT,
                    LEVEL_HARD_CONSTRAINT,
                    overridden_rule_id=decision.rule_id,
                )
        unsupported = (
            decision.action == Action.DROP_FIELD and fmt in (InputFormat.TEXT, InputFormat.LOGFMT)
        ) or (finding.location.in_key and decision.action in VALUE_TRANSFORM_ACTIONS)
        if unsupported and finding.category == CREDENTIAL_CATEGORY:
            # A credential that cannot be removed where it is must not wait for review.
            return Decision(
                Action.BLOCK,
                ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK,
                LEVEL_HARD_CONSTRAINT,
                overridden_rule_id=decision.rule_id,
            )
        if unsupported:
            return Decision(
                Action.REVIEW,
                ReasonCode.UNSUPPORTED_TRANSFORM,
                LEVEL_HARD_CONSTRAINT,
                overridden_rule_id=decision.rule_id,
            )
        return decision
