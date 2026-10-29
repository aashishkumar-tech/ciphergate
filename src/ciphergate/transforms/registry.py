"""Applies approved decisions to one value. Created per run (no global mutable state).

Combination rules for several decisions on the same value:

1. any ``drop_record`` -> the record is dropped; else any ``drop_field`` -> the field is dropped;
2. whole-value decisions (field-name/classification findings) — the most protective transform
   (by ``ACTION_RANK``) replaces the entire value;
3. otherwise span decisions (pattern findings) — overlapping spans are merged, each merged span
   takes its most protective action, and spans are rewritten right-to-left so surrounding debug
   context is preserved.

``block`` and ``review`` never reach this module: the planner withholds output before pass two.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ciphergate.constants import ACTION_RANK, Action
from ciphergate.errors import InternalError, TransformError
from ciphergate.models.finding import Finding, value_type_name
from ciphergate.models.policy import (
    ActionParams,
    DateShiftParams,
    GeneralizeParams,
    PseudonymizeParams,
    RedactParams,
    ReplaceParams,
)
from ciphergate.policy.engine import Decision
from ciphergate.policy.validator import Policy
from ciphergate.transforms.date_shift import date_shift, derive_offset_days
from ciphergate.transforms.generalize import generalize
from ciphergate.transforms.keys import KeyProvider
from ciphergate.transforms.pseudonymize import CollisionTracker, pseudonymize
from ciphergate.transforms.redact import redact
from ciphergate.transforms.replace import replace

EntityLookup = Callable[[str], Any]


@dataclass(frozen=True, slots=True)
class ValueOutcome:
    value: Any
    changed: bool = False
    type_changed: bool = False
    drop_field: bool = False
    drop_record: bool = False


class Transformer:
    def __init__(self, policy: Policy, keys: KeyProvider) -> None:
        self.namespace = policy.name
        self.keys = keys
        self.collisions = CollisionTracker()

    def apply_action(
        self,
        action: Action,
        params: ActionParams,
        value: Any,
        *,
        category: str,
        field_path: str,
        in_span: bool,
        entity_lookup: EntityLookup | None,
    ) -> Any:
        if action == Action.ALLOW:
            return value
        if action == Action.REDACT and isinstance(params, RedactParams):
            return redact(params, category)
        if action == Action.REPLACE and isinstance(params, ReplaceParams):
            return replace(params, in_span=in_span)
        if action == Action.PSEUDONYMIZE and isinstance(params, PseudonymizeParams):
            if value is None:
                return None
            return pseudonymize(
                value,
                params,
                key=self.keys.get(params.key_env),
                namespace=self.namespace,
                category=category,
                field_path=field_path,
                collisions=self.collisions,
            )
        if action == Action.GENERALIZE and isinstance(params, GeneralizeParams):
            return generalize(value, params)
        if action == Action.DATE_SHIFT and isinstance(params, DateShiftParams):
            if params.scope == "entity":
                if entity_lookup is None or params.entity_field is None:
                    raise TransformError(
                        "date_shift scope 'entity' needs structured input",
                        code="date_shift_entity_unavailable",
                    )
                entity = entity_lookup(params.entity_field)
                if entity is None or entity == "":
                    raise TransformError(
                        "date_shift entity_field is missing in a record",
                        code="date_shift_entity_missing",
                    )
            else:
                entity = "dataset"
            offset = derive_offset_days(
                self.keys.get(params.key_env),
                params.namespace or self.namespace,
                entity,
                params.max_days,
            )
            return date_shift(value, params, offset_days=offset)
        raise TransformError(
            f"action '{action}' cannot transform a value", code="unsupported_transform"
        )

    def transform_value(
        self,
        value: Any,
        evaluated: list[tuple[Finding, Decision]],
        *,
        field_path: str,
        entity_lookup: EntityLookup | None = None,
    ) -> ValueOutcome:
        if not evaluated:
            return ValueOutcome(value)
        actions = {d.action for _, d in evaluated}
        if Action.BLOCK in actions or Action.REVIEW in actions:
            raise InternalError("blocked/review decisions must not reach the transformer")
        if Action.DROP_RECORD in actions:
            return ValueOutcome(value, changed=True, drop_record=True)
        if Action.DROP_FIELD in actions:
            return ValueOutcome(value, changed=True, drop_field=True)

        whole = [(f, d) for f, d in evaluated if f.whole_value and d.action != Action.ALLOW]
        if whole:
            finding, decision = max(
                whole, key=lambda fd: (ACTION_RANK[fd[1].action], -fd[0].location.record_index)
            )
            new = self.apply_action(
                decision.action,
                decision.params,
                value,
                category=finding.category,
                field_path=field_path,
                in_span=False,
                entity_lookup=entity_lookup,
            )
            return ValueOutcome(
                new,
                changed=new != value or type(new) is not type(value),
                type_changed=value_type_name(new) != value_type_name(value),
            )

        spans = sorted(
            (
                (f.location.span, f, d)
                for f, d in evaluated
                if f.location.span is not None and d.action != Action.ALLOW
            ),
            key=lambda item: (item[0][0], item[0][1]),
        )
        if not spans:
            return ValueOutcome(value)
        text = value if isinstance(value, str) else ("" if value is None else str(value))
        groups: list[list[Any]] = []  # [start, end, finding, decision]
        for span, finding, decision in spans:
            if span is None:
                continue
            if groups and span[0] < groups[-1][1]:
                group = groups[-1]
                group[1] = max(group[1], span[1])
                if ACTION_RANK[decision.action] > ACTION_RANK[group[3].action]:
                    group[2], group[3] = finding, decision
            else:
                groups.append([span[0], span[1], finding, decision])
        out = text
        for start, end, finding, decision in reversed(groups):
            replacement = self.apply_action(
                decision.action,
                decision.params,
                out[start:end],
                category=finding.category,
                field_path=finding.location.field_path or field_path,
                in_span=True,
                entity_lookup=entity_lookup,
            )
            out = out[:start] + str(replacement) + out[end:]
        return ValueOutcome(
            out, changed=out != text, type_changed=value_type_name(out) != value_type_name(value)
        )
