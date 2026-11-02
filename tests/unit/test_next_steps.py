from __future__ import annotations

from typing import Any

from ciphergate.constants import ReasonCode
from ciphergate.reporting.next_steps import _HINTS, merge_next_steps, next_step_items, next_steps


def report(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "command": "sanitize",
        "exit_code": 1,
        "gates": [],
        "summary": {"by_reason_code": {}},
        "keys": [],
        "rescan": None,
    }
    base.update(extra)
    return base


def test_successful_run_has_no_hints() -> None:
    blocked = {"by_reason_code": {ReasonCode.EXPLICIT_HARD_BLOCK: 1}}
    assert next_steps(report(exit_code=0, summary=blocked)) == []


def test_gates_decisions_keys_and_rescan_each_give_a_hint() -> None:
    hints = next_steps(
        report(
            gates=[{"reason_code": ReasonCode.DESTINATION_REQUIRED_BUT_MISSING}],
            summary={"by_reason_code": {ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK: 2}},
            keys=[{"key_env": "CIPHERGATE_HMAC_KEY", "status": "missing"}],
            rescan={"failed": True},
        )
    )
    assert len(hints) == 4
    assert "--destination" in hints[0] and "rotate" in hints[1]
    assert "rescan" in hints[2] and "CIPHERGATE_HMAC_KEY" in hints[3]


def test_duplicate_hints_are_shown_once() -> None:
    summary = {
        "by_reason_code": {
            ReasonCode.NO_APPLICABLE_RULE_REQUIRES_REVIEW: 1,
            ReasonCode.NO_APPLICABLE_RULE_BLOCKS: 1,
        }
    }
    assert len(next_steps(report(summary=summary))) == 1


def test_rescan_hints_ignore_the_policy_decisions() -> None:
    summary = {"by_reason_code": {ReasonCode.EXPLICIT_HARD_BLOCK: 1}}
    hints = next_steps(
        report(command="rescan", exit_code=7, summary=summary, rescan={"failed": True})
    )
    assert hints == [_HINTS[ReasonCode.RESIDUAL_FINDING]]


def test_hints_are_fixed_text() -> None:
    # Hints come from a fixed table, so they can never carry input values.
    unknown = {"by_reason_code": {"explicit_policy_match": 3, "not_a_code": 1}}
    assert next_steps(report(summary=unknown)) == []


def test_items_carry_stable_codes() -> None:
    items = next_step_items(
        report(
            gates=[{"reason_code": ReasonCode.ENVIRONMENT_REQUIRED_BUT_MISSING}],
            keys=[
                {"key_env": "CIPHERGATE_HMAC_KEY", "status": "missing"},
                {"key_env": "OTHER_KEY", "status": "too_short"},
            ],
        )
    )
    assert [i["code"] for i in items] == [
        "environment_required_but_missing",
        "key_missing",
        "key_invalid",
    ]
    assert all(set(i) == {"code", "message"} for i in items)


def test_merge_keeps_first_occurrence_order() -> None:
    a = report(gates=[{"reason_code": ReasonCode.DESTINATION_REQUIRED_BUT_MISSING}])
    b = report(
        gates=[
            {"reason_code": ReasonCode.ENVIRONMENT_REQUIRED_BUT_MISSING},
            {"reason_code": ReasonCode.DESTINATION_REQUIRED_BUT_MISSING},
        ]
    )
    assert [i["code"] for i in merge_next_steps([a, b])] == [
        "destination_required_but_missing",
        "environment_required_but_missing",
    ]
