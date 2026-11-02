"""Short next-step hints for runs that did not complete. Built from reason codes only."""

from __future__ import annotations

from typing import Any

from ciphergate.constants import ReasonCode

_HINTS: dict[str, str] = {
    ReasonCode.CREDENTIAL_DETECTED_HARD_BLOCK: (
        "a credential was found: remove it from the input and rotate it if it is real; "
        "no policy can let credentials through"
    ),
    ReasonCode.EXPLICIT_HARD_BLOCK: (
        "a hard rule blocks these values for this destination: remove them from the input, or "
        "use a policy written for a destination allowed to receive them; "
        "'ciphergate explain' shows which rule wins"
    ),
    ReasonCode.ENVIRONMENT_GUARDRAIL: (
        "a guardrail rule blocks this environment-to-destination move; check the context, or "
        "change the guardrail in the policy after review"
    ),
    ReasonCode.PRD_TO_NONPRODUCTION_BLOCKED: (
        "production data cannot go to a non-production target without a reviewed 'transfers' "
        "approval in the policy (docs/policy-schema.md#transfers)"
    ),
    ReasonCode.NO_APPLICABLE_RULE_REQUIRES_REVIEW: (
        "no rule covers some findings: add rules for the categories listed above, then run "
        "'ciphergate plan' again"
    ),
    ReasonCode.NO_APPLICABLE_RULE_BLOCKS: (
        "no rule covers some findings: add rules for the categories listed above, then run "
        "'ciphergate plan' again"
    ),
    ReasonCode.UNKNOWN_CONTEXT_REQUIRES_REVIEW: (
        "the environment or destination is 'unknown': pass the real values with --environment "
        "and --destination"
    ),
    ReasonCode.HIGH_RISK_ALLOW_REQUIRES_ACKNOWLEDGEMENT: (
        "an allow rule reaches high-risk data toward an untrusted destination: narrow the rule, "
        "or set acknowledge_risk: true after review"
    ),
    ReasonCode.UNSUPPORTED_TRANSFORM: (
        "a rule's action cannot run on this format or location: choose another action for it"
    ),
    ReasonCode.ENVIRONMENT_REQUIRED_BUT_MISSING: (
        "pass --environment (dev, stg, prd) or pin context.environment in the policy"
    ),
    ReasonCode.DESTINATION_REQUIRED_BUT_MISSING: (
        "pass --destination (for example local_dev or external_ai) or pin context.destination "
        "in the policy"
    ),
    ReasonCode.TARGET_ENVIRONMENT_REQUIRED_BUT_MISSING: (
        "pass --target-environment or pin context.target_environment in the policy"
    ),
    ReasonCode.ENVIRONMENT_CONTEXT_CONFLICT: (
        "a CLI flag contradicts the policy's pinned context: drop the flag, or use a policy for "
        "that context"
    ),
    ReasonCode.UNSUPPORTED_ENVIRONMENT: "use one of the documented environment values",
    ReasonCode.STRICT_POLICY_REQUIRED: (
        "this destination needs a strict policy: set settings.strict: true"
    ),
    ReasonCode.RESCAN_REQUIRED: (
        "this destination needs the rescan gate: do not disable settings.rescan in the policy"
    ),
    ReasonCode.CREDENTIAL_DETECTION_REQUIRED: (
        "this destination needs credential detection: remove secret_pattern and field_name from "
        "detectors.disabled"
    ),
    ReasonCode.KEY_SCAN_REQUIRED: (
        "this destination needs JSON key scanning: set settings.scan_json_keys: true"
    ),
    ReasonCode.RESIDUAL_FINDING: (
        "the rescan still found gating categories in the output: add rules for them, then run again"
    ),
}

_KEY_HINT = (
    "set {env} to at least 32 random bytes in your environment (never on the command line); "
    "see 'Pseudonymization key' in the README"
)


def next_steps(report: dict[str, Any]) -> list[str]:
    """Hints for a run that ended with a non-zero exit code; empty otherwise."""
    if not report.get("exit_code"):
        return []
    codes = [gate["reason_code"] for gate in report.get("gates", [])]
    if report.get("command") != "rescan":
        # A rescan's policy decisions describe the output, not what to fix in the input.
        codes += list(report.get("summary", {}).get("by_reason_code", {}))
    rescan = report.get("rescan")
    if rescan and rescan.get("failed"):
        codes.append(ReasonCode.RESIDUAL_FINDING)
    hints: list[str] = []
    for code in codes:
        hint = _HINTS.get(code)
        if hint and hint not in hints:
            hints.append(hint)
    for key in report.get("keys", []):
        if key.get("status") != "available":
            hint = _KEY_HINT.format(env=key["key_env"])
            if hint not in hints:
                hints.append(hint)
    return hints
