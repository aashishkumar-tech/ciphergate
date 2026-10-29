"""Policy compilation: schema validation plus semantic checks, producing an immutable ``Policy``.

Semantic checks (all errors are reported together, with safe messages):

* categories/detectors referenced anywhere must exist (built-in or declared ``custom_categories``);
* action parameters must validate against the action's typed parameter model;
* credentials can never be ``allow``-ed (nor generalized/date-shifted);
* ``allow`` of a high-risk category toward a possibly untrusted destination needs
  ``acknowledge_risk: true`` (reported as a warning);
* ``hard``/``guardrail`` rules cannot be ``allow``; guardrails must name environment and
  target environment or destination;
* equally ranked rules that may overlap and disagree are rejected as ``policy_conflict``;
* custom/field regexes must compile and pass the regex-safety heuristics;
* replacement constants must not look like real identifiers or secrets;
* untrusted pinned destinations and transfer approvals require ``strict`` and the rescan gate;
  untrusted pinned destinations also require ``scan_json_keys``;
* credential detectors cannot be disabled in strict/untrusted/transfer policies;
* ``rescan.fail_on_categories`` cannot be empty (``credential.secret`` is always gating).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ciphergate.constants import (
    BUILTIN_CATEGORIES,
    CREDENTIAL_CATEGORY,
    CREDENTIAL_DETECTORS,
    CREDENTIAL_PERMITTED_ACTIONS,
    HIGH_RISK_CATEGORIES,
    HIGH_RISK_FAMILIES,
    STACK_TRACE_DETECTOR,
    UNTRUSTED_DESTINATIONS,
    Action,
    Destination,
    InputFormat,
)
from ciphergate.detectors.field_names import normalize_field_name
from ciphergate.detectors.regex_safety import regex_problems
from ciphergate.detectors.registry import BUILTIN_DETECTOR_IDS, unsafe_replacement_reason
from ciphergate.errors import PolicyValidationError, ValidationIssue
from ciphergate.models.context import EffectiveContext
from ciphergate.models.finding import Finding
from ciphergate.models.policy import (
    CATEGORY_RE,
    CATEGORY_SELECTOR_RE,
    PARAM_MODELS,
    ActionParams,
    DateShiftParams,
    PolicyDocument,
    PseudonymizeParams,
    ReplaceParams,
    Rule,
)
from ciphergate.policy.loader import parse_policy_yaml, policy_digest, read_policy_bytes
from ciphergate.policy.precedence import (
    LEVEL_GUARDRAIL,
    LEVEL_HARD_RULE,
    category_selector_matches,
    matches_may_overlap,
    rule_level,
)

MATCH_NO = 0
MATCH_YES = 1
MATCH_CONFIDENCE_ONLY = 2


@dataclass(frozen=True, slots=True)
class CompiledRule:
    rule: Rule
    index: int
    level: int
    params: ActionParams
    field_names: frozenset[str] | None
    field_regex: re.Pattern[str] | None

    @property
    def id(self) -> str:
        return self.rule.id

    def evaluate(self, finding: Finding, ctx: EffectiveContext, fmt: InputFormat) -> int:
        m = self.rule.match
        if m.categories is not None and not any(
            category_selector_matches(s, finding.category) for s in m.categories
        ):
            return MATCH_NO
        if m.detectors is not None and finding.detector not in m.detectors:
            return MATCH_NO
        if m.formats is not None and fmt not in m.formats:
            return MATCH_NO
        if self.field_names is not None and (
            not finding.field_name
            or normalize_field_name(finding.field_name) not in self.field_names
        ):
            return MATCH_NO
        path = finding.location.field_path
        if m.field_paths is not None and not any(
            fnmatch.fnmatchcase(path, p) for p in m.field_paths
        ):
            return MATCH_NO
        if self.field_regex is not None and not self.field_regex.search(path):
            return MATCH_NO
        for selector, value in (
            (m.environments, ctx.environment),
            (m.target_environments, ctx.target_environment),
            (m.destinations, ctx.destination),
            (m.domain_profiles, ctx.domain_profile),
            (m.use_cases, ctx.use_case),
        ):
            if selector is not None and (value is None or value not in selector):
                return MATCH_NO
        if m.min_confidence is not None and finding.confidence < m.min_confidence:
            return MATCH_CONFIDENCE_ONLY
        if m.max_confidence is not None and finding.confidence > m.max_confidence:
            return MATCH_NO
        return MATCH_YES

    def selectors(self) -> tuple[str, ...]:
        return tuple(name for name, value in self.rule.match if value is not None)


@dataclass(frozen=True, slots=True)
class CompiledDefault:
    selector: str
    action: Action
    params: ActionParams
    reason: str | None
    specificity: int  # 0 exact, 1 prefix glob, 2 "*"


@dataclass(frozen=True)
class Policy:
    """A validated, compiled policy. Immutable; safe to share across runs."""

    document: PolicyDocument
    digest: str
    source_name: str | None
    rules: tuple[CompiledRule, ...]
    defaults: tuple[CompiledDefault, ...]
    categories: frozenset[str]
    warnings: tuple[str, ...]
    required_keys: frozenset[str]
    replacement_values: frozenset[str] = field(default_factory=frozenset)
    # Built-in high-risk categories plus custom categories in a high-risk family.
    high_risk: frozenset[str] = HIGH_RISK_CATEGORIES

    @property
    def name(self) -> str:
        return self.document.name

    @property
    def version(self) -> int:
        return self.document.policy_version

    def default_for(self, category: str) -> CompiledDefault | None:
        for default in self.defaults:
            if category_selector_matches(default.selector, category):
                return default
        return None

    def rescan_fail_categories(self, *, untrusted: bool = False) -> frozenset[str]:
        """Categories whose unexpected residuals fail the rescan.

        ``credential.secret`` is always included; toward an untrusted (or missing) destination
        every high-risk category is included regardless of configuration.
        """
        configured = self.document.settings.rescan.fail_on_categories
        base = frozenset(configured) if configured is not None else self.high_risk
        base |= {CREDENTIAL_CATEGORY}
        return base | self.high_risk if untrusted else base


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[ValidationIssue, ...]
    warnings: tuple[str, ...]
    policy: Policy | None


def _loc(parts: tuple[int | str, ...]) -> str:
    out = ""
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p))
    return out or "policy"


def _pydantic_issues(exc: ValidationError) -> list[ValidationIssue]:
    issues = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        msg = str(err.get("msg", "invalid value"))
        msg = msg.removeprefix("Value error, ")
        issues.append(ValidationIssue(_loc(tuple(err.get("loc", ()))), msg, str(err.get("type"))))
    return issues


def _parse_params(
    action: Action, params: dict[str, Any], where: str, issues: list[ValidationIssue]
) -> ActionParams | None:
    model = PARAM_MODELS[action]
    try:
        return model.model_validate(params)  # type: ignore[return-value]
    except ValidationError as exc:
        for issue in _pydantic_issues(exc):
            issues.append(
                ValidationIssue(f"{where}.params.{issue.location}", issue.message, issue.code)
            )
        return None


def _effective_destinations(doc: PolicyDocument, rule_dests: list[Destination] | None) -> set[str]:
    if rule_dests is not None:
        return {str(d) for d in rule_dests}
    pinned = doc.context.destination
    if pinned is not None and "destination" not in doc.context.allow_cli_override:
        return {str(pinned)}
    return {str(d) for d in Destination}


def _selector_can_cover(selectors: list[str] | None, categories: frozenset[str]) -> set[str]:
    if selectors is None:
        return set(categories)
    return {c for c in categories if any(category_selector_matches(s, c) for s in selectors)}


def compile_policy(raw: dict[str, Any], *, digest: str, source_name: str | None = None) -> Policy:
    try:
        doc = PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        schema_issues = _pydantic_issues(exc)
        raise PolicyValidationError(
            f"policy failed schema validation ({len(schema_issues)} issue(s))",
            issues=schema_issues,
        ) from None

    issues: list[ValidationIssue] = []
    warnings: list[str] = []

    # --- categories
    for i, cat in enumerate(doc.custom_categories):
        if not CATEGORY_RE.match(cat):
            issues.append(ValidationIssue(f"custom_categories[{i}]", "invalid category id format"))
        elif cat in BUILTIN_CATEGORIES:
            issues.append(
                ValidationIssue(f"custom_categories[{i}]", "duplicates a built-in category")
            )
    categories = frozenset(BUILTIN_CATEGORIES | set(doc.custom_categories))
    high_risk = HIGH_RISK_CATEGORIES | {
        c for c in doc.custom_categories if c.split(".", 1)[0] in HIGH_RISK_FAMILIES
    }

    def check_category(cat: str, where: str) -> None:
        if cat not in categories:
            issues.append(
                ValidationIssue(
                    where, "unknown category (declare it in custom_categories)", "unknown_category"
                )
            )

    def check_selector(sel: str, where: str) -> None:
        if not CATEGORY_SELECTOR_RE.match(sel):
            issues.append(ValidationIssue(where, "invalid category selector", "invalid_selector"))
        elif not sel.endswith("*") and sel not in categories:
            check_category(sel, where)
        elif sel.endswith(".*") and not any(category_selector_matches(sel, c) for c in categories):
            issues.append(
                ValidationIssue(where, "selector matches no known category", "unknown_category")
            )

    # --- detectors
    detector_ids = set(BUILTIN_DETECTOR_IDS) | {"policy_classification", STACK_TRACE_DETECTOR}
    if doc.detectors.presidio.enabled:
        detector_ids.add("presidio_ner")
        for entity, cat in doc.detectors.presidio.entities.items():
            check_category(cat, f"detectors.presidio.entities.{entity}")
        warnings.append(
            "detectors.presidio is enabled: runs need the optional 'ner' extra and the spaCy "
            f"model '{doc.detectors.presidio.model}' installed locally (never downloaded); NER "
            "is incomplete and can be slow"
        )
    seen_custom: set[str] = set()
    for i, det in enumerate(doc.detectors.custom):
        where = f"detectors.custom[{i}]"
        if det.id in seen_custom:
            issues.append(ValidationIssue(where, "duplicate custom detector id", "duplicate_id"))
        seen_custom.add(det.id)
        detector_ids.add(f"custom:{det.id}")
        check_category(det.category, f"{where}.category")
        for problem in regex_problems(det.pattern, strict=doc.detectors.reject_risky_regex):
            issues.append(ValidationIssue(f"{where}.pattern", problem, "unsafe_regex"))
    for i, name in enumerate(doc.detectors.disabled):
        if name not in BUILTIN_DETECTOR_IDS:
            issues.append(
                ValidationIssue(
                    f"detectors.disabled[{i}]", "unknown built-in detector", "unknown_detector"
                )
            )
    pinned_untrusted = (
        doc.context.destination in UNTRUSTED_DESTINATIONS
        or doc.context.target_environment in ("external", "unknown")
    )
    disabled_credential = CREDENTIAL_DETECTORS & set(doc.detectors.disabled)
    if disabled_credential and (doc.settings.strict or pinned_untrusted or doc.transfers):
        issues.append(
            ValidationIssue(
                "detectors.disabled",
                "secret_pattern/field_name cannot be disabled in strict, untrusted-destination "
                "or transfer-approving policies",
                "credential_detection_required",
            )
        )
    elif disabled_credential:
        warnings.append("credential/field-name detection is disabled; secrets may go undetected")

    # --- classifications
    seen_cls: set[str] = set()
    for i, cls_ in enumerate(doc.classifications):
        if cls_.id in seen_cls:
            issues.append(
                ValidationIssue(f"classifications[{i}].id", "duplicate id", "duplicate_id")
            )
        seen_cls.add(cls_.id)
        check_category(cls_.category, f"classifications[{i}].category")

    # --- rules
    compiled: list[CompiledRule] = []
    required_keys: set[str] = set()
    replacement_values: set[str] = set()
    seen_rules: set[str] = set()
    for i, rule in enumerate(doc.rules):
        where = f"rules[{i}]"
        if rule.id in seen_rules:
            issues.append(ValidationIssue(f"{where}.id", "duplicate rule id", "duplicate_id"))
        seen_rules.add(rule.id)
        m = rule.match
        for j, sel in enumerate(m.categories or []):
            check_selector(sel, f"{where}.match.categories[{j}]")
        for j, det_id in enumerate(m.detectors or []):
            if det_id not in detector_ids:
                issues.append(
                    ValidationIssue(
                        f"{where}.match.detectors[{j}]", "unknown detector", "unknown_detector"
                    )
                )
        field_regex = None
        if m.field_regex is not None:
            problems = regex_problems(m.field_regex, strict=True)
            if problems:
                for problem in problems:
                    issues.append(
                        ValidationIssue(f"{where}.match.field_regex", problem, "unsafe_regex")
                    )
            else:
                field_regex = re.compile(m.field_regex)
        params = _parse_params(rule.action, rule.params, where, issues)
        level = rule_level(rule)
        if rule.hard and rule.action == Action.ALLOW:
            issues.append(ValidationIssue(where, "hard rules cannot allow", "unsafe_allow"))
        if rule.guardrail:
            if rule.action == Action.ALLOW:
                issues.append(
                    ValidationIssue(where, "guardrail rules cannot allow", "unsafe_allow")
                )
            if m.environments is None or (m.target_environments is None and m.destinations is None):
                issues.append(
                    ValidationIssue(
                        where,
                        "guardrail rules must select environments and target_environments "
                        "or destinations",
                        "invalid_guardrail",
                    )
                )
        if rule.hard and rule.guardrail:
            issues.append(ValidationIssue(where, "a rule cannot be both hard and guardrail"))

        covered = _selector_can_cover(m.categories, categories)
        if (
            CREDENTIAL_CATEGORY in covered
            and m.categories is not None
            and (rule.action not in CREDENTIAL_PERMITTED_ACTIONS)
        ):
            issues.append(
                ValidationIssue(
                    where,
                    f"action '{rule.action}' is never permitted for credential.secret",
                    "credential_unsafe_action",
                )
            )
        if rule.action == Action.ALLOW:
            dests = _effective_destinations(doc, m.destinations)
            untrusted = dests & {str(d) for d in UNTRUSTED_DESTINATIONS}
            risky = covered & high_risk
            if untrusted and risky and not rule.acknowledge_risk:
                issues.append(
                    ValidationIssue(
                        where,
                        "allow may apply high-risk categories to an untrusted destination; "
                        "restrict "
                        "'categories'/'destinations' or set acknowledge_risk: true",
                        "high_risk_allow_unacknowledged",
                    )
                )
            elif untrusted and risky:
                warnings.append(
                    f"rule '{rule.id}' allows high-risk categories toward a possibly untrusted "
                    "destination (acknowledge_risk: true)"
                )
        elif rule.acknowledge_risk:
            warnings.append(
                f"rule '{rule.id}': acknowledge_risk has no effect on non-allow actions"
            )

        if isinstance(params, PseudonymizeParams | DateShiftParams):
            required_keys.add(params.key_env)
        if isinstance(params, ReplaceParams) and isinstance(params.value, str):
            reason = unsafe_replacement_reason(params.value)
            if reason:
                issues.append(
                    ValidationIssue(f"{where}.params.value", reason, "unsafe_replacement")
                )
            replacement_values.add(params.value)
        if isinstance(params, ReplaceParams) and params.value is not None:
            replacement_values.add(str(params.value))
        if params is not None:
            compiled.append(
                CompiledRule(
                    rule=rule,
                    index=i,
                    level=level,
                    params=params,
                    field_names=(
                        frozenset(normalize_field_name(n) for n in m.field_names)
                        if m.field_names is not None
                        else None
                    ),
                    field_regex=field_regex,
                )
            )

    # --- conflicts between equally ranked rules
    for a_idx, a in enumerate(compiled):
        for b in compiled[a_idx + 1 :]:
            if a.level != b.level or a.rule.priority != b.rule.priority:
                continue
            if a.rule.action == b.rule.action and a.params == b.params:
                continue
            if a.level in (LEVEL_HARD_RULE, LEVEL_GUARDRAIL) and (
                a.rule.action == b.rule.action == Action.BLOCK
            ):
                continue
            if matches_may_overlap(a.rule.match, b.rule.match):
                issues.append(
                    ValidationIssue(
                        f"rules[{a.index}],rules[{b.index}]",
                        f"rules '{a.id}' and '{b.id}' have the same precedence level and priority, "
                        "may match the same finding, and choose different actions; "
                        "change a priority or narrow a selector",
                        "policy_conflict",
                    )
                )

    # --- defaults
    defaults: list[CompiledDefault] = []
    for sel, spec in doc.defaults.items():
        where = f"defaults.{sel}"
        check_selector(sel, where)
        params = _parse_params(spec.action, spec.params, where, issues)
        covered = (
            _selector_can_cover([sel], categories) if CATEGORY_SELECTOR_RE.match(sel) else set()
        )
        if spec.action == Action.ALLOW and covered & high_risk:
            issues.append(
                ValidationIssue(
                    where,
                    "defaults cannot allow high-risk categories; use an explicit scoped rule",
                    "unsafe_allow",
                )
            )
        if CREDENTIAL_CATEGORY in covered and spec.action not in CREDENTIAL_PERMITTED_ACTIONS:
            issues.append(
                ValidationIssue(
                    where,
                    f"action '{spec.action}' is never permitted for credential.secret",
                    "credential_unsafe_action",
                )
            )
        if isinstance(params, PseudonymizeParams | DateShiftParams):
            required_keys.add(params.key_env)
        if isinstance(params, ReplaceParams) and params.value is not None:
            if isinstance(params.value, str):
                reason = unsafe_replacement_reason(params.value)
                if reason:
                    issues.append(
                        ValidationIssue(f"{where}.params.value", reason, "unsafe_replacement")
                    )
            replacement_values.add(str(params.value))
        if params is not None:
            specificity = 2 if sel == "*" else (1 if sel.endswith(".*") else 0)
            defaults.append(CompiledDefault(sel, spec.action, params, spec.reason, specificity))
    defaults.sort(key=lambda d: (d.specificity, -len(d.selector)))

    # --- rescan / strictness / transfers
    fail_on = doc.settings.rescan.fail_on_categories
    for i, cat in enumerate(fail_on or []):
        check_category(cat, f"settings.rescan.fail_on_categories[{i}]")
    if fail_on is not None and not fail_on:
        issues.append(
            ValidationIssue(
                "settings.rescan.fail_on_categories",
                "must not be empty (omit it to use the high-risk default)",
                "invalid_value",
            )
        )
    elif fail_on is not None and not high_risk <= set(fail_on):
        warnings.append(
            "settings.rescan.fail_on_categories omits high-risk categories; credential.secret "
            "is always gating and untrusted destinations still gate on every high-risk category"
        )
    if not doc.requirements.destination:
        warnings.append(
            "requirements.destination is false: runs without a destination are treated as "
            "untrusted (strict policy and rescan gate required)"
        )
    if doc.settings.scan_json_keys is False and pinned_untrusted:
        issues.append(
            ValidationIssue(
                "settings.scan_json_keys",
                "policies pinned to an external/untrusted destination must scan JSON keys",
                "key_scan_required",
            )
        )
    if pinned_untrusted:
        if not doc.settings.strict:
            issues.append(
                ValidationIssue(
                    "settings.strict",
                    "policies pinned to an external/untrusted destination must be strict",
                    "strict_required",
                )
            )
        if not doc.settings.rescan.enabled:
            issues.append(
                ValidationIssue(
                    "settings.rescan.enabled",
                    "policies pinned to an external/untrusted destination "
                    "must enable the rescan gate",
                    "rescan_required",
                )
            )
    seen_transfers: set[str] = set()
    for i, transfer in enumerate(doc.transfers):
        if transfer.id in seen_transfers:
            issues.append(ValidationIssue(f"transfers[{i}].id", "duplicate id", "duplicate_id"))
        seen_transfers.add(transfer.id)
        if transfer.approval.approved_on > dt.date.today():
            issues.append(
                ValidationIssue(
                    f"transfers[{i}].approval.approved_on",
                    "approval date is in the future",
                    "invalid_value",
                )
            )
        warnings.append(
            f"transfer approval '{transfer.id}' lifts the built-in production-to-non-production "
            "block for the listed context; confirm it is still reviewed and current"
        )
    if doc.transfers and (not doc.settings.strict or not doc.settings.rescan.enabled):
        issues.append(
            ValidationIssue(
                "transfers",
                "transfer approvals require settings.strict and settings.rescan.enabled",
                "transfer_requires_strict",
            )
        )
    if not doc.settings.strict:
        warnings.append("settings.strict is false: unknown context will not force review")
    if doc.context.allow_cli_override:
        warnings.append(
            "context.allow_cli_override permits CLI values to replace pinned context: "
            + ", ".join(doc.context.allow_cli_override)
        )

    if issues:
        raise PolicyValidationError(
            f"policy failed semantic validation ({len(issues)} issue(s))", issues=issues
        )
    return Policy(
        document=doc,
        digest=digest,
        source_name=source_name,
        rules=tuple(compiled),
        defaults=tuple(defaults),
        categories=categories,
        warnings=tuple(warnings),
        required_keys=frozenset(required_keys),
        replacement_values=frozenset(replacement_values),
        high_risk=frozenset(high_risk),
    )


def load_policy(path: str | Path) -> Policy:
    """Load, schema-validate and compile a policy file. Raises ``PolicyValidationError``."""
    data = read_policy_bytes(path)
    raw = parse_policy_yaml(data)
    return compile_policy(raw, digest=policy_digest(data), source_name=Path(path).name)


def load_policy_text(text: str, *, source_name: str | None = None) -> Policy:
    data = text.encode("utf-8")
    return compile_policy(
        parse_policy_yaml(data), digest=policy_digest(data), source_name=source_name
    )


def validate_policy(source: str | Path | Policy) -> ValidationResult:
    """Validate without raising. Never reads any input dataset."""
    if isinstance(source, Policy):
        return ValidationResult(True, (), source.warnings, source)
    try:
        policy = load_policy(source)
    except PolicyValidationError as exc:
        issues = exc.issues or [ValidationIssue("policy", exc.message, exc.code)]
        return ValidationResult(False, tuple(issues), (), None)
    return ValidationResult(True, (), policy.warnings, policy)
