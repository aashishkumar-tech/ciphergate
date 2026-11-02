"""Policy layering: ``extends: [...]`` builds one effective policy from packs and local files.

An ``extends`` entry is either a shipped pack name (``policies/packs/<name>.yml``; compared to the
packs that exist, never used as a path) or a relative ``.yml``/``.yaml`` path to a local layer.
A local path resolves against the directory of the file that names it and must stay inside the
top-level policy's directory: no absolute paths or ``..`` (rejected by the schema), no symlinked
files, regular files only, the usual policy size limit. Packs and inline policies cannot extend
local files. Layers are ordered base first, the extending policy last; a layer reached twice is
used once, and layer names must be distinct.

Merging never lets a later layer quietly weaken an earlier one:

* context pins must agree; a later ``allow_cli_override`` cannot open a field an earlier layer
  pinned without allowing overrides;
* ``requirements`` and safety settings can only become stricter (``strict``, the rescan gate,
  JSON key scanning, ``unknown_sensitive_behavior`` ...); a weaker value is an error, not
  silently ignored;
* detectors an earlier layer runs cannot be disabled later;
* rules, classifications and transfers are concatenated; rule and classification ids must be
  unique across layers;
* a later rule that outranks an overlapping earlier rule and chooses a weaker action (block >
  review > transform > allow) is an error unless it names that rule in ``relaxes`` (reported as
  a warning). Earlier ``hard`` and ``guardrail`` rules can never be relaxed;
* a later default cannot weaken an earlier default it would take over, and a later ``allow``
  rule over an earlier non-allow default must name ``defaults:<selector>`` in ``relaxes``.

The effective digest covers every layer's file digest in order, so a change to any pack changes
it.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ciphergate.constants import HIGH_RISK_CATEGORIES, Action
from ciphergate.errors import PolicyValidationError, ValidationIssue
from ciphergate.models.policy import PolicyDocument, Rule
from ciphergate.policy.loader import (
    bundled_policies_dir,
    parse_policy_yaml,
    policy_digest,
    read_policy_bytes,
)
from ciphergate.policy.precedence import (
    category_selectors_overlap,
    matches_may_overlap,
    rule_level,
)

PACKS_DIR = "packs"
MAX_LAYER_DEPTH = 4
MAX_LAYERS = 8
LAYER_DIGEST_VERSION = "ciphergate-layers:v1"

_CONTEXT_FIELDS = ("environment", "target_environment", "destination", "domain_profile", "use_case")
# Settings where True is the stricter value.
_STRICT_TRUE = ("strict", "fail_on_parse_error", "scan_json_keys")
# For ordered settings, a higher index is stricter.
_ORDERED: dict[str, tuple[Any, ...]] = {
    "unknown_sensitive_behavior": ("review", "block"),
    "csv_duplicate_headers": ("disambiguate", "reject"),
    "malformed_record_action": ("drop_record", None),
}


@dataclass(frozen=True, slots=True)
class PolicyLayer:
    """One layer of an effective policy; safe to report (names and digests only)."""

    name: str
    kind: str  # "pack", "file" (a local layer) or "policy" (the top-level file)
    source: str | None
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "source": self.source, "digest": self.digest}


@dataclass(frozen=True)
class LayeredDocument:
    document: PolicyDocument
    layers: tuple[PolicyLayer, ...]
    digest: str
    rule_layers: dict[str, str] = field(default_factory=dict)
    default_layers: dict[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


@dataclass
class _Loaded:
    layer: PolicyLayer
    doc: PolicyDocument


def pack_names() -> list[str]:
    """Names accepted in ``extends``, sorted."""
    packs = bundled_policies_dir().joinpath(PACKS_DIR)
    if not packs.is_dir():
        return []
    return sorted(e.name.removesuffix(".yml") for e in packs.iterdir() if e.name.endswith(".yml"))


def read_pack_bytes(name: str) -> bytes:
    """Return a pack's bytes. ``name`` is only compared to known names, never used as a path."""
    if name not in pack_names():
        raise PolicyValidationError(
            "unknown policy pack in extends",
            issues=[
                ValidationIssue(
                    "extends", "unknown pack (see docs/policy-schema.md)", "unknown_pack"
                )
            ],
            code="unknown_policy_pack",
        )
    return bundled_policies_dir().joinpath(PACKS_DIR).joinpath(f"{name}.yml").read_bytes()


def _schema(raw: dict[str, Any], prefix: str) -> PolicyDocument:
    try:
        return PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        issues = []
        for err in exc.errors(include_url=False, include_input=False, include_context=False):
            loc = ".".join(str(p) for p in err.get("loc", ())) or "policy"
            msg = str(err.get("msg", "invalid value")).removeprefix("Value error, ")
            issues.append(ValidationIssue(f"{prefix}{loc}", msg, str(err.get("type"))))
        raise PolicyValidationError(
            f"policy pack failed schema validation ({len(issues)} issue(s))", issues=issues
        ) from None


def is_local_ref(ref: str) -> bool:
    """``extends`` entries with a slash or a YAML suffix name local files; others name packs."""
    return "/" in ref or ref.endswith((".yml", ".yaml"))


def _fail(message: str, detail: str, code: str) -> PolicyValidationError:
    return PolicyValidationError(
        message, issues=[ValidationIssue("extends", detail, code)], code=code
    )


def _local_file(ref: str, here: Path | None, root: Path | None) -> tuple[Path, str]:
    """Resolve a local ``extends`` entry; returns the real path and its path relative to root.

    Paths resolve against the directory of the file that names them and must stay inside the
    top-level policy's directory; symlinked files and anything that is not a regular file are
    rejected. Error messages repeat only the reference as written in the policy.
    """
    if here is None or root is None:
        raise _fail(
            "local files can only be extended from a policy file",
            f"'{ref}': packs and inline policies cannot extend local files",
            "local_extends_unavailable",
        )
    candidate = here / ref
    try:
        if candidate.is_symlink():
            raise _fail("policy layer is a symlink", f"'{ref}' is a symlink", "unsafe_extends_path")
        real = candidate.resolve(strict=True)
    except OSError as exc:
        raise _fail("policy layer not found", f"'{ref}' not found", "policy_not_found") from exc
    if not real.is_relative_to(root):
        raise _fail(
            "policy layer is outside the policy's directory",
            f"'{ref}' resolves outside the top-level policy's directory",
            "unsafe_extends_path",
        )
    return real, real.relative_to(root).as_posix()


def _collect(
    doc: PolicyDocument,
    out: list[_Loaded],
    seen: set[str],
    stack: tuple[str, ...],
    *,
    here: Path | None,
    root: Path | None,
) -> None:
    if len(stack) > MAX_LAYER_DEPTH + 1:  # the stack starts with the top-level policy
        raise PolicyValidationError(
            "policy layers nest too deeply",
            issues=[
                ValidationIssue("extends", f"more than {MAX_LAYER_DEPTH} levels", "layer_depth")
            ],
            code="policy_layer_depth",
        )
    for ref in doc.extends:
        real: Path | None = None
        if is_local_ref(ref):
            real, source = _local_file(ref, here, root)
            key, prefix = "file:" + os.path.normcase(str(real)), f"file[{source}]."
        else:
            source = f"{PACKS_DIR}/{ref}.yml"
            key, prefix = f"pack:{ref}", f"pack[{ref}]."
        if key in stack:
            raise _fail(
                "policy layers extend each other in a cycle",
                f"cycle through '{ref}'",
                "layer_cycle",
            )
        if key in seen:
            continue
        data = read_policy_bytes(real) if real is not None else read_pack_bytes(ref)
        layer_doc = _schema(parse_policy_yaml(data), prefix)
        if real is not None:
            layer = PolicyLayer(layer_doc.name, "file", source, policy_digest(data))
        else:
            layer = PolicyLayer(ref, "pack", source, policy_digest(data))
        next_here = real.parent if real is not None else None
        _collect(layer_doc, out, seen, (*stack, key), here=next_here, root=root)
        if key not in seen:
            seen.add(key)
            out.append(_Loaded(layer, layer_doc))
    if len(out) >= MAX_LAYERS:
        raise PolicyValidationError(
            "too many policy layers",
            issues=[ValidationIssue("extends", f"more than {MAX_LAYERS} layers", "layer_count")],
            code="policy_layer_count",
        )


def _rank(action: Action) -> int:
    if action == Action.BLOCK:
        return 3
    if action == Action.REVIEW:
        return 2
    if action == Action.ALLOW:
        return 0
    return 1


def _outranks(later: Rule, earlier: Rule) -> bool:
    a, b = rule_level(later), rule_level(earlier)
    return a < b or (a == b and later.priority > earlier.priority)


def _default_key(sel: str) -> tuple[int, int]:
    """Sort key matching ``Policy.default_for``: exact, then prefix globs (longest first), "*"."""
    return (2 if sel == "*" else (1 if sel.endswith(".*") else 0), -len(sel))


def _covers(default: str, selector: str) -> bool:
    if default == "*":
        return True
    if default.endswith(".*"):
        return selector.startswith(default[:-1])
    return default == selector


def _applicable_defaults(selector: str, defaults: Iterable[str]) -> list[str]:
    """Defaults that can decide some category matched by ``selector`` (shadowed ones excluded)."""
    overlapping = [d for d in defaults if category_selectors_overlap(selector, d)]
    covering = [d for d in overlapping if _covers(d, selector)]
    partial = [d for d in overlapping if d not in covering]
    return partial + ([min(covering, key=_default_key)] if covering else [])


class _Merger:
    def __init__(self, layers: list[_Loaded]) -> None:
        self.layers = layers
        self.issues: list[ValidationIssue] = []
        self.warnings: list[str] = []

    def issue(self, where: str, msg: str, code: str) -> None:
        self.issues.append(ValidationIssue(where, msg, code))

    def merge(self) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
        base = self.layers[0].doc
        merged: dict[str, Any] = base.model_dump()
        rule_layers = {r.id: self.layers[0].layer.name for r in base.rules}
        default_layers = dict.fromkeys(base.defaults, self.layers[0].layer.name)
        cls_layers = {c.id: self.layers[0].layer.name for c in base.classifications}
        pinned_by: dict[str, str] = {
            f: self.layers[0].layer.name for f in _CONTEXT_FIELDS if merged["context"][f]
        }
        earlier_rules: list[tuple[str, Rule]] = [(self.layers[0].layer.name, r) for r in base.rules]
        earlier_defaults: dict[str, tuple[str, Action]] = {
            sel: (self.layers[0].layer.name, spec.action) for sel, spec in base.defaults.items()
        }
        for loaded in self.layers[1:]:
            name, doc = loaded.layer.name, loaded.doc
            where = f"layer[{name}]"
            self._context(merged["context"], doc, where, pinned_by, name)
            self._requirements(merged["requirements"], doc, where)
            self._settings(merged["settings"], doc, where)
            self._detectors(merged["detectors"], doc, where)
            for cat in doc.custom_categories:
                if cat not in merged["custom_categories"]:
                    merged["custom_categories"].append(cat)
            for cls_ in doc.classifications:
                if cls_.id in cls_layers:
                    self.issue(
                        f"{where}.classifications",
                        f"classification '{cls_.id}' is already defined by layer "
                        f"'{cls_layers[cls_.id]}'; layers cannot redefine it",
                        "duplicate_id",
                    )
                cls_layers[cls_.id] = name
                merged["classifications"].append(cls_.model_dump())
            for rule in doc.rules:
                self._rule(rule, where, earlier_rules, earlier_defaults, rule_layers)
                rule_layers.setdefault(rule.id, name)
                merged["rules"].append(rule.model_dump())
            for sel, spec in doc.defaults.items():
                for old_sel in _applicable_defaults(sel, earlier_defaults):
                    old_layer, old_action = earlier_defaults[old_sel]
                    wins = old_sel == sel or _default_key(sel) < _default_key(old_sel)
                    if wins and _rank(spec.action) < _rank(old_action):
                        self.issue(
                            f"{where}.defaults.{sel}",
                            f"weakens default '{old_sel}' from layer '{old_layer}' "
                            f"('{old_action}' to '{spec.action}'); use a scoped rule with "
                            f"relaxes: ['defaults:{old_sel}'] instead",
                            "layer_weakens_default",
                        )
                merged["defaults"][sel] = spec.model_dump()
                default_layers[sel] = name
            for sel, spec in doc.defaults.items():
                earlier_defaults[sel] = (name, spec.action)
            earlier_rules.extend((name, r) for r in doc.rules)
            merged["transfers"].extend(t.model_dump() for t in doc.transfers)
            merged["name"] = doc.name
            merged["metadata"] = doc.metadata
            merged["extends"] = doc.extends
        return merged, rule_layers, default_layers

    def _context(
        self,
        ctx: dict[str, Any],
        doc: PolicyDocument,
        where: str,
        pinned_by: dict[str, str],
        name: str,
    ) -> None:
        later = doc.context
        for f in _CONTEXT_FIELDS:
            value = getattr(later, f)
            if value is None:
                continue
            if ctx[f] is not None and ctx[f] != value:
                self.issue(
                    f"{where}.context.{f}",
                    f"conflicts with the value pinned by layer '{pinned_by[f]}'",
                    "layer_context_conflict",
                )
                continue
            if ctx[f] is None:
                pinned_by[f] = name
            ctx[f] = value
        for f in later.allow_cli_override:
            if (
                ctx[f] is not None
                and pinned_by.get(f) != name
                and f not in ctx["allow_cli_override"]
            ):
                self.issue(
                    f"{where}.context.allow_cli_override",
                    f"cannot allow overriding '{f}': layer '{pinned_by[f]}' pins it without "
                    "allowing overrides",
                    "layer_weakens_context",
                )
            elif f not in ctx["allow_cli_override"]:
                ctx["allow_cli_override"].append(f)

    def _requirements(self, req: dict[str, Any], doc: PolicyDocument, where: str) -> None:
        for f in doc.requirements.model_fields_set:
            value = getattr(doc.requirements, f)
            if req[f] and not value:
                self.issue(
                    f"{where}.requirements.{f}",
                    "an earlier layer requires this context; a later layer cannot drop it",
                    "layer_weakens_setting",
                )
            req[f] = req[f] or value

    def _weaker(self, where: str, key: str) -> None:
        self.issue(
            f"{where}.settings.{key}",
            "is less strict than an earlier layer; a later layer can only tighten it",
            "layer_weakens_setting",
        )

    def _settings(self, settings: dict[str, Any], doc: PolicyDocument, where: str) -> None:
        later = doc.settings
        for key in later.model_fields_set:
            value = getattr(later, key)
            if key in _STRICT_TRUE:
                if settings[key] and not value:
                    self._weaker(where, key)
                settings[key] = settings[key] or value
            elif key in _ORDERED:
                order = _ORDERED[key]
                if order.index(value) < order.index(settings[key]):
                    self._weaker(where, key)
                else:
                    settings[key] = value
            elif key == "rescan":
                self._rescan(settings["rescan"], later.rescan, where)
            else:  # preserve_blank_lines, report_raw_values (always False): later wins
                settings[key] = value

    def _rescan(self, rescan: dict[str, Any], later: Any, where: str) -> None:
        if "enabled" in later.model_fields_set:
            if rescan["enabled"] and not later.enabled:
                self._weaker(where, "rescan.enabled")
            rescan["enabled"] = rescan["enabled"] or later.enabled
        if "fail_on_categories" in later.model_fields_set and later.fail_on_categories is not None:
            current = rescan["fail_on_categories"]
            # None means "every high-risk category"; keep that floor when lists are combined.
            floor = sorted(HIGH_RISK_CATEGORIES) if current is None else list(current)
            rescan["fail_on_categories"] = floor + [
                c for c in later.fail_on_categories if c not in floor
            ]

    def _detectors(self, det: dict[str, Any], doc: PolicyDocument, where: str) -> None:
        later = doc.detectors
        fields = later.model_fields_set
        if "disabled" in fields:
            newly = [d for d in later.disabled if d not in det["disabled"]]
            if newly:
                self.issue(
                    f"{where}.detectors.disabled",
                    "cannot disable detectors that an earlier layer runs",
                    "layer_weakens_detectors",
                )
        if (
            "reject_risky_regex" in fields
            and det["reject_risky_regex"]
            and not later.reject_risky_regex
        ):
            self.issue(
                f"{where}.detectors.reject_risky_regex",
                "is less strict than an earlier layer",
                "layer_weakens_setting",
            )
        if "dates_emit_generic" in fields:
            det["dates_emit_generic"] = later.dates_emit_generic
        if "internal_host_suffixes" in fields:
            det["internal_host_suffixes"] += [
                s for s in later.internal_host_suffixes if s not in det["internal_host_suffixes"]
            ]
        det["custom"] += [c.model_dump() for c in later.custom]
        if "presidio" in fields and "enabled" in later.presidio.model_fields_set:
            if det["presidio"]["enabled"] and not later.presidio.enabled:
                self.issue(
                    f"{where}.detectors.presidio.enabled",
                    "cannot turn off a detector that an earlier layer enables",
                    "layer_weakens_detectors",
                )
            elif later.presidio.enabled:
                det["presidio"] = later.presidio.model_dump()

    def _rule(
        self,
        rule: Rule,
        where: str,
        earlier_rules: list[tuple[str, Rule]],
        earlier_defaults: dict[str, tuple[str, Action]],
        rule_layers: dict[str, str],
    ) -> None:
        loc = f"{where}.rules.{rule.id}"
        if rule.id in rule_layers:
            self.issue(
                loc,
                f"rule id is already defined by layer '{rule_layers[rule.id]}'; layers cannot "
                "redefine rules (add a new rule, and use relaxes if it must weaken one)",
                "duplicate_id",
            )
        known = {r.id: (layer, r) for layer, r in earlier_rules}
        used: set[str] = set()
        for ref in rule.relaxes:
            if ref.startswith("defaults:"):
                if ref.removeprefix("defaults:") not in earlier_defaults:
                    self.issue(loc, f"relaxes names unknown '{ref}'", "unknown_relaxes")
            elif ref not in known:
                self.issue(
                    loc,
                    f"relaxes names rule '{ref}', not defined by an earlier layer",
                    "unknown_relaxes",
                )
        for layer, earlier in earlier_rules:
            if (
                _rank(rule.action) >= _rank(earlier.action)
                or not _outranks(rule, earlier)
                or not matches_may_overlap(rule.match, earlier.match)
            ):
                continue
            if earlier.hard or earlier.guardrail:
                self.issue(
                    loc,
                    f"would weaken {'hard' if earlier.hard else 'guardrail'} rule '{earlier.id}' "
                    f"from layer '{layer}'; hard and guardrail rules cannot be relaxed",
                    "layer_weakens_rule",
                )
            elif earlier.id in rule.relaxes:
                used.add(earlier.id)
                self.warnings.append(
                    f"rule '{rule.id}' relaxes rule '{earlier.id}' from layer '{layer}' "
                    f"('{earlier.action}' to '{rule.action}')"
                )
            else:
                self.issue(
                    loc,
                    f"outranks rule '{earlier.id}' from layer '{layer}' with a weaker action "
                    f"('{earlier.action}' to '{rule.action}'); narrow the selectors, or add "
                    f"relaxes: ['{earlier.id}'] if this is intended",
                    "layer_weakens_rule",
                )
        if rule.action == Action.ALLOW:
            applicable: list[str] = []
            for cat in rule.match.categories or ["*"]:
                applicable += [
                    d for d in _applicable_defaults(cat, earlier_defaults) if d not in applicable
                ]
            for sel in applicable:
                layer, action = earlier_defaults[sel]
                if action == Action.ALLOW:
                    continue
                if f"defaults:{sel}" in rule.relaxes:
                    used.add(f"defaults:{sel}")
                    self.warnings.append(
                        f"rule '{rule.id}' relaxes default '{sel}' from layer '{layer}' "
                        f"('{action}' to 'allow')"
                    )
                else:
                    self.issue(
                        loc,
                        f"allows categories that default '{sel}' from layer '{layer}' handles "
                        f"with '{action}'; add relaxes: ['defaults:{sel}'] if this is intended",
                        "layer_weakens_default",
                    )
        for ref in rule.relaxes:
            if ref not in used and (
                ref in known or ref.removeprefix("defaults:") in earlier_defaults
            ):
                self.warnings.append(f"rule '{rule.id}': relaxes '{ref}' has no effect")


def _digest(layers: list[PolicyLayer]) -> str:
    ids = (f"{x.kind}:{x.source if x.kind == 'file' else x.name}={x.digest}" for x in layers)
    text = "\n".join([LAYER_DIGEST_VERSION, *ids])
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def resolve_layers(
    doc: PolicyDocument,
    *,
    digest: str,
    source_name: str | None,
    path: Path | None = None,
) -> LayeredDocument:
    """Merge ``doc`` with the packs and local files it extends. Raises ``PolicyValidationError``.

    ``path`` is the top-level policy file; without it (inline text, templates) only packs can be
    extended.
    """
    loaded: list[_Loaded] = []
    top = path.resolve() if path is not None else None
    root = top.parent if top is not None else None
    start = ("file:" + os.path.normcase(str(top)),) if top is not None else ("policy",)
    _collect(doc, loaded, set(), start, here=root, root=root)
    loaded.append(_Loaded(PolicyLayer(doc.name, "policy", source_name, digest), doc))
    names = [x.layer.name for x in loaded]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise _fail(
            "policy layers must have distinct names",
            "layers share the name(s): " + ", ".join(duplicates),
            "duplicate_layer_name",
        )
    merger = _Merger(loaded)
    merged, rule_layers, default_layers = merger.merge()
    if merger.issues:
        raise PolicyValidationError(
            f"policy layers could not be merged ({len(merger.issues)} issue(s))",
            issues=merger.issues,
        )
    layers = [x.layer for x in loaded]
    return LayeredDocument(
        document=PolicyDocument.model_validate(merged),
        layers=tuple(layers),
        digest=_digest(layers),
        rule_layers=rule_layers,
        default_layers=default_layers,
        warnings=tuple(merger.warnings),
    )
