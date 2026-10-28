"""Safe YAML loading for policies.

* Uses ``yaml.SafeLoader`` (no arbitrary tags, no object construction).
* Rejects duplicate mapping keys (PyYAML silently keeps the last one by default).
* Rejects anchors/aliases, which enable "billion laughs" expansion and make policies harder
  to review.
* Enforces a size limit before parsing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node

from ciphergate.errors import PolicyValidationError, ValidationIssue

MAX_POLICY_BYTES = 1024 * 1024


class _StrictSafeLoader(yaml.SafeLoader):
    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            line = event.start_mark.line + 1 if event.start_mark else 0
            raise PolicyValidationError(
                "YAML anchors/aliases are not allowed in policies",
                issues=[ValidationIssue(f"line {line}", "alias not allowed", "yaml_alias")],
                code="policy_yaml_alias",
            )
        node: Node | None = super().compose_node(parent, index)
        return node

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str | int | bool | float) and key is not None:
                raise PolicyValidationError(
                    "policy mapping keys must be scalars",
                    issues=[_issue_at(key_node, "non-scalar key", "yaml_key")],
                )
            if key in seen:
                raise PolicyValidationError(
                    "duplicate key in policy YAML",
                    issues=[_issue_at(key_node, f"duplicate key '{key}'", "yaml_duplicate_key")],
                    code="policy_duplicate_key",
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _issue_at(node: Node, message: str, code: str) -> ValidationIssue:
    line = node.start_mark.line + 1 if node.start_mark else 0
    return ValidationIssue(f"line {line}", message, code)


def read_policy_bytes(path: str | Path) -> bytes:
    p = Path(path)
    try:
        if not p.is_file():
            raise PolicyValidationError(
                "policy file not found or not a regular file", code="policy_not_found"
            )
        size = p.stat().st_size
        if size > MAX_POLICY_BYTES:
            raise PolicyValidationError(
                f"policy file exceeds {MAX_POLICY_BYTES} bytes", code="policy_too_large"
            )
        return p.read_bytes()
    except OSError as exc:
        raise PolicyValidationError(
            "policy file could not be read", code="policy_unreadable"
        ) from exc


def parse_policy_yaml(data: bytes) -> dict[str, Any]:
    """Parse YAML bytes into a plain mapping, with safe, value-free error messages."""
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyValidationError("policy exceeds size limit", code="policy_too_large")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyValidationError(
            "policy file is not valid UTF-8", code="policy_encoding"
        ) from exc
    try:
        loaded = yaml.load(text, Loader=_StrictSafeLoader)  # noqa: S506 - strict SafeLoader subclass
    except PolicyValidationError:
        raise
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown position"
        raise PolicyValidationError(
            "policy YAML syntax error",
            issues=[ValidationIssue(where, "YAML syntax error", "yaml_syntax")],
            code="policy_yaml_syntax",
        ) from exc
    except yaml.YAMLError as exc:
        raise PolicyValidationError(
            "policy YAML could not be parsed", code="policy_yaml_syntax"
        ) from exc
    if not isinstance(loaded, dict):
        raise PolicyValidationError(
            "policy document must be a YAML mapping", code="policy_not_mapping"
        )
    return loaded


def policy_digest(data: bytes) -> str:
    """Digest of the policy file contents. Policies reference keys by env-var name only."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
