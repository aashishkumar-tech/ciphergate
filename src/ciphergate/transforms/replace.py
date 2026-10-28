"""Replacement with a configured synthetic constant (validated at policy load time)."""

from __future__ import annotations

from ciphergate.models.policy import ReplaceParams


def replace(params: ReplaceParams, *, in_span: bool) -> str | int | float | bool | None:
    """Inside free text (a span) the constant is inserted as text (``None`` -> ``null``)."""
    if in_span:
        if params.value is None:
            return "null"
        if isinstance(params.value, bool):
            return "true" if params.value else "false"
        return str(params.value)
    return params.value
