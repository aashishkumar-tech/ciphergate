"""Starter policy templates shipped with the package. Every template requires review before use."""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from ciphergate.errors import UsageError


def _templates_dir() -> Traversable:
    packaged = resources.files("ciphergate").joinpath("policies")
    if packaged.is_dir():
        return packaged
    # Editable install: the build copies policies/ into wheels only, so use the source checkout.
    return Path(__file__).resolve().parents[3] / "policies"


def template_names() -> list[str]:
    """Names accepted by `read_template`, sorted."""
    return sorted(
        entry.name.removesuffix(".yml")
        for entry in _templates_dir().iterdir()
        if entry.name.endswith(".yml")
    )


def read_template(name: str) -> str:
    """Return a template's text. `name` is only compared to known names, never used as a path."""
    if name not in template_names():
        raise UsageError(
            "unknown policy template; run: ciphergate init --list-templates",
            code="unknown_policy_template",
        )
    return _templates_dir().joinpath(f"{name}.yml").read_text(encoding="utf-8")
