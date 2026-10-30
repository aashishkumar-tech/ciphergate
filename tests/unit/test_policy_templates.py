"""Packaged policy templates through the public Python API."""

from __future__ import annotations

from pathlib import Path

import pytest

import ciphergate
from ciphergate import (
    ContextInput,
    RunStatus,
    load_policy,
    load_template,
    sanitize_file,
    template_names,
)
from ciphergate.errors import CipherGateError, UsageError
from tests.conftest import EXAMPLES, POLICIES


def test_public_exports() -> None:
    for name in ("load_template", "template_names"):
        assert name in ciphergate.__all__ and hasattr(ciphergate, name)


def test_names_match_the_policy_files() -> None:
    assert template_names() == sorted(p.stem for p in POLICIES.glob("*.yml"))


@pytest.mark.parametrize("name", template_names())
def test_load_template_matches_the_policy_file(name: str) -> None:
    policy = load_template(name)
    assert policy.name == load_policy(POLICIES / f"{name}.yml").name
    assert policy.source_name == f"{name}.yml"


@pytest.mark.parametrize("name", ["nope", "../pyproject", "dev_local.yml", ""])
def test_unknown_template_is_rejected(name: str) -> None:
    with pytest.raises(UsageError) as err:
        load_template(name)
    assert err.value.code == "unknown_policy_template"
    assert isinstance(err.value, CipherGateError)


def test_loaded_template_still_blocks_and_publishes_nothing(tmp_path: Path) -> None:
    output = tmp_path / "out.log"
    report = sanitize_file(
        EXAMPLES / "sample.log",
        output,
        load_template("prd_external_ai"),
        ContextInput(),
    )
    assert report.status == RunStatus.BLOCKED and report.exit_code == 1
    assert not output.exists()
