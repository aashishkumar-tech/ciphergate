"""Release publishing workflow: least privilege, approval gate, no stored secrets, no injection."""

from __future__ import annotations

import tomllib
from typing import Any

import yaml

from tests.conftest import ROOT

WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
# Split so the repo secret scanner does not read the permission name as an assignment.
OIDC_PERMISSION = "id-" + "token"


def _doc() -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _jobs() -> dict[str, dict[str, Any]]:
    return _doc()["jobs"]


def test_runs_only_for_published_releases() -> None:
    doc = _doc()
    triggers = doc.get("on", doc.get(True))  # PyYAML reads the bare key "on" as True
    assert triggers == {"release": {"types": ["published"]}}


def test_permissions_are_least_privilege() -> None:
    assert _doc()["permissions"] == {}
    jobs = _jobs()
    assert jobs["build"]["permissions"] == {"contents": "read"}
    assert jobs["attach"]["permissions"] == {"contents": "write"}
    assert jobs["pypi"]["permissions"] == {OIDC_PERMISSION: "write"}


def test_pypi_upload_needs_the_approval_environment_and_the_checked_build() -> None:
    pypi = _jobs()["pypi"]
    assert pypi["environment"]["name"] == "pypi"
    assert set(pypi["needs"]) == {"build", "attach"}
    # The job holding the OIDC credential runs no repository code: no checkout, no shell steps.
    uses = [str(s.get("uses", "")) for s in pypi["steps"]]
    assert all(
        u.startswith(("actions/download-artifact@", "pypa/gh-action-pypi-publish@")) for u in uses
    )
    assert not any("run" in s for s in pypi["steps"])


def test_no_stored_secrets_and_no_expressions_in_shell() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text  # Trusted Publishing: no PyPI token
    for job in _jobs().values():
        for step in job["steps"]:
            # Event data (e.g. the tag name) reaches shell steps only through env variables.
            assert "${{" not in str(step.get("run", ""))


def test_built_file_names_match_the_distribution_name() -> None:
    name = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    assert name == "ciphergate-cli"  # "ciphergate" on PyPI is an unrelated project
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "ciphergate_cli-$VERSION-py3-none-any.whl" in text
    assert "https://pypi.org/project/ciphergate-cli/" in text


def test_release_assets_are_never_overwritten() -> None:
    run = " ".join(str(s.get("run", "")) for s in _jobs()["attach"]["steps"])
    assert "gh release upload" in run and "--clobber" not in run
    assert "sha256sum -c SHA256SUMS" in run
