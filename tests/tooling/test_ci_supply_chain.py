"""CI supply-chain rules: SHA-pinned actions, no persisted token, tested dependency floors."""

from __future__ import annotations

import re
import tomllib

import yaml

from tests.conftest import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+)*$")


def _steps() -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job in doc["jobs"].values():
            steps.extend(job.get("steps", []))
    return steps


def test_workflows_exist() -> None:
    assert WORKFLOWS


def test_actions_pinned_to_full_commit_sha() -> None:
    # yaml drops the trailing comment, so check the raw lines for "<sha> # vX.Y.Z".
    for wf in WORKFLOWS:
        for line in wf.read_text(encoding="utf-8").splitlines():
            stripped = line.strip().removeprefix("- ")
            if stripped.startswith("uses:"):
                ref = stripped.removeprefix("uses:").strip()
                if ref.startswith("./"):
                    continue  # local action: versioned with the repository
                assert SHA_PIN.match(ref), f"{wf.name}: action not pinned to a commit SHA"


def test_checkout_does_not_persist_credentials() -> None:
    checkouts = [s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts
    for step in checkouts:
        assert step.get("with", {}).get("persist-credentials") is False  # type: ignore[union-attr]


def test_min_constraints_match_pyproject_lower_bounds() -> None:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "dependencies"
    ]
    floors = {}
    for dep in deps:
        m = re.match(r"^([A-Za-z0-9_.-]+)>=([0-9][0-9.]*)", dep)
        assert m, f"runtime dependency without a lower bound: {dep}"
        floors[m.group(1).lower()] = m.group(2)
    pins = {}
    for raw in (ROOT / "ci" / "constraints-min.txt").read_text(encoding="utf-8").splitlines():
        spec = raw.split("#", 1)[0].strip()
        if spec:
            name, version = spec.split("==")
            pins[name.lower()] = version
    assert pins.keys() == floors.keys()
    for name, floor in floors.items():
        assert pins[name].split(".")[: len(floor.split("."))] == floor.split("."), name
