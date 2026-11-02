"""Local-file layers in `extends`: resolution, confinement, cycles, digest and provenance."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.config import RuntimeSettings
from ciphergate.errors import PolicyValidationError
from ciphergate.pipeline.sanitizer import SanitizeOptions, sanitize_file
from ciphergate.policy import layers
from ciphergate.policy.validator import load_policy_text
from tests.conftest import POLICIES

ORG = """policy_version: 1
name: org-base
extends: [us_hipaa]
classifications:
  - {id: org-ids, field_names: [visit_number], category: pii.customer_identifier}
"""
HOSPITAL = """policy_version: 1
name: hospital
extends: ["org/base.yml"]
context: {destination: approved_internal, environment: prd}
"""


def tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def codes(path: Path) -> set[str]:
    with pytest.raises(PolicyValidationError) as exc:
        load_policy(path)
    return {i.code for i in exc.value.issues} | {exc.value.code}


def symlink_or_skip(link: Path, target: Path, *, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def test_local_layer_sits_between_packs_and_the_policy(tmp_path: Path) -> None:
    tree(tmp_path, {"org/base.yml": ORG, "hospital.yml": HOSPITAL})
    policy = load_policy(tmp_path / "hospital.yml")
    assert [(x.name, x.kind) for x in policy.layers] == [
        ("healthcare_baseline", "pack"),
        ("us_hipaa", "pack"),
        ("org-base", "file"),
        ("hospital", "policy"),
    ]
    assert policy.layers[2].source == "org/base.yml"
    assert any(c.id == "org-ids" for c in policy.document.classifications)


def test_paths_resolve_against_the_file_that_names_them(tmp_path: Path) -> None:
    org = ORG.replace("extends: [us_hipaa]", 'extends: [us_hipaa, "common.yml"]')
    common = "policy_version: 1\nname: org-common\n"
    tree(tmp_path, {"org/base.yml": org, "org/common.yml": common, "hospital.yml": HOSPITAL})
    policy = load_policy(tmp_path / "hospital.yml")
    sources = [x.source for x in policy.layers if x.kind == "file"]
    assert sources == ["org/common.yml", "org/base.yml"]


def test_local_layers_cannot_weaken_earlier_layers(tmp_path: Path) -> None:
    weak = ORG + "settings: {strict: false}\n"
    tree(tmp_path, {"org/base.yml": weak, "hospital.yml": HOSPITAL})
    assert "layer_weakens_setting" in codes(tmp_path / "hospital.yml")


@pytest.mark.parametrize(
    "ref",
    ["../outside.yml", "org/../../outside.yml", "/etc/policy.yml", "C:/policy.yml", "org\base.yml"],
)
def test_paths_outside_the_directory_are_rejected_by_the_schema(tmp_path: Path, ref: str) -> None:
    tree(tmp_path, {"hospital.yml": HOSPITAL.replace('"org/base.yml"', f"'{ref}'")})
    with pytest.raises(PolicyValidationError):
        load_policy(tmp_path / "hospital.yml")


def test_symlinked_directory_cannot_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    tree(outside, {"base.yml": ORG})
    inside = tmp_path / "policies"
    tree(inside, {"hospital.yml": HOSPITAL.replace("org/base.yml", "link/base.yml")})
    symlink_or_skip(inside / "link", outside, is_dir=True)
    assert "unsafe_extends_path" in codes(inside / "hospital.yml")


def test_symlinked_file_is_rejected(tmp_path: Path) -> None:
    tree(tmp_path, {"real.yml": ORG, "hospital.yml": HOSPITAL.replace("org/base.yml", "base.yml")})
    symlink_or_skip(tmp_path / "base.yml", tmp_path / "real.yml")
    assert "unsafe_extends_path" in codes(tmp_path / "hospital.yml")


def test_missing_file_and_directory_are_rejected(tmp_path: Path) -> None:
    tree(tmp_path, {"hospital.yml": HOSPITAL})
    assert "policy_not_found" in codes(tmp_path / "hospital.yml")
    (tmp_path / "org" / "base.yml").mkdir(parents=True)
    assert "policy_not_found" in codes(tmp_path / "hospital.yml")


def test_cycles_are_rejected(tmp_path: Path) -> None:
    tree(
        tmp_path,
        {
            "a.yml": 'policy_version: 1\nname: a\nextends: ["b.yml"]\n',
            "b.yml": 'policy_version: 1\nname: b\nextends: ["a.yml"]\n',
            "self.yml": 'policy_version: 1\nname: me\nextends: ["self.yml"]\n',
        },
    )
    assert "layer_cycle" in codes(tmp_path / "a.yml")
    assert "layer_cycle" in codes(tmp_path / "self.yml")


def test_inline_policies_and_packs_cannot_extend_local_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(PolicyValidationError) as exc:
        load_policy_text('policy_version: 1\nname: x\nextends: ["base.yml"]\n')
    assert exc.value.code == "local_extends_unavailable"
    root = tmp_path / "shipped"
    shutil.copytree(POLICIES, root)
    (root / "packs" / "sneaky.yml").write_text(
        'policy_version: 1\nname: sneaky\nextends: ["base.yml"]\n', encoding="utf-8"
    )
    monkeypatch.setattr(layers, "bundled_policies_dir", lambda: root)
    tree(tmp_path, {"p.yml": "policy_version: 1\nname: p\nextends: [sneaky]\n", "base.yml": ORG})
    assert "local_extends_unavailable" in codes(tmp_path / "p.yml")


def test_layer_names_must_be_distinct(tmp_path: Path) -> None:
    tree(tmp_path, {"org/base.yml": ORG.replace("org-base", "hospital"), "hospital.yml": HOSPITAL})
    assert "duplicate_layer_name" in codes(tmp_path / "hospital.yml")


def test_digest_changes_when_a_local_layer_changes(tmp_path: Path) -> None:
    tree(tmp_path, {"org/base.yml": ORG, "hospital.yml": HOSPITAL})
    before = load_policy(tmp_path / "hospital.yml").digest
    tree(tmp_path, {"org/base.yml": ORG + "# reviewed again\n"})
    assert load_policy(tmp_path / "hospital.yml").digest != before


def test_report_hides_local_layer_paths_when_redacted(tmp_path: Path) -> None:
    tree(tmp_path, {"org/base.yml": ORG, "hospital.yml": HOSPITAL, "data.csv": "age\n93\n"})
    policy = load_policy(tmp_path / "hospital.yml")
    report = sanitize_file(
        tmp_path / "data.csv",
        tmp_path / "out.csv",
        policy,
        options=SanitizeOptions(runtime=RuntimeSettings(path_display="redacted")),
    )
    assert str(report.status) == "sanitized"
    shown = [(x["name"], x["source"]) for x in report.to_dict()["policy"]["layers"]]
    assert shown == [
        ("healthcare_baseline", "packs/healthcare_baseline.yml"),
        ("us_hipaa", "packs/us_hipaa.yml"),
        ("org-base", None),
        ("hospital", None),
    ]


def test_bad_path_error_is_readable(tmp_path: Path) -> None:
    tree(tmp_path, {"hospital.yml": HOSPITAL.replace('"org/base.yml"', "'../x.yml'")})
    with pytest.raises(PolicyValidationError) as exc:
        load_policy(tmp_path / "hospital.yml")
    message = exc.value.issues[0].message
    assert "relative .yml/.yaml path" in message and "^(?:" not in message
