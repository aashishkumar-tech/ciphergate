"""Absent rules, keys or context must never resolve to an allow / published output."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ciphergate import RunStatus, sanitize_file
from ciphergate.policy.validator import Policy
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import ctx

EMPTY = "policy_version: 1\nname: empty\nrequirements: {environment: false, destination: false}\n"


def test_no_rules_means_review_not_allow(
    tmp_path: Path, write: Callable[[str, str | bytes], Path], policy_text: Callable[[str], Policy]
) -> None:
    out = tmp_path / "o.log"
    r = sanitize_file(write("in.log", "mail alice.test@example.com\n"), out, policy_text(EMPTY))
    assert r.status == RunStatus.REVIEW_REQUIRED and not out.exists()
    assert r.summary["by_reason_code"] == {"no_applicable_rule_requires_review": 1}


def test_findings_free_input_passes_but_with_disclaimer(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
) -> None:
    out = tmp_path / "o.log"
    r = sanitize_file(write("in.log", "nothing to see\n"), out, policy_text(EMPTY))
    assert r.status == RunStatus.SANITIZED
    assert "does not prove" in r.to_dict()["disclaimer"]


def test_unknown_destination_never_trusted(
    tmp_path: Path, write: Callable[[str, str | bytes], Path], policy_file: Callable[[str], Policy]
) -> None:
    out = tmp_path / "o.log"
    r = sanitize_file(
        write("in.log", "host api-1.prod.internal\n"),
        out,
        policy_file("developer_logs.yml"),
        ctx("dev", dest="unknown"),
    )
    assert r.status == RunStatus.REVIEW_REQUIRED and not out.exists()


def test_missing_key_never_falls_back(
    tmp_path: Path, write: Callable[[str, str | bytes], Path], policy_file: Callable[[str], Policy]
) -> None:
    from ciphergate import SanitizeOptions

    out = tmp_path / "o.csv"
    r = sanitize_file(
        write("in.csv", "email\nalice.test@example.com\n"),
        out,
        policy_file("test_dataset.yml"),
        ctx("dev", dest="local_dev"),
        SanitizeOptions(keys=KeyProvider({"CIPHERGATE_HMAC_KEY": "short"})),
    )
    assert r.status == RunStatus.CONFIGURATION_REQUIRED and not out.exists()
    assert r.keys[0]["status"] == "too_short"


def test_secret_block_shows_only_metadata(
    tmp_path: Path, write: Callable[[str, str | bytes], Path], policy_file: Callable[[str], Policy]
) -> None:
    out = tmp_path / "o.log"
    r = sanitize_file(
        write("in.log", "token=TEST_ONLY_NOT_A_CREDENTIAL\n"),
        out,
        policy_file("external_ai.yml"),
        ctx("dev"),
    )
    assert r.status == RunStatus.BLOCKED and r.exit_code == 1 and not out.exists()
    item = r.items[0]
    assert set(item) == {
        "category",
        "detector",
        "confidence",
        "band",
        "evidence",
        "value_type",
        "location",
        "decision",
    }
    assert item["decision"]["reason_code"] == "credential_detected_hard_block"
