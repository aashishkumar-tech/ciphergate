"""Regression tests: golden example outputs and bugs fixed during development."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import RunStatus, inspect_file, sanitize_file
from ciphergate.detectors.secrets import SecretDetector
from ciphergate.models.finding import ScanItem
from ciphergate.policy.validator import Policy
from ciphergate.readers import detect_format
from tests.conftest import EXAMPLES, MINIMAL_POLICY, ctx


@pytest.mark.parametrize("name", ["sample.csv", "sample.json", "sample.jsonl", "sample.log"])
def test_golden_examples(tmp_path: Path, policy_file: Callable[[str], Policy], name: str) -> None:
    out = tmp_path / name
    r = sanitize_file(
        EXAMPLES / name, out, policy_file("developer_logs.yml"), ctx("dev", dest="local_dev")
    )
    assert r.status == RunStatus.SANITIZED
    expected = EXAMPLES / "expected" / name.replace("sample", "sample.dev_local_dev")
    assert out.read_bytes() == expected.read_bytes()


def test_sanitizing_twice_is_idempotent(
    tmp_path: Path, policy_file: Callable[[str], Policy]
) -> None:
    p = policy_file("developer_logs.yml")
    first = EXAMPLES / "expected" / "sample.dev_local_dev.log"
    out = tmp_path / "again.log"
    sanitize_file(first, out, p, ctx("dev", dest="local_dev"))
    assert out.read_bytes() == first.read_bytes()


def test_regression_plain_token_assignment_detected() -> None:
    # Found by tests/security: "token=..." was not covered by the assignment family.
    item = ScanItem(0, 1, "", None, "token=TEST_ONLY_NOT_A_CREDENTIAL")
    assert SecretDetector().detect(item)


def test_regression_json_sniff_rejects_csv_content(
    write: Callable[[str, str | bytes], Path],
) -> None:
    # 'n' (for null) previously let CSV text named *.json through the content check.
    from ciphergate.errors import InputFormatError

    with pytest.raises(InputFormatError):
        detect_format(write("x.json", "name,email\n"))


def test_regression_max_confidence_miss_is_not_threshold_reason(
    policy_text: Callable[[str], Policy],
    write: Callable[[str, str | bytes], Path],
) -> None:
    p = policy_text(
        MINIMAL_POLICY.replace(
            "rules:\n",
            "rules:\n  - id: low\n    priority: 900\n    match: {max_confidence: 0.1}\n"
            "    action: review\n",
        )
    )
    r = inspect_file(write("a.log", "alice.test@example.com\n"), p)
    assert "confidence_below_rule_threshold" not in r.summary["by_reason_code"]
