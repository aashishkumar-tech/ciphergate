"""Raw values, secrets and keys must not appear in reports, logs, exceptions or terminal output."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import SanitizeOptions, inspect_file, plan_file, sanitize_file
from ciphergate.errors import CipherGateError
from ciphergate.policy.validator import Policy
from ciphergate.reporting.safe_text import escape_control, safe_field_path
from ciphergate.reporting.serializer import report_to_json
from ciphergate.reporting.terminal import render_summary
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, ctx

ADVERSARIAL_LOG = "\n".join(
    [
        "user alice.test@example.com paid with 4111 1111 1111 1111",
        "Authorization: Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123",
        "export AWS_ACCESS_KEY_ID=AKIATESTONLYNOTREAL1",
        "postgres://svc:TEST_ONLY_DB_PW_9@db.example.invalid:5432/app",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "TESTONLYPRIVATEKEYBODYLINE",
        "-----END OPENSSH PRIVATE KEY-----",
        'escaped {\\"password\\": \\"TEST_ONLY_ESCAPED_PW\\"}',
        "ansi \x1b[31mred\x1b[0m and bidi \u202e reversed",
    ]
)
RAW = [
    "alice.test@example.com",
    "4111 1111 1111 1111",
    "TEST_ONLY_NOT_A_REAL_TOKEN_123",
    "AKIATESTONLYNOTREAL1",
    "TEST_ONLY_DB_PW_9",
    "TESTONLYPRIVATEKEYBODYLINE",
    "TEST_ONLY_ESCAPED_PW",
]


def assert_clean(blob: str, extra: list[str] | None = None) -> None:
    for value in RAW + (extra or []):
        assert value not in blob, value
    assert "\x1b" not in blob and "\u202e" not in blob


@pytest.mark.parametrize(
    "policy_name", ["developer_logs.yml", "prd_external_ai.yml", "external_ai.yml"]
)
def test_reports_and_summaries_have_no_values(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_file: Callable[[str], Policy],
    policy_name: str,
    hmac_key: str,
) -> None:
    src = write("adv.log", ADVERSARIAL_LOG)
    p = policy_file(policy_name)
    keys = KeyProvider({"CIPHERGATE_HMAC_KEY": hmac_key})
    pins = p.document.context
    context = ctx(
        None if pins.environment else "dev", dest=None if pins.destination else "local_dev"
    )
    for report in (inspect_file(src, p, context, keys=keys), plan_file(src, p, context, keys=keys)):
        assert_clean(report_to_json(report), [hmac_key[4:]])
        assert_clean(render_summary(report, verbose=True), [hmac_key[4:]])


def test_sanitized_output_and_report_clean(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_file: Callable[[str], Policy],
) -> None:
    src = write("adv.log", ADVERSARIAL_LOG)
    out = tmp_path / "o.log"
    r = sanitize_file(src, out, policy_file("developer_logs.yml"), ctx("dev", dest="local_dev"))
    for value in RAW:
        assert value not in out.read_text(encoding="utf-8"), value
    assert_clean(report_to_json(r))


def test_logging_never_receives_values(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    src = write("adv.log", ADVERSARIAL_LOG)
    sanitize_file(src, tmp_path / "o.log", policy_text(MINIMAL_POLICY))
    assert_clean(caplog.text)


def test_exceptions_have_no_values(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
) -> None:
    bad = write("bad.jsonl", '{"password": "TEST_ONLY_NOT_A_REAL_TOKEN_123", oops}\n')
    with pytest.raises(CipherGateError) as info:
        inspect_file(bad, policy_text(MINIMAL_POLICY))
    assert_clean(str(info.value) + repr(info.value))
    assert info.value.__cause__ is None or "TEST_ONLY" not in str(info.value)


def test_json_keys_and_csv_headers_masked_in_reports(
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
) -> None:
    src = write("k.json", json.dumps({"alice.test@example.com": {"phone": "+1 202 555 0143"}}))
    report = inspect_file(src, policy_text(MINIMAL_POLICY))
    blob = report_to_json(report)
    assert "alice.test" not in blob and "<redacted-key>" in blob
    assert safe_field_path("/users/0/email") == "/users/0/email"


def test_escape_control() -> None:
    assert escape_control("a\x1b[2Jb\r\n\u202ec") == "a\\x1b[2Jb\\x0d\\x0a\\u202ec"
    assert len(escape_control("x" * 1000)) == 200


def test_no_unkeyed_fingerprints_in_reports(
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
) -> None:
    import hashlib

    src = write("e.log", "user alice.test@example.com\n")
    blob = report_to_json(inspect_file(src, policy_text(MINIMAL_POLICY)))
    for algo in ("sha256", "sha1", "md5"):
        digest = hashlib.new(algo, b"alice.test@example.com").hexdigest()
        assert digest[:12] not in blob


def test_key_never_written_anywhere(
    tmp_path: Path,
    policy_file: Callable[[str], Policy],
    hmac_key: str,
) -> None:
    from tests.conftest import EXAMPLES

    out = tmp_path / "o.csv"
    r = sanitize_file(
        EXAMPLES / "sample.csv",
        out,
        policy_file("prd_external_ai.yml"),
        options=SanitizeOptions(keys=KeyProvider({"CIPHERGATE_HMAC_KEY": hmac_key})),
    )
    for blob in (out.read_text(encoding="utf-8"), report_to_json(r), render_summary(r)):
        assert hmac_key not in blob and hmac_key[4:20] not in blob
