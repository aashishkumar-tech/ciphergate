"""logfmt format (#11): parser, field attribution, never weaker than text, transforms."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ciphergate import RunStatus, inspect_file, sanitize_file
from ciphergate.constants import InputFormat
from ciphergate.pipeline.sanitizer import SanitizeOptions
from ciphergate.policy.validator import Policy
from ciphergate.readers.logfmt_reader import LogfmtField, parse_fields
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, SYNTHETIC_SECRETS, ctx

DEV = ctx("dev", dest="local_dev")


def _with_rule(rule: str) -> str:
    return MINIMAL_POLICY.replace("rules:\n", "rules:\n" + rule, 1)


# ----------------------------------------------------------------------------- parser


def test_parse_fields_bare_quoted_and_free_text() -> None:
    line = 'ts=1 2026-01-05 level=info msg="a \\"b\\" c" empty= k.x-y=v'
    fields = parse_fields(line)
    assert fields is not None
    assert [(f.key, f.value) for f in fields] == [
        ("ts", "1"),
        ("level", "info"),
        ("msg", 'a "b" c'),
        ("empty", ""),
        ("k.x-y", "v"),
    ]
    msg = fields[2]
    assert line[msg.start : msg.end] == 'a \\"b\\" c'  # raw span inside the quotes


@pytest.mark.parametrize(
    "line",
    [
        'msg="unterminated',
        'msg="glued"x',
        'free "quoted text" k=v',
    ],
)
def test_malformed_quoting_gives_no_field_context(line: str) -> None:
    assert parse_fields(line) is None


@pytest.mark.parametrize(
    ("line", "keys"),
    [
        ("plain words only", []),
        ("=value 1=x a=b", ["a"]),  # keys must start with a letter or underscore
        ("url=https://example.invalid/a?b=c", ["url"]),  # '=' inside a bare value
        ("", []),
    ],
)
def test_parse_fields_edge_cases(line: str, keys: list[str]) -> None:
    fields = parse_fields(line)
    assert fields is not None and [f.key for f in fields] == keys


# ----------------------------------------------------------------------------- detection


def _findings(
    tmp_path: Path, text: str, fmt: InputFormat, policy: Policy
) -> list[dict[str, object]]:
    src = tmp_path / f"in-{fmt}.log"
    src.write_text(text, encoding="utf-8")
    return inspect_file(src, policy, DEV, fmt=fmt).items


def test_field_context_added(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    policy = policy_text(MINIMAL_POLICY)
    line = 'level=info customer_name="Alice Test" user_email=alice.test@example.com\n'
    items = _findings(tmp_path, line, InputFormat.LOGFMT, policy)
    paths = {(i["category"], i["location"].get("field_path")) for i in items}
    assert ("pii.person_name", "/customer_name") in paths
    assert ("pii.email", "/user_email") in paths
    text_items = _findings(tmp_path, line, InputFormat.TEXT, policy)
    assert not any(i["category"] == "pii.person_name" for i in text_items)


def test_field_rules_apply_to_content_findings(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: keep-support-email
    priority: 900
    match:
      categories: [pii.email]
      field_names: [support_contact]
    action: allow
"""
        )
    )
    line = "support_contact=help@example.com user_email=alice.test@example.com\n"
    items = _findings(tmp_path, line, InputFormat.LOGFMT, policy)
    decisions = {i["location"]["field_path"]: i["decision"]["action"] for i in items}
    assert decisions["/support_contact"] == "allow"
    assert decisions["/user_email"] != "allow"


def test_private_key_block_lines_never_parsed(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    text = (
        "level=info msg=start\n"
        "-----BEGIN PRIVATE KEY-----\n"  # TEST_ONLY synthetic header, no key material
        "TESTONLYabc=def==\n"
        "-----END PRIVATE KEY-----\n"
    )
    items = _findings(tmp_path, text, InputFormat.LOGFMT, policy)
    body = [i for i in items if i["location"]["line"] == 3]
    assert body and all(i["category"] == "credential.secret" for i in body)
    assert all(not i["location"].get("field_path") for i in body)  # body line: no fields


_TOKENS = st.sampled_from(
    [
        "level=info",
        "user_email=alice.test@example.com",
        'msg="call 202-555-0143 now"',
        "password=TEST_ONLY_NOT_A_CREDENTIAL",
        "ip=192.0.2.10",
        "card=4111111111111111",
        "words",
        '"quoted free"',
        "Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123",
        "token=",
        "a=b=c",
        "x",
    ]
)


@given(st.lists(st.lists(_TOKENS, max_size=6).map(" ".join), min_size=1, max_size=5))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_logfmt_never_finds_less_than_text(
    tmp_path_factory: pytest.TempPathFactory,
    policy_text: Callable[[str], Policy],
    lines: list[str],
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    tmp = tmp_path_factory.mktemp("lf")
    text = "\n".join(lines) + "\n"
    as_text = _findings(tmp, text, InputFormat.TEXT, policy)
    as_logfmt = _findings(tmp, text, InputFormat.LOGFMT, policy)

    def keyed(items: list[dict[str, object]]) -> set[tuple[object, ...]]:
        out = set()
        for i in items:
            loc = i["location"]
            assert isinstance(loc, dict)
            out.add((i["category"], loc["line"], tuple(loc.get("span") or ())))
        return out

    assert keyed(as_text) <= keyed(as_logfmt)


# ----------------------------------------------------------------------------- transforms


def test_sanitize_preserves_quoting_and_free_text(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    src = tmp_path / "app.log"
    src.write_bytes(  # bytes: no newline translation, so the mixed endings are exact
        b'2026-01-05T10:00:00Z level=warn msg="retry \\"pay\\"" '
        b"user_email=alice.test@example.com\r\n"
        b'customer_name="Alice Test" n=1\n'
    )
    out = tmp_path / "out.log"
    r = sanitize_file(src, out, policy, DEV, SanitizeOptions(format=InputFormat.LOGFMT))
    assert r.status == RunStatus.SANITIZED
    data = out.read_bytes().decode("utf-8")
    first, second = data.split("\r\n")
    assert first.startswith('2026-01-05T10:00:00Z level=warn msg="retry \\"pay\\"" user_email=')
    assert "alice.test" not in data and "Alice Test" not in data
    assert second.startswith('customer_name="') and second.endswith('" n=1\n')
    fields = parse_fields(second.rstrip("\n"))
    assert fields is not None and [f.key for f in fields] == ["customer_name", "n"]
    for secret in SYNTHETIC_SECRETS:
        assert secret not in data


def test_pseudonym_scope_uses_each_field(
    tmp_path: Path, policy_text: Callable[[str], Policy], keys: KeyProvider
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: pz-email
    priority: 900
    match: {categories: [pii.email]}
    action: pseudonymize
    params: {scope: field, prefix: "e_"}
"""
        )
    )
    src = tmp_path / "app.log"
    src.write_text(
        "from=alice.test@example.com to=alice.test@example.com\nfrom=alice.test@example.com\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.log"
    r = sanitize_file(src, out, policy, DEV, SanitizeOptions(format=InputFormat.LOGFMT, keys=keys))
    assert r.status == RunStatus.SANITIZED
    first, second = (parse_fields(x) for x in out.read_text(encoding="utf-8").splitlines())
    assert first is not None and second is not None
    values = {f.key: f.value for f in first}
    assert values["from"] != values["to"]  # field scope: different fields do not link
    assert second[0].value == values["from"]  # same field, same value: stable


def test_drop_field_becomes_review(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: drop-email
    priority: 900
    match: {categories: [pii.email]}
    action: drop_field
"""
        )
    )
    src = tmp_path / "app.log"
    src.write_text("user_email=alice.test@example.com\n", encoding="utf-8")
    out = tmp_path / "o.log"
    r = sanitize_file(src, out, policy, DEV, SanitizeOptions(format=InputFormat.LOGFMT))
    assert r.status == RunStatus.REVIEW_REQUIRED and not out.exists()


def test_field_value_is_list_of_fields() -> None:
    assert parse_fields("a=1") == [LogfmtField("a", "1", 2, 3)]
