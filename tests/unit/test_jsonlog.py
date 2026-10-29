"""JSON-in-log format (#39): parser, span snapping, JSON-safe rewriting and the text superset."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ciphergate import RunStatus, inspect_file, sanitize_file
from ciphergate.constants import InputFormat
from ciphergate.errors import TransformError
from ciphergate.pipeline.sanitizer import SanitizeOptions
from ciphergate.policy.validator import Policy
from ciphergate.readers import line_structure
from ciphergate.readers.jsonlog_reader import JSONLOG_STRUCTURE, MAX_CANDIDATES, parse_regions
from ciphergate.readers.line_structure import SpanCodec, region_tokens, snap_span
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, SYNTHETIC_SECRETS, ctx

DEV = ctx("dev", dest="local_dev")
LINE = (
    '2026-01-05T10:00:00Z ERROR login failed {"user": {"email": "alice.test@example.com", '
    '"customer_name": "Testa Fakename", "user_id": 12345}, "tags": ["a", "b"]} retry=1'
)


def _with_rule(rule: str) -> str:
    return MINIMAL_POLICY.replace("rules:\n", "rules:\n" + rule, 1)


def _objects(line: str) -> list[object]:
    """Every embedded object of a line, decoded with the standard library parser."""
    decoder = json.JSONDecoder()
    out, i = [], 0
    while (start := line.find("{", i)) >= 0:
        try:
            obj, end = decoder.raw_decode(line, start)
        except ValueError:
            i = start + 1
            continue
        out.append(obj)
        i = end
    return out


# ----------------------------------------------------------------------------- parser


def test_regions_tokens_and_pointers() -> None:
    regions = parse_regions(LINE)
    assert len(regions) == 1
    region = regions[0]
    assert json.loads(LINE[region.start : region.end]) == _objects(LINE)[0]
    values = {(t.pointer, t.kind): t.value for t in region.tokens if t.kind != "key"}
    assert values == {
        ("/user/email", "string"): "alice.test@example.com",
        ("/user/customer_name", "string"): "Testa Fakename",
        ("/user/user_id", "literal"): 12345,
        ("/tags/0", "string"): "a",
        ("/tags/1", "string"): "b",
    }
    email = next(t for t in region.tokens if t.pointer == "/user/email" and t.kind == "string")
    assert LINE[email.start : email.end] == "alice.test@example.com"  # inside the quotes
    assert email.key == "email" and not email.escaped


def test_escapes_pointer_escaping_and_multiple_objects() -> None:
    line = 'a {"a/b~c": "x\\u0040y", "n": null} mid {"k": [true, -1.5e3]} end'
    regions = parse_regions(line)
    assert [json.loads(line[r.start : r.end]) for r in regions] == _objects(line)
    tokens = region_tokens(regions)
    escaped = next(t for t in tokens if t.kind == "string" and t.pointer == "/a~1b~0c")
    assert escaped.escaped and escaped.value == "x@y"
    assert {t.value for t in tokens if t.kind == "literal"} == {None, True, -1500.0}


@pytest.mark.parametrize(
    "line",
    [
        "no json here",
        'broken {"a": "x" then text',
        '{"a": 01}',
        '{"a": "tab\there"}',  # raw control character inside a string
        "{'single': 'quotes'}",
        '["top-level arrays are not objects"]',
        '{"a": tru}',
    ],
)
def test_invalid_json_gives_no_regions(line: str) -> None:
    assert parse_regions(line) == []


def test_depth_and_candidate_limits() -> None:
    deep = '{"a": ' * 5 + "1" + "}" * 5
    assert parse_regions(deep, max_depth=5)[0].start == 0
    # Too deep from the outer brace: only an inner object within the limit is recognised.
    assert all(r.start > 0 for r in parse_regions(deep, max_depth=4))
    noisy = "{ " * MAX_CANDIDATES + '{"a": "b"}'
    assert parse_regions(noisy) == []  # bounded work per line; still scanned as text
    assert parse_regions("{ " * (MAX_CANDIDATES - 1) + '{"a": "b"}')


# ----------------------------------------------------------------------------- spans


def test_snap_span() -> None:
    line = 'pw {"pw_value": "TEST_ONLY_NOT_A_CREDENTIAL", "n": 4111} tail'
    regions = parse_regions(line)
    tokens = {t.pointer + ":" + t.kind: t for t in region_tokens(regions)}
    value = tokens["/pw_value:string"]
    number = tokens["/n:literal"]
    # Already inside one string: unchanged.
    assert snap_span(regions, value.start + 1, value.end - 1) == [(value.start + 1, value.end - 1)]
    # Across key, colon and quotes: only the value body.
    key = tokens["/pw_value:key"]
    assert snap_span(regions, key.start, value.end + 1) == [(value.start, value.end)]
    # Part of a number: the whole literal.
    assert snap_span(regions, number.start + 1, number.end) == [(number.start, number.end)]
    # Text before the object plus the start of the value: split.
    assert snap_span(regions, 0, value.start + 3) == [
        (0, regions[0].start),
        (value.start, value.start + 3),
    ]
    # Pure punctuation: every value of the object, whole (fail-safe).
    values = [(t.start, t.end) for t in regions[0].tokens if t.kind != "key"]
    assert snap_span(regions, value.end, value.end + 2) == values
    assert snap_span(parse_regions("x {} y"), 2, 3) == []


def test_codec_keeps_json_valid() -> None:
    line = '{"s": "a\\"b", "n": 42}'
    regions = parse_regions(line)
    codec = SpanCodec(JSONLOG_STRUCTURE, regions)
    s = next(t for t in regions[0].tokens if t.pointer == "/s" and t.kind == "string")
    n = next(t for t in regions[0].tokens if t.kind == "literal")
    assert codec.decode(s.start, s.end, line[s.start : s.end]) == 'a"b'
    assert codec.decode(n.start, n.end, "42") == 42
    assert codec.encode(s.start, s.end, 'x"y\\z') == 'x\\"y\\\\z'
    assert codec.encode(n.start, n.end, "[REDACTED:pii.phone]") == '"[REDACTED:pii.phone]"'
    assert codec.encode(0, 0, "outside") == "outside"


# ----------------------------------------------------------------------------- detection


def _items(tmp_path: Path, text: str, fmt: InputFormat, policy: Policy) -> list[dict[str, object]]:
    src = tmp_path / f"in-{fmt}.log"
    src.write_bytes(text.encode("utf-8"))
    return inspect_file(src, policy, DEV, fmt=fmt).items


def test_field_context_and_escaped_values(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    line = LINE[:-9] + ', "note": "mail alice\\u0040example.com"}\n'
    items = _items(tmp_path, line, InputFormat.JSONLOG, policy)
    paths = {(i["category"], i["location"].get("field_path")) for i in items}
    assert ("pii.email", "/user/email") in paths
    assert ("pii.person_name", "/user/customer_name") in paths
    assert ("pii.customer_identifier", "/user/user_id") in paths
    assert ("pii.email", "/note") in paths  # only visible after decoding the escape
    text_cats = {i["category"] for i in _items(tmp_path, line, InputFormat.TEXT, policy)}
    assert "pii.person_name" not in text_cats
    assert (
        sum(i["category"] == "pii.email" for i in _items(tmp_path, line, InputFormat.TEXT, policy))
        == 1
    )


def test_not_inferred_from_extension(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    src = tmp_path / "app.log"
    src.write_bytes((LINE + "\n").encode("utf-8"))
    report = inspect_file(src, policy_text(MINIMAL_POLICY), DEV)
    assert report.input["format"] == "text"


def test_pem_block_lines_are_not_parsed(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    text = (
        "-----BEGIN PRIVATE KEY-----\n"  # TEST_ONLY synthetic header, no key material
        '{"looks": "like json"}\n'
        "-----END PRIVATE KEY-----\n"
    )
    items = _items(tmp_path, text, InputFormat.JSONLOG, policy_text(MINIMAL_POLICY))
    body = [i for i in items if i["location"]["line"] == 2]
    assert body and all(i["category"] == "credential.secret" for i in body)
    assert all(not i["location"].get("field_path") for i in body)


# ----------------------------------------------------------------------------- transforms


def _sanitize(
    tmp_path: Path, text: str, policy: Policy, keys: KeyProvider | None = None
) -> tuple[object, Path]:
    src = tmp_path / "in.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp_path / "out.log"
    report = sanitize_file(
        src, out, policy, DEV,
        SanitizeOptions(apply=True, format=InputFormat.JSONLOG, keys=keys or KeyProvider({})),
    )  # fmt: skip
    return report, out


def test_rewrite_keeps_json_valid_and_text_intact(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    report, out = _sanitize(tmp_path, LINE + "\n", policy_text(MINIMAL_POLICY))
    assert report.status == RunStatus.SANITIZED  # type: ignore[attr-defined]
    line = out.read_text(encoding="utf-8")
    assert line.startswith("2026-01-05T10:00:00Z ERROR login failed {") and line.endswith(
        " retry=1\n"
    )
    (obj,) = _objects(line)
    assert obj == {  # type: ignore[comparison-overlap]
        "user": {
            "email": "[REDACTED:pii.email]",
            "customer_name": "[REDACTED:pii.person_name]",
            "user_id": "[REDACTED:pii.customer_identifier]",  # number became a JSON string
        },
        "tags": ["a", "b"],
    }
    for secret in SYNTHETIC_SECRETS:
        assert secret not in line


def test_replacement_with_quotes_is_escaped(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: replace-names
    priority: 900
    match: {categories: [pii.person_name]}
    action: replace
    params: {value: 'say "hi" \\ there'}
"""
        )
    )
    report, out = _sanitize(tmp_path, LINE + "\n", policy)
    assert report.ok  # type: ignore[attr-defined]
    (obj,) = _objects(out.read_text(encoding="utf-8"))
    assert obj["user"]["customer_name"] == 'say "hi" \\ there'  # type: ignore[index]


def test_pseudonyms_match_the_json_format(
    tmp_path: Path, policy_text: Callable[[str], Policy], keys: KeyProvider
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: pz-email
    priority: 900
    match: {categories: [pii.email]}
    action: pseudonymize
    params: {scope: field}
"""
        )
    )
    line = '{"user": {"email": "alice\\u002etest@example.com"}}'
    _, out = _sanitize(tmp_path, line + "\n", policy, keys)
    (from_log,) = _objects(out.read_text(encoding="utf-8"))
    src = tmp_path / "doc.json"
    src.write_text('{"user": {"email": "alice.test@example.com"}}', encoding="utf-8")
    doc_out = tmp_path / "doc.out.json"
    assert sanitize_file(src, doc_out, policy, DEV, SanitizeOptions(keys=keys)).ok
    assert from_log == json.loads(doc_out.read_text(encoding="utf-8"))


def test_drop_field_becomes_review(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: drop-names
    priority: 900
    match: {categories: [pii.person_name]}
    action: drop_field
"""
        )
    )
    report, out = _sanitize(tmp_path, LINE + "\n", policy)
    assert report.status == RunStatus.REVIEW_REQUIRED and not out.exists()  # type: ignore[attr-defined]


def test_broken_rewrite_fails_closed(
    tmp_path: Path, policy_text: Callable[[str], Policy], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(line_structure.SpanCodec, "encode", lambda self, s, e, r: '"')
    with pytest.raises(TransformError) as exc:
        _sanitize(tmp_path, LINE + "\n", policy_text(MINIMAL_POLICY))
    assert exc.value.code == "jsonlog_rewrite_invalid"
    assert not (tmp_path / "out.log").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.log"]


# ----------------------------------------------------------------------------- properties

_VALUES = st.sampled_from(
    [
        '"alice.test@example.com"',
        '"call 202-555-0143 now"',
        '"TEST_ONLY_NOT_A_CREDENTIAL"',
        '"Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123"',
        '"192.0.2.10"',
        "4111111111111111",
        "2025550143",
        "null",
        "true",
        '"x\\u0040example.com"',
        '"plain"',
        '{"email": "alice.test@example.com"}',
        '["a", "4111 1111 1111 1111"]',
    ]
)
_KEYS = st.sampled_from(
    [
        *("email", "password", "customer_name", "user_id", "msg", "card", "phone", "ip", "x"),
        *("bob.test@example.org", "[REDACTED:pii.email]"),  # data, and our own marker, as keys
    ]
)
_OBJECTS = st.dictionaries(_KEYS, _VALUES, min_size=1, max_size=4).map(
    lambda d: "{" + ", ".join(f'"{k}": {v}' for k, v in d.items()) + "}"
)
_PARTS = st.one_of(
    _OBJECTS,
    st.sampled_from(["ERROR", "user=alice.test@example.com", "{", "}", '"', "token=", "x:1"]),
)


@given(st.lists(st.lists(_PARTS, max_size=4).map(" ".join), min_size=1, max_size=4))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_jsonlog_never_finds_less_than_text_and_output_stays_valid(
    tmp_path_factory: pytest.TempPathFactory,
    policy_text: Callable[[str], Policy],
    lines: list[str],
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    tmp = tmp_path_factory.mktemp("jl")
    text = "\n".join(lines) + "\n"

    def covered(items: list[dict[str, object]]) -> dict[tuple[object, object], set[int]]:
        # Characters each (category, line) protects. jsonlog may split or snap a text span to
        # JSON tokens, but must never protect fewer data characters than text mode.
        out: dict[tuple[object, object], set[int]] = {}
        for i in items:
            loc = i["location"]
            assert isinstance(loc, dict)
            span = loc.get("span") or (0, 0)
            out.setdefault((i["category"], loc["line"]), set()).update(range(*span))
        return out

    as_text = covered(_items(tmp, text, InputFormat.TEXT, policy))
    as_jsonlog = covered(_items(tmp, text, InputFormat.JSONLOG, policy))
    source = text.split("\n")
    syntax = set(' {}[]:,"')
    for key, chars in as_text.items():
        line = source[int(key[1]) - 1]  # type: ignore[arg-type]
        data = {c for c in chars if c < len(line) and line[c] not in syntax}
        assert data <= as_jsonlog.get(key, set()), key

    src = tmp / "p.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp / "p.out.log"
    report = sanitize_file(
        src, out, policy, DEV, SanitizeOptions(format=InputFormat.JSONLOG, keys=KeyProvider({}))
    )
    if report.ok:
        for before, after in zip(source, out.read_text(encoding="utf-8").split("\n"), strict=False):
            assert len(_objects(after)) >= len(parse_regions(before))


# ----------------------------------------------------------------------------- regressions


def test_phone_inside_a_sensitive_field_is_still_reported(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    # The field-name email finding covers the whole value; it must not suppress the phone.
    items = _items(
        tmp_path, '{"email": "call 202-555-0143 now"}\n', InputFormat.JSONLOG,
        policy_text(MINIMAL_POLICY),
    )  # fmt: skip
    assert "pii.phone" in {i["category"] for i in items}


def test_secret_span_on_object_punctuation_protects_the_object(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    # The assignment pattern matches only the opening brace; redacting it would break the JSON.
    report, out = _sanitize(
        tmp_path, 'token= {"email": "alice.test@example.com"}\n', policy_text(MINIMAL_POLICY)
    )
    assert report.ok  # type: ignore[attr-defined]
    line = out.read_text(encoding="utf-8")
    (obj,) = _objects(line)
    assert "alice.test@example.com" not in line
    assert set(obj) == {"email"}  # type: ignore[arg-type]


def test_data_in_a_key_is_rewritten_without_a_false_rescan_failure(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    # The redacted key becomes "[REDACTED:pii.email]"; that must not make the value look like
    # an email on rescan.
    report, out = _sanitize(
        tmp_path, '{"alice.test@example.com": 1}\n', policy_text(MINIMAL_POLICY)
    )
    assert report.ok  # type: ignore[attr-defined]
    (obj,) = _objects(out.read_text(encoding="utf-8"))
    assert obj == {"[REDACTED:pii.email]": 1}


def test_marker_key_does_not_hide_value_content(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    line = '{"[REDACTED:pii.email]": "alice.test@example.com"}\n'
    items = _items(tmp_path, line, InputFormat.JSONLOG, policy_text(MINIMAL_POLICY))
    assert "pii.email" in {i["category"] for i in items}


def test_escaped_key_is_decoded_scanned_and_rewritten(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    # Keys can carry data too; an escape hides it from the raw-text scan.
    escape = chr(92) + "u0040"  # a JSON \u escape for '@'
    line = '{"alice' + escape + 'example.com": 1}\n'
    policy = policy_text(MINIMAL_POLICY)
    assert "pii.email" not in {
        i["category"] for i in _items(tmp_path, line, InputFormat.TEXT, policy)
    }
    assert "pii.email" in {
        i["category"] for i in _items(tmp_path, line, InputFormat.JSONLOG, policy)
    }
    report, out = _sanitize(tmp_path, line, policy)
    assert report.ok  # type: ignore[attr-defined]
    (obj,) = _objects(out.read_text(encoding="utf-8"))
    assert obj == {"[REDACTED:pii.email]": 1}
