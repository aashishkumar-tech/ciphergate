"""Access-log format (#39): parser, decoding, field context, structure-safe rewriting, superset."""

from __future__ import annotations

import json
import time
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
from ciphergate.readers.accesslog_reader import ACCESSLOG_STRUCTURE, parse_regions
from ciphergate.readers.line_structure import SpanCodec, region_tokens
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, SYNTHETIC_SECRETS, ctx

DEV = ctx("dev", dest="local_dev")
BS = chr(92)  # a literal backslash, kept out of source escapes
HEAD = '192.0.2.10 - alice.test [05/Jan/2026:10:00:00 +0000] "GET /users/42?'
LINE = (
    HEAD + "email=alice.test%40example.com&access_token=TEST_ONLY_abc123&page=2 HTTP/1.1"
    '" 200 512 "https://app.example.com/login?next=%2Fhome" "Mozilla/5.0 (X11)"'
)
COMMON = '198.51.100.7 - - [05/Jan/2026:10:00:01 +0000] "GET /healthz HTTP/1.1" 200 2'


def _with_rule(rule: str) -> str:
    return MINIMAL_POLICY.replace("rules:\n", "rules:\n" + rule, 1)


def _fields(line: str) -> dict[str, object]:
    """Pointer -> decoded value of every value token (keys excluded)."""
    (region,) = parse_regions(line)
    return {t.pointer: t.value for t in region.tokens if t.kind != "key"}


# ----------------------------------------------------------------------------- parser


def test_combined_line_fields() -> None:
    fields = _fields(LINE)
    assert fields == {
        "/remote_addr": "192.0.2.10",
        "/remote_user": "alice.test",
        "/time_local": "05/Jan/2026:10:00:00 +0000",
        "/request/method": "GET",
        "/request/path": "/users/42",
        "/request/query/email": "alice.test@example.com",  # percent-decoded
        "/request/query/access_token": "TEST_ONLY_abc123",
        "/request/query/page": "2",
        "/request/protocol": "HTTP/1.1",
        "/status": "200",
        "/body_bytes_sent": "512",
        "/http_referer": "https://app.example.com/login",
        "/http_referer/query/next": "/home",
        "/http_user_agent": "Mozilla/5.0 (X11)",
    }
    (region,) = parse_regions(LINE)
    assert (region.start, region.end) == (0, len(LINE))
    for t in region.tokens:
        assert LINE[t.start : t.end]  # spans point into the line


def test_common_format_dashes_and_trailing_fields() -> None:
    assert set(_fields(COMMON)) == {
        "/remote_addr",
        "/time_local",
        "/request/method",
        "/request/path",
        "/request/protocol",
        "/status",
        "/body_bytes_sent",
    }  # "-" ident/user get no field
    extra = COMMON + ' "-" "probe/1.0" "203.0.113.9"'
    (region,) = parse_regions(extra)
    assert region.end == len(extra) - len(' "203.0.113.9"')  # after the user agent: text only
    assert "/http_referer" not in _fields(extra)


def test_request_that_is_not_three_parts_is_one_field() -> None:
    line = COMMON.replace("GET /healthz HTTP/1.1", BS + "x16" + BS + "x03junk")
    fields = _fields(line)
    assert fields["/request"] == chr(0x16) + chr(0x03) + "junk"  # log escapes decoded


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not an access log line",
        '192.0.2.10 - - [05/Jan/2026:10:00:00 +0000] "GET /unterminated 200 1',
        '192.0.2.10 - - 05/Jan/2026:10:00:00 "GET / HTTP/1.1" 200 1',
        '192.0.2.10 - [05/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1',
        '192.0.2.10 - - [05/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1"',
        'vhost.example:80 192.0.2.10 - - [05/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1',
    ],
)
def test_other_layouts_get_no_fields(line: str) -> None:
    assert parse_regions(line) == []


def test_escapes_and_percent_decoding() -> None:
    agent = f"a{BS}x22b{BS}{BS}c{BS}" + '"d'
    line = COMMON + f' "-" "{agent}"'
    assert _fields(line)["/http_user_agent"] == 'a"b' + BS + 'c"d'
    query = "q=a+b%20c&bad=%zz%4&utf=%E2%9C%93&inv=%FF&empty=&flag"
    line = COMMON.replace("/healthz", "/s?" + query)
    fields = _fields(line)
    assert fields["/request/query/q"] == "a b c"
    assert fields["/request/query/bad"] == "%zz%4"  # invalid escapes stay as they are
    assert fields["/request/query/utf"] == "\N{CHECK MARK}"
    assert fields["/request/query/inv"] == "\N{REPLACEMENT CHARACTER}"
    assert fields["/request/query/empty"] == ""
    keys = [t.key for t in region_tokens(parse_regions(line)) if t.kind == "key"]
    assert keys == ["q", "bad", "utf", "inv", "empty", "flag"]


def test_parsing_is_bounded() -> None:
    huge = [
        "a " * 200_000,
        '" ' * 200_000,
        "1 2 3 [" + "x" * 200_000,
        '1 2 3 [t] "' + BS * 200_001,
        '1 2 3 [t] "' + "a" * 20_000 + '" 200 1',  # quoted field longer than the cap
    ]
    started = time.perf_counter()
    for line in huge:
        assert parse_regions(line) == []
    assert time.perf_counter() - started < 5


# ----------------------------------------------------------------------------- detection


def _items(tmp_path: Path, text: str, fmt: InputFormat, policy: Policy) -> list[dict[str, object]]:
    src = tmp_path / f"in-{fmt}.log"
    src.write_bytes(text.encode("utf-8"))
    return inspect_file(src, policy, DEV, fmt=fmt).items


def test_field_context_and_decoded_values(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    line = LINE.replace("Mozilla/5.0 (X11)", f"bot alice{BS}x40example.org") + "\n"
    found = {
        (i["category"], i["location"].get("field_path"))  # type: ignore[union-attr]
        for i in _items(tmp_path, line, InputFormat.ACCESSLOG, policy)
    }
    assert ("pii.email", "/request/query/email") in found  # only visible after %40 decoding
    assert ("credential.secret", "/request/query/access_token") in found  # from the name
    assert ("pii.customer_identifier", "/remote_user") in found
    assert ("pii.ip_address", "/remote_addr") in found
    assert ("pii.email", "/http_user_agent") in found  # only visible after \x40 decoding
    text_cats = [i["category"] for i in _items(tmp_path, line, InputFormat.TEXT, policy)]
    # Text mode sees the %40 form but does not decode log escapes such as \x40.
    assert text_cats.count("pii.email") == 1


def test_not_inferred_from_extension(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    src = tmp_path / "access.log"
    src.write_bytes((LINE + "\n").encode("utf-8"))
    assert inspect_file(src, policy_text(MINIMAL_POLICY), DEV).input["format"] == "text"


def test_pem_block_lines_are_not_parsed(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    text = "-----BEGIN PRIVATE KEY-----\n" + COMMON + "\n-----END PRIVATE KEY-----\n"  # TEST_ONLY
    items = _items(tmp_path, text, InputFormat.ACCESSLOG, policy_text(MINIMAL_POLICY))
    body = [i for i in items if i["location"]["line"] == 2]  # type: ignore[index]
    assert "credential.secret" in {i["category"] for i in body}
    assert all(not i["location"].get("field_path") for i in body)  # type: ignore[union-attr]


def test_reports_and_output_never_echo_values(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    line = LINE.replace("TEST_ONLY_abc123", SYNTHETIC_SECRETS[0]) + "\n"
    report, out = _sanitize(tmp_path, line, policy_text(MINIMAL_POLICY))
    assert report.ok  # type: ignore[attr-defined]
    dumped = json.dumps(report.to_dict())  # type: ignore[attr-defined]
    output = out.read_text(encoding="utf-8")
    for raw in (SYNTHETIC_SECRETS[0], "alice.test%40example.com", "alice.test@example.com"):
        assert raw not in dumped and raw not in output


# ----------------------------------------------------------------------------- transforms


def _sanitize(
    tmp_path: Path, text: str, policy: Policy, keys: KeyProvider | None = None
) -> tuple[object, Path]:
    src = tmp_path / "in.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp_path / "out.log"
    report = sanitize_file(
        src, out, policy, DEV,
        SanitizeOptions(apply=True, format=InputFormat.ACCESSLOG, keys=keys or KeyProvider({})),
    )  # fmt: skip
    return report, out


def test_rewrite_keeps_the_line_and_its_fields(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    report, out = _sanitize(tmp_path, LINE + "\n" + COMMON + "\n", policy_text(MINIMAL_POLICY))
    assert report.status == RunStatus.SANITIZED  # type: ignore[attr-defined]
    first, second = out.read_text(encoding="utf-8").splitlines()
    assert second.startswith("[REDACTED:") and "198.51.100.7" not in second
    assert second.split(" ", 1)[1] == COMMON.split(" ", 1)[1]
    fields = _fields(first)
    assert fields["/request/query/email"] == "[REDACTED:pii.email]"
    assert fields["/request/query/access_token"] == "[REDACTED:credential.secret]"
    assert fields["/remote_user"] == "[REDACTED:pii.customer_identifier]"
    assert fields["/request/query/page"] == "2" and fields["/request/path"] == "/users/42"
    assert fields["/http_user_agent"] == "Mozilla/5.0 (X11)"
    assert first.endswith(
        '" 200 512 "https://app.example.com/login?next=%2Fhome" "Mozilla/5.0 (X11)"'
    )


def test_replacements_are_encoded_for_their_field(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    awkward = 'a b&c=d?"e' + BS
    policy = policy_text(
        _with_rule(
            f"""  - id: replace-awkward
    priority: 900
    match: {{categories: [pii.email, pii.customer_identifier]}}
    action: replace
    params: {{value: {json.dumps(awkward)}}}
"""
        )
    )
    line = LINE.replace("Mozilla/5.0 (X11)", "bot alice.test@example.org") + "\n"
    report, out = _sanitize(tmp_path, line, policy)
    assert report.ok  # type: ignore[attr-defined]
    rewritten = out.read_text(encoding="utf-8").rstrip("\n")
    fields = _fields(rewritten)  # still parses, with every field in place
    assert set(fields) == set(_fields(line.rstrip("\n")))
    assert fields["/request/query/email"] == awkward  # percent-encoded in the query
    assert fields["/remote_user"] == awkward  # \xHH-escaped outside quotes
    assert fields["/http_user_agent"] == "bot " + awkward  # \xHH-escaped inside quotes
    assert "&page=2 HTTP/1.1" in rewritten


def test_pseudonyms_match_the_json_format(
    tmp_path: Path, policy_text: Callable[[str], Policy], keys: KeyProvider
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: pz-email
    priority: 900
    match: {categories: [pii.email]}
    action: pseudonymize
    params: {scope: category}
"""
        )
    )
    _, out = _sanitize(tmp_path, LINE + "\n", policy, keys)
    from_log = _fields(out.read_text(encoding="utf-8").rstrip("\n"))["/request/query/email"]
    src = tmp_path / "doc.json"
    src.write_text('{"email": "alice.test@example.com"}', encoding="utf-8")
    doc_out = tmp_path / "doc.out.json"
    assert sanitize_file(src, doc_out, policy, DEV, SanitizeOptions(keys=keys)).ok
    assert from_log == json.loads(doc_out.read_text(encoding="utf-8"))["email"]


def test_drop_field_becomes_review(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: drop-emails
    priority: 900
    match: {categories: [pii.email]}
    action: drop_field
"""
        )
    )
    report, out = _sanitize(tmp_path, LINE + "\n", policy)
    assert report.status == RunStatus.REVIEW_REQUIRED and not out.exists()  # type: ignore[attr-defined]


def test_broken_rewrite_fails_closed(
    tmp_path: Path, policy_text: Callable[[str], Policy], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(line_structure.SpanCodec, "encode", lambda self, s, e, r: '" "')
    with pytest.raises(TransformError) as exc:
        _sanitize(tmp_path, LINE + "\n", policy_text(MINIMAL_POLICY))
    assert exc.value.code == "accesslog_rewrite_invalid"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.log"]


def test_codec_round_trip() -> None:
    (region,) = parse_regions(LINE)
    codec = SpanCodec(ACCESSLOG_STRUCTURE, [region])
    email = next(
        t for t in region.tokens if t.pointer == "/request/query/email" and t.kind != "key"
    )
    assert codec.decode(email.start, email.end, LINE[email.start : email.end]) == (
        "alice.test@example.com"
    )
    part = (email.start, email.start + 13)  # "alice.test%40"
    assert codec.decode(*part, LINE[part[0] : part[1]]) == "alice.test@"
    assert codec.encode(email.start, email.end, "x y") == "x%20y"


# ----------------------------------------------------------------------------- properties

_QUERY_VALUES = st.sampled_from(
    [
        "alice.test%40example.com",
        "alice.test@example.com",
        "202-555-0143",
        "TEST_ONLY_NOT_A_CREDENTIAL",
        "192.0.2.10",
        "4111111111111111",
        "%22%5C",
        "",
    ]
)
_QUERY_KEYS = st.sampled_from(["email", "access_token", "q", "user_id", "phone", "x"])
_QUERIES = st.lists(st.tuples(_QUERY_KEYS, _QUERY_VALUES), max_size=4).map(
    lambda kv: "&".join(f"{k}={v}" for k, v in kv)
)
_AGENTS = st.sampled_from(
    ["Mozilla/5.0", "-", "bot alice.test@example.com", "a" + BS + '"b', "call 202-555-0143"]
)
_USERS = st.sampled_from(["-", "alice.test", "alice.test@example.com", "USER_TEST_001"])


@st.composite
def _lines(draw: st.DrawFn) -> str:
    if draw(st.booleans()):
        query = draw(_QUERIES)
        target = "/p" + ("?" + query if query else "")
        user, agent = draw(_USERS), draw(_AGENTS)
        tail = draw(
            st.sampled_from(["", f' "-" "{agent}"', f' "https://ref.example/?{query}" "x"'])
        )
        return (
            f'192.0.2.10 - {user} [05/Jan/2026:10:00:00 +0000] "GET {target} HTTP/1.1" 200 5{tail}'
        )
    return draw(st.sampled_from(["plain alice.test@example.com", '"', "1 2 3 [", "token= x"]))


@given(st.lists(_lines(), min_size=1, max_size=4))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_accesslog_never_finds_less_than_text_and_output_stays_parseable(
    tmp_path_factory: pytest.TempPathFactory,
    policy_text: Callable[[str], Policy],
    lines: list[str],
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    tmp = tmp_path_factory.mktemp("al")
    text = "\n".join(lines) + "\n"

    def covered(items: list[dict[str, object]]) -> dict[tuple[object, object], set[int]]:
        out: dict[tuple[object, object], set[int]] = {}
        for i in items:
            loc = i["location"]
            assert isinstance(loc, dict)
            span = loc.get("span") or (0, 0)
            out.setdefault((i["category"], loc["line"]), set()).update(range(*span))
        return out

    as_text = covered(_items(tmp, text, InputFormat.TEXT, policy))
    as_access = covered(_items(tmp, text, InputFormat.ACCESSLOG, policy))
    source = text.split("\n")
    syntax = set(' []"?&=')
    for key, chars in as_text.items():
        line = source[int(key[1]) - 1]  # type: ignore[arg-type]
        data = {c for c in chars if c < len(line) and line[c] not in syntax}
        assert data <= as_access.get(key, set()), key

    src = tmp / "p.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp / "p.out.log"
    report = sanitize_file(
        src, out, policy, DEV, SanitizeOptions(format=InputFormat.ACCESSLOG, keys=KeyProvider({}))
    )
    if report.ok:
        rewritten = out.read_text(encoding="utf-8").split("\n")
        for before, after in zip(source, rewritten, strict=False):
            if parse_regions(before):
                assert len(region_tokens(parse_regions(after))) >= len(
                    region_tokens(parse_regions(before))
                )
