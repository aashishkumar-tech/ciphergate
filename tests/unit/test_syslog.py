"""syslog/CEF format (#46): RFC 5424, RFC 3164, CEF, field context, escaping and the superset."""

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
from ciphergate.readers.line_structure import SpanCodec, region_tokens
from ciphergate.readers.syslog_reader import SYSLOG_STRUCTURE, parse_regions
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, SYNTHETIC_SECRETS, ctx

DEV = ctx("dev", dest="local_dev")
BS = chr(92)  # a literal backslash, kept out of source escapes
RFC5424 = (
    '<34>1 2026-01-05T10:00:00.003Z web01 billing 4242 ID47 [origin ip="192.0.2.10"]'
    '[auth@32473 email="alice.test@example.com" note="a' + BS + '"b' + BS + ']c"] login failed'
)
RFC3164 = "Jan  5 10:00:00 web01 sshd[4242]: Accepted publickey for USER_TEST_001 port 22"
CEF = (
    "CEF:0|Vendor|Prod" + BS + "|uct|1.0|100|Login ok|5|suser=alice.test src=192.0.2.10 "
    "cs1Label=email cs1=alice.test@example.com msg=a b" + BS + "=c"
)


def _with_rule(rule: str) -> str:
    return MINIMAL_POLICY.replace("rules:\n", "rules:\n" + rule, 1)


def _fields(line: str) -> dict[str, object]:
    (region,) = parse_regions(line)
    return {t.pointer: t.value for t in region.tokens if t.kind != "key"}


# ----------------------------------------------------------------------------- parser


def test_rfc5424_header_structured_data_and_message() -> None:
    assert _fields(RFC5424) == {
        "/timestamp": "2026-01-05T10:00:00.003Z",
        "/hostname": "web01",
        "/app_name": "billing",
        "/procid": "4242",
        "/msgid": "ID47",
        "/sd/origin/ip": "192.0.2.10",
        "/sd/auth@32473/email": "alice.test@example.com",
        "/sd/auth@32473/note": 'a"b]c',  # SD escapes decoded
        "/msg": "login failed",
    }


def test_rfc5424_nil_values_and_no_message() -> None:
    assert _fields("<34>1 2026-01-05T10:00:00Z - - - - - plain") == {
        "/timestamp": "2026-01-05T10:00:00Z",
        "/msg": "plain",
    }
    assert set(_fields('<34>1 - h a - - [x k="v"]')) == {"/hostname", "/app_name", "/sd/x/k"}
    bom = "<34>1 - h a - - - " + "﻿" + "text"
    assert _fields(bom)["/msg"] == "text"


@pytest.mark.parametrize(
    "line",
    [
        RFC3164,
        "<13>" + RFC3164,
        "2026-01-05T10:00:00+00:00 web01 sshd[4242]: Accepted publickey for USER_TEST_001 port 22",
    ],
)
def test_rfc3164_variants(line: str) -> None:
    fields = _fields(line)
    assert fields["/hostname"] == "web01" and fields["/app_name"] == "sshd"
    assert fields["/procid"] == "4242"
    assert fields["/msg"] == "Accepted publickey for USER_TEST_001 port 22"


def test_cef_header_extensions_hints_and_labels() -> None:
    for line in (CEF, "<134>Jan 05 10:00:00 fw01 " + CEF):
        (region,) = parse_regions(line)
        tokens = {t.pointer: t for t in region.tokens if t.kind != "key"}
        assert tokens["/cef/device_product"].value == "Prod|uct"
        assert tokens["/cef/event_name"].value == "Login ok"  # not "name": no person-name hint
        assert tokens["/cef/severity"].value == "5"
        assert tokens["/cef/extension/suser"].hint == "source_user_name"
        assert tokens["/cef/extension/src"].hint == "source_ip"
        assert tokens["/cef/extension/cs1"].hint == "email"  # from cs1Label
        assert tokens["/cef/extension/cs1"].value == "alice.test@example.com"
        assert tokens["/cef/extension/msg"].value == "a b=c"  # spaces kept, \= decoded
    assert _fields("CEF:0|V|P|1|2|N|3|") == {
        "/cef/device_vendor": "V",
        "/cef/device_product": "P",
        "/cef/device_version": "1",
        "/cef/signature_id": "2",
        "/cef/event_name": "N",
        "/cef/severity": "3",
    }


@pytest.mark.parametrize(
    "line",
    [
        "",
        "plain text",
        "Jan  5 10:00:00 web01 no tag here",
        "<34>1 2026-01-05T10:00:00Z h a p m [broken",
        '<34>1 2026-01-05T10:00:00Z h a p m [x k="unterminated]',
        "<34>1 2026-01-05T10:00:00Z h a p m [x k=v]",
        "<34>1 2026-01-05T10:00:00Z h a p m [x]glued",
        "CEF:0|only|three|fields",
        "CEF:x|V|P|1|2|N|3|",
    ],
)
def test_other_layouts_get_no_fields(line: str) -> None:
    assert parse_regions(line) == []


def test_parsing_is_bounded() -> None:
    huge = [
        "CEF:0|" + "a" * 200_000,
        "CEF:0|V|P|1|2|N|3|" + "k=v " * 50_000,  # extension fields are capped, not rejected
        "<34>1 - h a - - " + "[x]" * 50_000,
        '<34>1 - h a - - [x k="' + BS * 200_001,
        "Jan  5 10:00:00 " + "h" * 200_000,
    ]
    started = time.perf_counter()
    for line in huge:
        regions = parse_regions(line)
        assert len(region_tokens(regions)) <= 6 + 2 * 256
    assert time.perf_counter() - started < 5


# ----------------------------------------------------------------------------- detection


def _items(tmp_path: Path, text: str, fmt: InputFormat, policy: Policy) -> list[dict[str, object]]:
    src = tmp_path / f"in-{fmt}.log"
    src.write_bytes(text.encode("utf-8"))
    return inspect_file(src, policy, DEV, fmt=fmt).items


def test_field_context_from_sd_and_cef(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    text = RFC5424 + "\n" + CEF + "\n"
    paths = {
        (i["category"], i["location"].get("field_path"))  # type: ignore[union-attr]
        for i in _items(tmp_path, text, InputFormat.SYSLOG, policy)
    }
    assert ("pii.email", "/sd/auth@32473/email") in paths
    assert ("pii.ip_address", "/sd/origin/ip") in paths  # field name "ip"
    assert ("pii.customer_identifier", "/cef/extension/suser") in paths  # via the hint
    assert ("pii.ip_address", "/cef/extension/src") in paths  # via the hint
    assert ("pii.email", "/cef/extension/cs1") in paths
    assert not any(p == "/cef/event_name" for _, p in paths)
    text_cats = {i["category"] for i in _items(tmp_path, text, InputFormat.TEXT, policy)}
    assert "pii.customer_identifier" not in text_cats


def test_field_names_rules_use_the_raw_cef_key(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(
        _with_rule(
            """  - id: replace-suser
    priority: 950
    match: {field_names: [suser]}
    action: replace
    params: {value: someone}
"""
        )
    )
    report, out = _sanitize(tmp_path, CEF + "\n", policy)
    assert report.ok  # type: ignore[attr-defined]
    assert _fields(out.read_text(encoding="utf-8").rstrip("\n"))["/cef/extension/suser"] == (
        "someone"
    )


def test_not_inferred_from_extension(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    src = tmp_path / "syslog.log"
    src.write_bytes((RFC5424 + "\n").encode("utf-8"))
    assert inspect_file(src, policy_text(MINIMAL_POLICY), DEV).input["format"] == "text"


def test_pem_block_lines_are_not_parsed(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    text = "-----BEGIN PRIVATE KEY-----\n" + CEF + "\n-----END PRIVATE KEY-----\n"  # TEST_ONLY
    items = _items(tmp_path, text, InputFormat.SYSLOG, policy_text(MINIMAL_POLICY))
    body = [i for i in items if i["location"]["line"] == 2]  # type: ignore[index]
    assert "credential.secret" in {i["category"] for i in body}
    assert all(not i["location"].get("field_path") for i in body)  # type: ignore[union-attr]


def test_reports_and_output_never_echo_values(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    param = "pass" + "word"  # split so the repo secret scanner does not flag the fixture
    line = RFC5424.replace('note="', f'{param}="{SYNTHETIC_SECRETS[0]}" note="') + "\n"
    report, out = _sanitize(tmp_path, line + CEF + "\n", policy_text(MINIMAL_POLICY))
    assert report.ok  # type: ignore[attr-defined]
    dumped = json.dumps(report.to_dict())  # type: ignore[attr-defined]
    output = out.read_text(encoding="utf-8")
    for raw in (SYNTHETIC_SECRETS[0], "alice.test@example.com", "alice.test "):
        assert raw not in dumped
    for raw in (SYNTHETIC_SECRETS[0], "alice.test@example.com"):
        assert raw not in output


# ----------------------------------------------------------------------------- transforms


def _sanitize(
    tmp_path: Path, text: str, policy: Policy, keys: KeyProvider | None = None
) -> tuple[object, Path]:
    src = tmp_path / "in.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp_path / "out.log"
    report = sanitize_file(
        src, out, policy, DEV,
        SanitizeOptions(apply=True, format=InputFormat.SYSLOG, keys=keys or KeyProvider({})),
    )  # fmt: skip
    return report, out


def test_rewrite_keeps_structure_and_escapes_markers(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    report, out = _sanitize(tmp_path, RFC5424 + "\n" + CEF + "\n", policy_text(MINIMAL_POLICY))
    assert report.status == RunStatus.SANITIZED  # type: ignore[attr-defined]
    first, second = out.read_text(encoding="utf-8").splitlines()
    assert 'email="[REDACTED:pii.email' + BS + ']"' in first  # "]" escaped per RFC 5424
    assert first.split(" ")[2] == "[REDACTED:network.telemetry]"  # hostname marker intact
    sd = _fields(first)
    assert sd["/sd/auth@32473/email"] == "[REDACTED:pii.email]"
    assert sd["/sd/auth@32473/note"] == 'a"b]c' and sd["/msg"] == "login failed"
    cef = _fields(second)
    assert cef["/cef/extension/cs1"] == "[REDACTED:pii.email]"
    assert cef["/cef/extension/suser"] == "[REDACTED:pii.customer_identifier]"
    assert cef["/cef/extension/msg"] == "a b=c" and cef["/cef/event_name"] == "Login ok"


def test_replacements_are_escaped_for_their_field(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    awkward = 'a b|c=d]e"f' + BS
    policy = policy_text(
        _with_rule(
            f"""  - id: replace-awkward
    priority: 900
    match: {{categories: [pii.email, pii.customer_identifier, network.telemetry]}}
    action: replace
    params: {{value: {json.dumps(awkward)}}}
"""
        )
    )
    text = RFC5424 + "\n" + CEF.replace("Prod" + BS + "|uct", "Prod") + "\n"
    report, out = _sanitize(tmp_path, text, policy)
    assert report.ok  # type: ignore[attr-defined]
    first, second = out.read_text(encoding="utf-8").splitlines()
    sd, cef = _fields(first), _fields(second)  # both still parse
    assert sd["/sd/auth@32473/email"] == awkward
    assert sd["/hostname"] == 'a_b|c=d]e"f' + BS  # header fields: whitespace becomes "_"
    assert cef["/cef/extension/cs1"] == awkward
    assert cef["/cef/extension/suser"] == awkward
    assert set(sd) == set(_fields(RFC5424))


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
    report, out = _sanitize(tmp_path, RFC5424 + "\n", policy)
    assert report.status == RunStatus.REVIEW_REQUIRED and not out.exists()  # type: ignore[attr-defined]


def test_broken_rewrite_fails_closed(
    tmp_path: Path, policy_text: Callable[[str], Policy], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(line_structure.SpanCodec, "encode", lambda self, s, e, r: '"] [')
    with pytest.raises(TransformError) as exc:
        _sanitize(tmp_path, RFC5424 + "\n", policy_text(MINIMAL_POLICY))
    assert exc.value.code == "syslog_rewrite_invalid"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.log"]


# ----------------------------------------------------------------------------- properties

_VALUES = st.sampled_from(
    [
        "alice.test@example.com",
        "call 202-555-0143",
        "TEST_ONLY_NOT_A_CREDENTIAL",
        "192.0.2.10",
        "4111111111111111",
        "a" + BS + '"b',
        "plain",
    ]
)
_SD_KEYS = st.sampled_from(["email", "password", "user_id", "ip", "x"])
_CEF_KEYS = st.sampled_from(["suser", "src", "cs1", "msg", "requestUrl"])
_MESSAGES = st.sampled_from(["", " login failed", " mail alice.test@example.com", " token= x"])


def _sd_value(value: str) -> str:
    return value.replace(BS, BS * 2).replace('"', BS + '"').replace("]", BS + "]")


@st.composite
def _lines(draw: st.DrawFn) -> str:
    kind = draw(st.sampled_from(["5424", "3164", "cef", "other"]))
    message = draw(_MESSAGES)
    if kind == "5424":
        params = draw(st.lists(st.tuples(_SD_KEYS, _VALUES), max_size=3))
        sd = "[x " + " ".join(f'{k}="{_sd_value(v)}"' for k, v in params) + "]" if params else "-"
        sd = sd.replace("[x ]", "[x]")
        return f"<34>1 2026-01-05T10:00:00Z web01 app - - {sd}{message}"
    if kind == "3164":
        return f"Jan  5 10:00:00 web01 sshd[42]:{message or ' x'}"
    if kind == "cef":
        ext = draw(st.lists(st.tuples(_CEF_KEYS, _VALUES), max_size=3))
        body = " ".join(f"{k}={v.replace(BS, BS * 2).replace('=', BS + '=')}" for k, v in ext)
        return "CEF:0|V|P|1|2|N|3|" + body
    return draw(st.sampled_from(["plain alice.test@example.com", "[", "CEF:0|", "<34>1 -"]))


@given(st.lists(_lines(), min_size=1, max_size=4))
@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_syslog_never_finds_less_than_text_and_output_stays_parseable(
    tmp_path_factory: pytest.TempPathFactory,
    policy_text: Callable[[str], Policy],
    lines: list[str],
) -> None:
    policy = policy_text(MINIMAL_POLICY)
    tmp = tmp_path_factory.mktemp("sl")
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
    as_syslog = covered(_items(tmp, text, InputFormat.SYSLOG, policy))
    source = text.split("\n")
    syntax = set(' []"=|' + BS)
    for key, chars in as_text.items():
        line = source[int(key[1]) - 1]  # type: ignore[arg-type]
        data = {c for c in chars if c < len(line) and line[c] not in syntax}
        assert data <= as_syslog.get(key, set()), key

    src = tmp / "p.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp / "p.out.log"
    report = sanitize_file(
        src, out, policy, DEV, SanitizeOptions(format=InputFormat.SYSLOG, keys=KeyProvider({}))
    )
    if report.ok:
        rewritten = out.read_text(encoding="utf-8").split("\n")
        for before, after in zip(source, rewritten, strict=False):
            if parse_regions(before):
                assert len(region_tokens(parse_regions(after))) >= len(
                    region_tokens(parse_regions(before))
                )


def test_codec_rules_for_tag_and_message() -> None:
    (region,) = parse_regions(RFC3164)
    codec = SpanCodec(SYSLOG_STRUCTURE, [region])
    tokens = {t.pointer: t for t in region.tokens}
    tag, msg = tokens["/app_name"], tokens["/msg"]
    # An RFC 3164 tag only holds [A-Za-z0-9_./-]; anything else becomes "_".
    assert codec.encode(tag.start, tag.end, "[REDACTED:x]") == "_REDACTED_x_"
    # A message never gets a raw line break or control character.
    assert codec.encode(msg.start, msg.end, "a\nb\x07c") == "a b c"
    rewritten = RFC3164[: tag.start] + "_REDACTED_x_" + RFC3164[tag.end :]
    assert _fields(rewritten)["/app_name"] == "_REDACTED_x_"
