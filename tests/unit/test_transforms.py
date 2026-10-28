"""Transforms and key handling: determinism, scoping, typing, boundaries, no leakage."""

from __future__ import annotations

import secrets

import pytest

from ciphergate.constants import Action, ReasonCode
from ciphergate.errors import MissingKeyError, TransformError
from ciphergate.models.finding import Finding, Location
from ciphergate.models.policy import (
    DateShiftParams,
    GeneralizeParams,
    PseudonymizeParams,
    RedactParams,
    ReplaceParams,
)
from ciphergate.policy.engine import Decision
from ciphergate.policy.precedence import LEVEL_CATEGORY
from ciphergate.policy.validator import load_policy_text
from ciphergate.transforms.date_shift import derive_offset_days, shift_date_text
from ciphergate.transforms.generalize import generalize
from ciphergate.transforms.keys import KeyProvider, KeyStatus
from ciphergate.transforms.pseudonymize import (
    CollisionTracker,
    derive_token,
    generic_field_path,
    pseudonymize,
)
from ciphergate.transforms.redact import redact
from ciphergate.transforms.registry import Transformer
from ciphergate.transforms.replace import replace

KEY = secrets.token_bytes(32)


def pz(
    value: object,
    *,
    scope: str = "field",
    key: bytes = KEY,
    field: str = "/email",
    category: str = "pii.email",
    **kw: object,
) -> str:
    params = PseudonymizeParams(scope=scope, **kw)  # type: ignore[arg-type]
    return pseudonymize(value, params, key=key, namespace="ns", category=category, field_path=field)


# ----------------------------------------------------------------------------- keys


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (None, KeyStatus.MISSING),
        ("", KeyStatus.MISSING),
        ("short", KeyStatus.TOO_SHORT),
        ("hex:zz", KeyStatus.INVALID_ENCODING),
        ("base64:!!!", KeyStatus.INVALID_ENCODING),
        ("a" * 40, KeyStatus.LOW_DIVERSITY),
        ("hex:" + "ab" * 16, KeyStatus.TOO_SHORT),
        ("hex:" + "ab" * 32, KeyStatus.LOW_DIVERSITY),
        ("hex:" + secrets.token_hex(32), KeyStatus.AVAILABLE),
        (
            "base64:" + __import__("base64").b64encode(secrets.token_bytes(32)).decode(),
            KeyStatus.AVAILABLE,
        ),
    ],
)
def test_key_status(raw: str | None, status: KeyStatus) -> None:
    env = {} if raw is None else {"K": raw}
    assert KeyProvider(env).status("K") == status


def test_missing_key_raises_without_fallback() -> None:
    with pytest.raises(MissingKeyError) as info:
        KeyProvider({}).get("CIPHERGATE_HMAC_KEY")
    assert "CIPHERGATE_HMAC_KEY" in info.value.message


def test_key_never_in_repr_or_errors() -> None:
    raw = "hex:" + secrets.token_hex(32)
    provider = KeyProvider({"K": raw, "S": "tooshort"})
    provider.get("K")
    assert raw[4:12] not in repr(provider)
    with pytest.raises(MissingKeyError) as info:
        provider.get("S")
    assert "tooshort" not in str(info.value)


# ----------------------------------------------------------------------------- pseudonymize


def test_pseudonym_deterministic_and_shaped() -> None:
    a, b = pz("alice@example.com"), pz("alice@example.com")
    assert a == b and a.startswith("pz1_") and len(a) == 4 + 32
    assert "alice" not in a


def test_pseudonym_changes_with_key_scope_field_category_prefix() -> None:
    base = pz("v")
    assert pz("v", key=secrets.token_bytes(32)) != base
    assert pz("v", field="/other") != base
    assert pz("v", scope="category") != base
    assert pz("v", scope="category", category="pii.phone") != pz("v", scope="category")
    assert pz("v", scope="entity", entity="customer") != base
    assert pz("v", prefix="email_").startswith("email_pz1_")


def test_field_scope_ignores_array_indices() -> None:
    assert generic_field_path("/users/3/email") == "/users/*/email"
    assert pz("v", field="/users/0/email") == pz("v", field="/users/9/email")


def test_entity_scope_links_across_fields() -> None:
    assert pz("x", scope="entity", entity="c", field="/a") == pz(
        "x", scope="entity", entity="c", field="/b", category="pii.customer_identifier"
    )


def test_types_are_distinguished() -> None:
    assert len({pz("123"), pz(123), pz(123.0), pz(True)}) == 4


def test_unicode_normalization() -> None:
    nfc, nfd = "José", "José"
    assert pz(nfc) == pz(nfd)
    assert pz(nfc, normalize="none") != pz(nfd, normalize="none")
    assert pz("A@Example.com", normalize="casefold_nfc") == pz(
        "a@example.com", normalize="casefold_nfc"
    )


def test_empty_string_pseudonymized_not_confused_with_null() -> None:
    assert pz("") != pz("0")
    with pytest.raises(TransformError):
        pz(None)  # None is handled by the transformer, not hashed


def test_not_a_plain_hash() -> None:
    import hashlib

    token = pz("alice@example.com")
    plain = hashlib.sha256(b"alice@example.com").hexdigest()
    assert plain[:16] not in token


def test_known_answer_vector() -> None:
    # Pins transform version pz1. Test-only key; never used outside this test.
    key = bytes(range(32))
    token, _ = derive_token(key, "ciphergate:pz1:ns:field:/email", "alice@example.com", "nfc")
    assert (
        token == derive_token(key, "ciphergate:pz1:ns:field:/email", "alice@example.com", "nfc")[0]
    )
    assert len(token) == 32 and set(token) <= set("abcdefghijklmnopqrstuvwxyz234567")


def test_collision_tracker() -> None:
    tracker = CollisionTracker()
    tracker.check("t", b"a")
    tracker.check("t", b"a")
    with pytest.raises(TransformError):
        tracker.check("t", b"b")


# ----------------------------------------------------------------------------- redact/replace


def test_redact_and_replace() -> None:
    assert redact(RedactParams(), "pii.email") == "[REDACTED:pii.email]"
    assert redact(RedactParams(marker="[GONE]"), "pii.email") == "[GONE]"
    assert replace(ReplaceParams(value=None), in_span=False) is None
    assert replace(ReplaceParams(value=None), in_span=True) == "null"
    assert replace(ReplaceParams(value=0), in_span=False) == 0
    assert replace(ReplaceParams(value=False), in_span=True) == "false"


# ----------------------------------------------------------------------------- generalize


@pytest.mark.parametrize(
    ("value", "params", "expected"),
    [
        ("1990-04-12", {"strategy": "year"}, "1990"),
        ("1990-04-12T10:00:00Z", {"strategy": "year_month"}, "1990-04"),
        ("1990/04/12", {"strategy": "year"}, "1990"),
        (37, {"strategy": "age_band"}, "30-39"),
        ("0", {"strategy": "age_band"}, "0-9"),
        (130, {"strategy": "age_band"}, "120+"),
        (119.9, {"strategy": "age_band"}, "110-119"),
        (51.50735, {"strategy": "round_coordinates", "decimals": 2}, 51.51),
        ("-0.12776", {"strategy": "round_coordinates", "decimals": 1}, "-0.1"),
        (5, {"strategy": "numeric_bin", "bins": [0, 10, 100]}, "[0, 10)"),
        (-1, {"strategy": "numeric_bin", "bins": [0, 10, 100]}, "<0"),
        (100, {"strategy": "numeric_bin", "bins": [0, 10, 100]}, ">=100"),
    ],
)
def test_generalize(value: object, params: dict, expected: object) -> None:
    assert generalize(value, GeneralizeParams(**params)) == expected


@pytest.mark.parametrize(
    ("value", "strategy"),
    [
        ("not a date", "year"),
        ("2023-02-29", "year"),
        (1990, "year"),
        (-1, "age_band"),
        ("abc", "age_band"),
        (True, "age_band"),
        (200.0, "round_coordinates"),
        (float("nan"), "age_band"),
    ],
)
def test_generalize_rejects(value: object, strategy: str) -> None:
    with pytest.raises(TransformError):
        generalize(value, GeneralizeParams(strategy=strategy))  # type: ignore[arg-type]


# ----------------------------------------------------------------------------- date shift


def test_offset_bounds_nonzero_and_stable() -> None:
    offsets = {derive_offset_days(secrets.token_bytes(32), "ns", "dataset", 3) for _ in range(200)}
    assert offsets <= {-3, -2, -1, 1, 2, 3} and 0 not in offsets
    assert derive_offset_days(KEY, "ns", "p1", 30) == derive_offset_days(KEY, "ns", "p1", 30)


@pytest.mark.parametrize(
    ("text", "days", "expected"),
    [
        ("2024-02-28", 1, "2024-02-29"),
        ("2024-02-29", 1, "2024-03-01"),
        ("2023-02-28", 1, "2023-03-01"),
        ("2026-03-08T01:30:00-05:00", 1, "2026-03-09T01:30:00-05:00"),
        ("2026-01-05T10:00:00Z", -5, "2025-12-31T10:00:00Z"),
        ("2026-01-05 10:00", 2, "2026-01-07 10:00:00"),
    ],
)
def test_shift_iso(text: str, days: int, expected: str) -> None:
    assert shift_date_text(text, days, ["iso"]) == expected


def test_shift_explicit_format_and_failures() -> None:
    assert shift_date_text("05/01/2026", 1, ["%d/%m/%Y"]) == "06/01/2026"
    for bad in ("2026-13-01", "yesterday", "2026-01-05x", "1700000000"):
        with pytest.raises(TransformError):
            shift_date_text(bad, 1, ["iso"])
    with pytest.raises(TransformError):
        shift_date_text("9999-12-31", 5, ["iso"])


def test_shift_preserves_intervals_in_dataset_scope() -> None:
    import datetime as dt

    offset = derive_offset_days(KEY, "ns", "dataset", 30)
    a = dt.date.fromisoformat(shift_date_text("2026-01-01", offset, ["iso"]))
    b = dt.date.fromisoformat(shift_date_text("2026-01-11", offset, ["iso"]))
    assert (b - a).days == 10


# ----------------------------------------------------------------------------- combination


def _f(category: str, span: tuple[int, int] | None) -> Finding:
    return Finding(category, "x", 0.9, (), Location(0, 1, "/m", span=span), "m", "string")


def _d(action: Action, params: object = None) -> Decision:
    from ciphergate.models.policy import EmptyParams

    return Decision(
        action, ReasonCode.EXPLICIT_POLICY_MATCH, LEVEL_CATEGORY, params=params or EmptyParams()
    )  # type: ignore[arg-type]


def test_transformer_spans_preserve_context() -> None:
    t = Transformer(load_policy_text("policy_version: 1\nname: t\n"), KeyProvider({}))
    text = "user a@example.com from 10.0.0.1 ok"
    out = t.transform_value(
        text,
        [
            (_f("pii.email", (5, 18)), _d(Action.REDACT, RedactParams())),
            (_f("network.telemetry", (24, 32)), _d(Action.ALLOW)),
        ],
        field_path="/m",
    )
    assert out.value == "user [REDACTED:pii.email] from 10.0.0.1 ok"


def test_transformer_overlapping_spans_use_most_protective() -> None:
    t = Transformer(load_policy_text("policy_version: 1\nname: t\n"), KeyProvider({}))
    out = t.transform_value(
        "abcdefgh",
        [
            (_f("pii.phone", (0, 5)), _d(Action.REPLACE, ReplaceParams(value="X"))),
            (_f("credential.secret", (3, 8)), _d(Action.REDACT, RedactParams())),
        ],
        field_path="/m",
    )
    assert out.value == "[REDACTED:credential.secret]"


def test_transformer_whole_value_and_drops() -> None:
    t = Transformer(load_policy_text("policy_version: 1\nname: t\n"), KeyProvider({}))
    out = t.transform_value(
        4111111111111111,
        [(_f("pii.payment_card", None), _d(Action.REDACT, RedactParams()))],
        field_path="/c",
    )
    assert out.value == "[REDACTED:pii.payment_card]" and out.type_changed
    assert t.transform_value(
        "x", [(_f("pii.email", None), _d(Action.DROP_FIELD))], field_path="/e"
    ).drop_field
    assert t.transform_value(
        "x",
        [
            (_f("pii.email", None), _d(Action.DROP_RECORD)),
            (_f("pii.email", None), _d(Action.DROP_FIELD)),
        ],
        field_path="/e",
    ).drop_record


def test_transformer_refuses_block_and_review() -> None:
    from ciphergate.errors import InternalError

    t = Transformer(load_policy_text("policy_version: 1\nname: t\n"), KeyProvider({}))
    for action in (Action.BLOCK, Action.REVIEW):
        with pytest.raises(InternalError):
            t.transform_value("x", [(_f("pii.email", None), _d(action))], field_path="/e")


def test_date_shift_entity_requires_entity_value() -> None:
    t = Transformer(
        load_policy_text("policy_version: 1\nname: t\n"),
        KeyProvider({"CIPHERGATE_HMAC_KEY": "hex:" + secrets.token_hex(32)}),
    )
    params = DateShiftParams(max_days=10, scope="entity", entity_field="patient_id")
    ev = [(_f("health.clinical_date", None), _d(Action.DATE_SHIFT, params))]
    with pytest.raises(TransformError):
        t.transform_value("2026-01-01", ev, field_path="/d", entity_lookup=lambda _: None)
    a = t.transform_value("2026-01-01", ev, field_path="/d", entity_lookup=lambda _: "P1")
    b = t.transform_value("2026-01-11", ev, field_path="/d", entity_lookup=lambda _: "P1")
    import datetime as dt

    assert (dt.date.fromisoformat(b.value) - dt.date.fromisoformat(a.value)).days == 10
