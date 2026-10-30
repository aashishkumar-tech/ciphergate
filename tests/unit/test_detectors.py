"""Positive, negative, edge and ambiguity cases for every built-in detector."""

from __future__ import annotations

import pytest

from ciphergate.detectors.custom_regex import CustomRegexDetector
from ciphergate.detectors.dates import DateDetector
from ciphergate.detectors.email import EmailDetector
from ciphergate.detectors.field_names import (
    FieldNameDetector,
    PolicyClassificationDetector,
    classify_field_name,
    normalize_field_name,
)
from ciphergate.detectors.iban import IbanDetector, iban_valid
from ciphergate.detectors.ip_address import IPAddressDetector
from ciphergate.detectors.mac_address import MacAddressDetector
from ciphergate.detectors.network import InternalHostDetector
from ciphergate.detectors.payment_card import PaymentCardDetector, luhn_valid
from ciphergate.detectors.phone import PhoneDetector
from ciphergate.detectors.regex_safety import regex_problems
from ciphergate.detectors.registry import DetectorSet, TextBlockState, unsafe_replacement_reason
from ciphergate.detectors.secrets import SecretDetector
from ciphergate.detectors.ssn import SsnDetector
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import Classification, CustomDetector, DetectorSettings


def item(value: object, field: str | None = None) -> ScanItem:
    return ScanItem(record_index=0, line=1, field_path=field or "", field_name=field, value=value)


def spans(findings: list, text: str) -> list[str]:
    return [text[f.location.span[0] : f.location.span[1]] for f in findings if f.location.span]


# ----------------------------------------------------------------------------- email


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("contact alice.test@example.com now", ["alice.test@example.com"]),
        ("<bob+tag@sub.example.org>,", ["bob+tag@sub.example.org"]),
        ("trailing dot alice@example.com.", ["alice@example.com"]),
        ("two a@example.com b@example.net", ["a@example.com", "b@example.net"]),
    ],
)
def test_email_positive(text: str, expected: list[str]) -> None:
    assert spans(EmailDetector().detect(item(text)), text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "not an email",
        "user@localhost",
        "a..b@example.com",
        ".a@example.com",
        "@example.com",
        "x@-bad.example.com",
    ],
)
def test_email_negative(text: str) -> None:
    assert EmailDetector().detect(item(text)) == []


def test_email_reserved_domain_evidence() -> None:
    f = EmailDetector().detect(item("u@example.invalid"))[0]
    assert "reserved_domain" in f.evidence


# ----------------------------------------------------------------------------- phone


@pytest.mark.parametrize(
    ("text", "min_conf"),
    [
        ("call +1 202 555 0143", 0.8),
        ("+44 20 7946 0958", 0.8),
        ("phone: (202) 555-0143", 0.6),
        ("tel 202-555-0143 x123", 0.6),
    ],
)
def test_phone_positive(text: str, min_conf: float) -> None:
    findings = PhoneDetector().detect(item(text))
    assert findings and max(f.confidence for f in findings) >= min_conf


def test_phone_bare_digits_are_low_confidence() -> None:
    f = PhoneDetector().detect(item("id 2025550143"))
    assert f and f[0].band == "low"


@pytest.mark.parametrize(
    "text", ["2026-01-05", "12/31/2026", "123456", "1111111111", "v1.2.3", "+12 34"]
)
def test_phone_negative(text: str) -> None:
    assert PhoneDetector().detect(item(text)) == []


def test_phone_suppressed_by_card_ip_date_in_registry() -> None:
    ds = DetectorSet(DetectorSettings())
    for text in ("4111 1111 1111 1111", "2026-01-05T10:00:00Z", "10.0.12.7"):
        assert not [f for f in ds.scan(item(text)) if f.category == "pii.phone"], text


# ----------------------------------------------------------------------------- ip


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("from 8.8.8.8", "pii.ip_address"),
        ("from 10.0.0.1", "network.telemetry"),
        ("loopback 127.0.0.1", "network.telemetry"),
        ("v6 2606:4700::1111", "pii.ip_address"),
        ("v6 ::1", "network.telemetry"),
        ("link fe80::1%eth0", "network.telemetry"),
        ("bracket [2606:4700::1111]:443", "pii.ip_address"),
    ],
)
def test_ip_positive(text: str, category: str) -> None:
    findings = IPAddressDetector().detect(item(text))
    assert [f.category for f in findings] == [category]


@pytest.mark.parametrize(
    "text", ["256.1.1.1", "1.2.3", "10.0.0.1.5", "std::vector", "12:30:45", "abc::def::1", "::"]
)
def test_ip_negative(text: str) -> None:
    assert IPAddressDetector().detect(item(text)) == []


def test_ip_documentation_range_flagged() -> None:
    f = IPAddressDetector().detect(item("192.0.2.44"))[0]
    assert "documentation_range" in f.evidence


# ----------------------------------------------------------------------------- cards


def test_luhn() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


@pytest.mark.parametrize(
    "text", ["4111 1111 1111 1111", "4111-1111-1111-1111", "5555555555554444", "378282246310005"]
)
def test_card_high_confidence(text: str) -> None:
    f = PaymentCardDetector().detect(item(text))
    assert f and f[0].band == "high" and "checksum_valid" in f[0].evidence


def test_card_luhn_invalid_ignored() -> None:
    assert PaymentCardDetector().detect(item("4111 1111 1111 1112")) == []


def test_long_luhn_valid_identifier_without_prefix_is_low() -> None:
    # 18-digit Luhn-valid number without issuer prefix or context.
    digits = "100000000000000008"
    assert luhn_valid(digits)
    f = PaymentCardDetector().detect(item(f"order {digits}"))
    assert f and f[0].band == "low"


def test_card_mixed_separators_and_repeated_digits_ignored() -> None:
    assert PaymentCardDetector().detect(item("4111 1111-1111 1111")) == []
    assert PaymentCardDetector().detect(item("0000000000000000")) == []


def test_card_as_json_integer() -> None:
    assert PaymentCardDetector().detect(item(4111111111111111))


# ----------------------------------------------------------------------------- secrets


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123", "TEST_ONLY_NOT_A_REAL_TOKEN_123"),
        ("password=TEST_ONLY_NOT_A_CREDENTIAL", "TEST_ONLY_NOT_A_CREDENTIAL"),
        ('{"api_key": "TEST_ONLY_KEY_000"}', "TEST_ONLY_KEY_000"),
        ('msg="client_secret: \\"TESTSECRET01\\""', "TESTSECRET01"),
        ("aws AKIATESTONLYNOTREAL1 used", "AKIATESTONLYNOTREAL1"),
        ("tok ghp_" + "T" * 36, "ghp_" + "T" * 36),
        ("postgres://app:TEST_ONLY_PW@db.example.invalid/app", "TEST_ONLY_PW"),
        ("Server=x;User Id=app;Password=TEST_ONLY_PW2;", "TEST_ONLY_PW2"),
        ("export SECRET_KEY=TEST_ONLY_VALUE", "TEST_ONLY_VALUE"),
        ("csrf_token=TEST_ONLY_CSRF", "TEST_ONLY_CSRF"),
        ("token: TEST_ONLY_TOKEN", "TEST_ONLY_TOKEN"),
        ("jwt eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"),
    ],
)
def test_secret_positive(text: str, secret: str) -> None:
    findings = SecretDetector().detect(item(text))
    assert secret in spans(findings, text)
    assert all(f.category == "credential.secret" for f in findings)


@pytest.mark.parametrize(
    "text",
    [
        "password=",
        "password: null",
        "password=[REDACTED:credential.secret]",
        "password=********",
        "token_count=42",
        "the key_name is fine",
        "monkey business",
    ],
)
def test_secret_negative(text: str) -> None:
    assert SecretDetector().detect(item(text)) == []


def test_private_key_in_single_value() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nTESTONLYBODY\n-----END RSA PRIVATE KEY-----"
    f = SecretDetector().detect(item(text))
    assert f[0].location.span == (0, len(text))


def test_private_key_block_across_text_lines() -> None:
    ds = DetectorSet(DetectorSettings())
    state = TextBlockState()
    lines = [
        "key:",
        "-----BEGIN PRIVATE KEY-----",
        "TESTONLYBODYLINE1",
        "TESTONLYBODYLINE2",
        "-----END PRIVATE KEY-----",
        "after",
    ]
    flagged = []
    for i, line in enumerate(lines):
        findings = ds.scan_text_line(ScanItem(i, i + 1, "", None, line), state)
        flagged.append(any(f.category == "credential.secret" for f in findings))
    assert flagged == [False, True, True, True, True, False]


# ----------------------------------------------------------------------------- dates


def test_dob_requires_context() -> None:
    assert DateDetector().detect(item("created 2026-01-05")) == []
    assert DateDetector().detect(item("1990-04-12", field="birth_date"))[0].category == (
        "pii.date_of_birth"
    )
    assert DateDetector().detect(item("dob: 1990-04-12"))[0].category == "pii.date_of_birth"


def test_generic_dates_when_enabled() -> None:
    f = DateDetector(emit_generic=True).detect(item("at 2026-01-05T10:00:00+05:30"))
    assert f and f[0].category == "date.generic"


def test_ambiguous_locale_and_invalid_dates() -> None:
    f = DateDetector(emit_generic=True).detect(item("03/04/2020"))
    assert "ambiguous_locale" in f[0].evidence
    assert DateDetector(emit_generic=True).detect(item("2026-02-30")) == []
    assert DateDetector(emit_generic=True).detect(item("2024-02-29"))  # leap day valid
    assert DateDetector(emit_generic=True).detect(item("2023-02-29")) == []


def test_dates_with_null_byte_not_partially_parsed() -> None:
    assert DateDetector(emit_generic=True).detect(item("2026-01-0\x005")) == []


# ----------------------------------------------------------------------------- field names


@pytest.mark.parametrize(
    ("name", "category"),
    [
        ("email", "pii.email"),
        ("contactEmail", "pii.email"),
        ("E-Mail", "pii.email"),
        ("firstName", "pii.person_name"),
        ("date-of-birth", "pii.date_of_birth"),
        ("API_KEY", "credential.secret"),
        ("clientSecret", "credential.secret"),
        ("server_ip_address", "pii.ip_address"),
        ("home_address", "pii.address"),
        ("userId", "pii.customer_identifier"),
        ("trace_id", "network.telemetry"),
        ("MRN", "health.phi"),
    ],
)
def test_field_names(name: str, category: str) -> None:
    term = classify_field_name(name)
    assert term is not None and term.category == category


@pytest.mark.parametrize(
    "name",
    [
        "monkey",
        "token_count",
        "key_name",
        "product_name",
        "id",
        "value",
        "email_verified",
        "zipper",
        "description",
    ],
)
def test_field_names_misleading(name: str) -> None:
    assert classify_field_name(name) is None


def test_normalization() -> None:
    assert normalize_field_name("HTTPRequestID") == "http_request_id"
    assert normalize_field_name("  Contact Email ") == "contact_email"


def test_field_name_detector_skips_empty_and_markers() -> None:
    d = FieldNameDetector()
    assert d.detect(item("", field="email")) == []
    assert d.detect(item(None, field="email")) == []
    assert d.detect(item("[REDACTED:pii.email]", field="email")) == []
    assert d.detect(item(0, field="user_id"))  # zero is data, not missing


def test_policy_classification() -> None:
    d = PolicyClassificationDetector(
        [Classification(id="c", field_names=["admissionDate"], category="health.phi")]
    )
    assert d.detect(item("2026-01-01", field="admission_date"))[0].category == "health.phi"


# ----------------------------------------------------------------------------- other


def test_internal_host() -> None:
    d = InternalHostDetector([".internal", ".corp"])
    text = "call api-1.prod.internal and db.corp, not example.com or a.internalx"
    assert spans(d.detect(item(text)), text) == ["api-1.prod.internal", "db.corp"]


def test_custom_regex_detector() -> None:
    d = CustomRegexDetector(
        CustomDetector(id="order", category="identifier.generic", pattern=r"ORD-[0-9]{6}")
    )
    text = "order ORD-123456 shipped"
    assert spans(d.detect(item(text)), text) == ["ORD-123456"]


@pytest.mark.parametrize(
    ("pattern", "problem"),
    [
        ("(a+)+", "nested quantifier"),
        ("(\\w*)*x", "nested quantifier"),
        ("(a)\\1", "backreferences"),
        ("a*", "empty string"),
        ("(", "does not compile"),
        ("x" * 600, "longer than"),
        (".*a.*b", "multiple unbounded"),
    ],
)
def test_regex_safety(pattern: str, problem: str) -> None:
    assert any(problem in p for p in regex_problems(pattern))


def test_regex_safety_accepts_bounded() -> None:
    assert regex_problems(r"ORD-[0-9]{6}") == []


@pytest.mark.parametrize(
    ("value", "unsafe"),
    [
        ("user@example.invalid", False),
        ("Test Person", False),
        ("192.0.2.1", False),
        ("real@gmail.com", True),
        ("4111111111111111", True),
        ("password=hunter22", True),
        ("+1 202 555 0143", True),
        ("8.8.8.8", True),
    ],
)
def test_unsafe_replacement(value: str, unsafe: bool) -> None:
    assert (unsafe_replacement_reason(value) is not None) is unsafe


def test_findings_never_contain_raw_values() -> None:
    ds = DetectorSet(DetectorSettings())
    text = "alice.test@example.com Bearer TEST_ONLY_NOT_A_REAL_TOKEN_123 4111 1111 1111 1111"
    for f in ds.scan(item(text, field="notes")):
        rendered = repr(f) + str(f.location.to_dict()) + str(f.evidence)
        for secret in ("alice.test", "TEST_ONLY_NOT", "4111"):
            assert secret not in rendered


# ----------------------------------------------------------------- mac address and iban


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("dhcp lease for 00:1A:2B:3C:4D:5E done", ["00:1A:2B:3C:4D:5E"]),
        ("device 00-1a-2b-3c-4d-5e offline", ["00-1a-2b-3c-4d-5e"]),
        ("port 001a.2b3c.4d5e up", ["001a.2b3c.4d5e"]),
        ("mixed 00:1a-2b:3c:4d:5e", []),
        ("null 00:00:00:00:00:00 broadcast ff:ff:ff:ff:ff:ff", []),
        ("at 12:30:45 today", []),
        ("seven 00:1a:2b:3c:4d:5e:6f groups", []),
        ("host 2001:db8::1 up", []),
    ],
)
def test_mac_address(text: str, expected: list[str]) -> None:
    findings = MacAddressDetector().detect(item(text))
    assert spans(findings, text) == expected
    assert all(f.category == "pii.device_identifier" for f in findings)


def test_mac_address_confidence_is_lower_when_all_digits() -> None:
    assert MacAddressDetector().detect(item("id 12-34-56-78-90-12"))[0].confidence == 0.6
    assert MacAddressDetector().detect(item("id 12-34-56-78-90-ab"))[0].confidence == 0.85


IBAN = "GB82" + "WEST" + "12345698765432"  # the ISO 13616 example number
IBAN_SPACED = "GB82 WEST 1234 5698 7654 32"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"payout to {IBAN} failed", [IBAN]),
        (f"payout to {IBAN_SPACED} failed", [IBAN_SPACED]),
        (f"payout to {IBAN_SPACED} DONE", [IBAN_SPACED]),
        ("payout to GB83" + "WEST12345698765432 failed", []),
        ("payout to " + IBAN.lower(), []),
        ("code AB12 short", []),
    ],
)
def test_iban(text: str, expected: list[str]) -> None:
    findings = IbanDetector().detect(item(text))
    assert spans(findings, text) == expected
    assert all(f.category == "pii.bank_account" for f in findings)


def test_iban_valid_rejects_bad_lengths() -> None:
    assert iban_valid(IBAN)
    assert not iban_valid("GB82WEST")


def test_new_detectors_suppress_phone_matches() -> None:
    detectors = DetectorSet(DetectorSettings())
    text = f"account {IBAN_SPACED} and 12-34-56-78-90-12"
    ids = {f.detector for f in detectors.scan(item(text))}
    assert "phone_pattern" not in ids and {"iban", "mac_address"} <= ids


def test_new_detectors_can_be_disabled() -> None:
    detectors = DetectorSet(DetectorSettings(disabled=["mac_address", "iban"]))
    assert not detectors.scan(item(f"{IBAN} 00:1A:2B:3C:4D:5E"))


@pytest.mark.parametrize("value", [IBAN, "00:1A:2B:3C:4D:5E"])
def test_replacement_must_not_look_real(value: str) -> None:
    assert unsafe_replacement_reason(value) is not None


# ------------------------------------------------------------- encoded and env-style values


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("GET /users?mail=alice.test%40example.com 404", "alice.test%40example.com"),
        ("redirect /v?a=Alice%40EXAMPLE.org&b=1", "Alice%40EXAMPLE.org"),
    ],
)
def test_percent_encoded_email(text: str, expected: str) -> None:
    assert spans(EmailDetector().detect(item(text)), text) == [expected]


def test_percent_40_without_an_address_is_ignored() -> None:
    assert not EmailDetector().detect(item("progress 100%40 done"))


@pytest.mark.parametrize(
    "name", ["PGPASSWORD", "pgpassword", "MYSQL_PWD", "DBPASSWORD", "ROOTPASSWORD", "UserPassword"]
)
def test_env_style_password_names(name: str) -> None:
    text = f"{name}=TEST_ONLY_NOT_A_CREDENTIAL psql"
    assert spans(SecretDetector().detect(item(text)), text) == ["TEST_ONLY_NOT_A_CREDENTIAL"]


@pytest.mark.parametrize("name", ["nopassword", "haspassword", "password_reset_enabled"])
def test_other_password_words_stay_unmatched(name: str) -> None:
    assert not SecretDetector().detect(item(f"{name}=enabled"))


# ------------------------------------------------- bugs found by simulated developer runs


TEST_ONLY = "TEST_ONLY_NOT_A_CREDENTIAL"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ssn 219-09-9999 failed", ["219-09-9999"]),
        ("078-05-1120", ["078-05-1120"]),
        ("area 000-12-3456", []),
        ("area 666-12-3456", []),
        ("area 912-12-3456", []),
        ("group 219-00-9999", []),
        ("serial 219-09-0000", []),
        ("long 1219-09-99991", []),
        ("undashed 219099999", []),
    ],
)
def test_ssn(text: str, expected: list[str]) -> None:
    findings = SsnDetector().detect(item(text))
    assert spans(findings, text) == expected
    assert all(f.category == "pii.government_id" for f in findings)


def test_ssn_is_not_reported_as_a_phone_number() -> None:
    categories = {f.category for f in DetectorSet(DetectorSettings()).scan(item("id 219-09-9999"))}
    assert categories == {"pii.government_id"}


@pytest.mark.parametrize(
    "text",
    [
        f'{{"spring.datasource.password":{{"value":"{TEST_ONLY}"}}}}',
        f'{{"password": {{ "value": "{TEST_ONLY}" }}}}',
    ],
)
def test_nested_value_is_found_not_the_brace(text: str) -> None:
    assert spans(SecretDetector().detect(item(text)), text) == [TEST_ONLY]


def test_lone_brace_is_not_a_secret() -> None:
    assert not SecretDetector().detect(item('{"password":{"rotated":true}}'))


@pytest.mark.parametrize(
    "text",
    [
        f"-Djavax.net.ssl.keyStorePassword={TEST_ONLY}",
        f"trustStorePassword: {TEST_ONLY}",
        f'{{"dbPassword":"{TEST_ONLY}"}}',
    ],
)
def test_camel_case_password_names(text: str) -> None:
    assert spans(SecretDetector().detect(item(text)), text) == [TEST_ONLY]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"Cookie: sessionid={TEST_ONLY}; csrftoken={TEST_ONLY}",
            f"sessionid={TEST_ONLY}; csrftoken={TEST_ONLY}",
        ),
        (f"Set-Cookie: sid={TEST_ONLY}; Path=/", f"sid={TEST_ONLY}; Path=/"),
        (f"'sessionid': '{TEST_ONLY}'", TEST_ONLY),
        (f"csrfmiddlewaretoken={TEST_ONLY}&next=/", TEST_ONLY),
        (f"JSESSIONID={TEST_ONLY}", TEST_ONLY),
        (f"session={TEST_ONLY}", TEST_ONLY),
    ],
)
def test_cookies_and_session_values(text: str, expected: str) -> None:
    assert spans(SecretDetector().detect(item(text)), text) == [expected]


@pytest.mark.parametrize(
    "text",
    ["cookie: required", "session: established", "session=short", "sessionid=abc"],
)
def test_cookie_prose_is_not_a_secret(text: str) -> None:
    assert not SecretDetector().detect(item(text))


@pytest.mark.parametrize(
    "text",
    [
        "PWD=/home/heidi",
        "pwd=~/project",
        "PWD=C:\\Users\\heidi",
        'token=request.POST["card_token"]',
        "api_key=settings.CRM_KEY",
        "secret=os.environ['SIGNING']",
        "password=config.db_password",
    ],
)
def test_paths_and_code_references_are_not_secrets(text: str) -> None:
    assert not SecretDetector().detect(item(text))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"Password={TEST_ONLY};Server=db", TEST_ONLY),
        (f"PWD={TEST_ONLY}", TEST_ONLY),
        ("password=/TEST_ONLY_slash", "/TEST_ONLY_slash"),
        ("api_key=settingsTEST_ONLY", "settingsTEST_ONLY"),
    ],
)
def test_real_values_near_those_exceptions_stay_found(text: str, expected: str) -> None:
    assert spans(SecretDetector().detect(item(text)), text) == [expected]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("cvv=123", ["123"]),
        ('{"cvc": "1234"}', ["1234"]),
        ("CVV2: 123", ["123"]),
        ("cvv=12", []),
        ("cvv=12345", []),
        ("cvv=enabled", []),
    ],
)
def test_labelled_cvv(text: str, expected: list[str]) -> None:
    findings = PaymentCardDetector().detect(item(text))
    assert spans(findings, text) == expected
    assert all(f.category == "pii.payment_card" for f in findings)


def test_http_status_and_bytes_are_not_a_phone() -> None:
    assert not PhoneDetector().detect(item('GET /x 200 1024 "-"'))


def test_a_number_after_a_phone_keyword_is_still_a_phone() -> None:
    assert PhoneDetector().detect(item("phone 202 5550143"))
