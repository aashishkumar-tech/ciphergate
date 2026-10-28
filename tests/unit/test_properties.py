"""Property-based and resource-limit tests (Hypothesis)."""

from __future__ import annotations

import csv
import io
import json
import secrets
import time
from collections.abc import Callable
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ciphergate import RunStatus, sanitize_file
from ciphergate.config import RuntimeSettings
from ciphergate.detectors.registry import DetectorSet
from ciphergate.errors import CipherGateError
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import DetectorSettings, PseudonymizeParams, RedactParams
from ciphergate.pipeline.sanitizer import SanitizeOptions
from ciphergate.policy.validator import Policy, load_policy_text
from ciphergate.transforms.pseudonymize import pseudonymize
from ciphergate.transforms.redact import redact
from tests.conftest import MINIMAL_POLICY

KEY = secrets.token_bytes(32)
DETECTORS = DetectorSet(DetectorSettings())
POLICY = load_policy_text(MINIMAL_POLICY)
FAST = settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)

json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(-(10**12), 10**12)
    | st.text(max_size=30)
    | (st.floats(allow_nan=False, allow_infinity=False))
)
json_values = st.recursive(
    json_scalars,
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4),
    max_leaves=20,
)


@given(st.text(max_size=300))
@FAST
def test_detectors_never_crash_and_spans_valid(text: str) -> None:
    for f in DETECTORS.scan(ScanItem(0, 1, "/f", "notes", text)):
        if f.location.span:
            start, end = f.location.span
            assert 0 <= start < end <= len(text)
        assert 0.0 <= f.confidence <= 1.0


@given(st.one_of(st.text(max_size=50), st.integers(), st.floats(allow_nan=False), st.booleans()))
@FAST
def test_pseudonym_deterministic(value: object) -> None:
    params = PseudonymizeParams(scope="field")
    a = pseudonymize(value, params, key=KEY, namespace="n", category="c", field_path="/x")
    b = pseudonymize(value, params, key=KEY, namespace="n", category="c", field_path="/x")
    assert a == b and len(a) == 36


MARKER = redact(RedactParams(), "pii.email")


# Values that are substrings of the constant marker trivially "appear" in it; exclude only those.
@given(st.text(min_size=4, max_size=40).filter(lambda s: s not in MARKER))
@FAST
def test_redaction_never_contains_original(value: str) -> None:
    assert value not in redact(RedactParams(), "pii.email")


@given(json_values)
@FAST
def test_json_roundtrip_unaffected_data(tmp_path_factory: object, value: object) -> None:
    tmp = tmp_path_factory.mktemp("j")  # type: ignore[attr-defined]
    src = tmp / "in.json"
    src.write_text(json.dumps(value), encoding="utf-8")
    out = tmp / "out.json"
    try:
        r = sanitize_file(src, out, POLICY, options=SanitizeOptions())
    except CipherGateError:
        assert not out.exists()
        return
    if r.status == RunStatus.SANITIZED:
        parsed = json.loads(out.read_text(encoding="utf-8"))  # output always parseable
        if r.summary["findings_total"] == 0:
            assert parsed == value
    else:
        assert not out.exists()


@given(
    st.lists(
        st.lists(
            st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12),
            min_size=2,
            max_size=2,
        ),
        max_size=6,
    )
)
@FAST
def test_csv_roundtrip(tmp_path_factory: object, rows: list[list[str]]) -> None:
    tmp = tmp_path_factory.mktemp("c")  # type: ignore[attr-defined]
    buf = io.StringIO()
    # QUOTE_ALL: with QUOTE_MINIMAL the stdlib writer leaves a lone CR unquoted, producing an
    # input that no longer represents ``rows``. Bytes avoid Windows newline translation.
    csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_ALL).writerows([["a", "b"], *rows])
    src = tmp / "in.csv"
    src.write_bytes(buf.getvalue().encode("utf-8"))
    out = tmp / "o.csv"
    try:
        r = sanitize_file(src, out, POLICY)
    except CipherGateError:
        assert not out.exists()
        return
    if r.status == RunStatus.SANITIZED:
        with out.open(encoding="utf-8", newline="") as fh:
            parsed = list(csv.reader(fh))
        assert parsed[0] == ["a", "b"]
        if r.summary["findings_total"] == 0:
            assert parsed[1:] == rows  # unaffected rows survive byte-for-byte semantically


# ----------------------------------------------------------------------------- resource limits


def test_too_many_findings(tmp_path: Path) -> None:
    from ciphergate import inspect_file
    from ciphergate.errors import InputLimitError

    src = tmp_path / "many.log"
    src.write_text("a@example.com b@example.com\n" * 100, encoding="utf-8")
    try:
        inspect_file(src, POLICY, runtime=RuntimeSettings(max_findings=50))
    except InputLimitError as exc:
        assert exc.code == "too_many_findings"
    else:
        raise AssertionError("limit not enforced")


def test_pathological_inputs_are_fast() -> None:
    hostile = [
        "a" * 50_000 + "@",
        "@" * 20_000,
        "1" * 50_000,
        "1-" * 20_000,
        ":" * 30_000,
        "password=" * 5_000,
        "-----BEGIN PRIVATE KEY-----" * 500,
        ("a." * 10_000) + "internal",
    ]
    start = time.perf_counter()
    for text in hostile:
        DETECTORS.scan(ScanItem(0, 1, "", None, text))
    assert time.perf_counter() - start < 10


def test_deep_json_and_giant_line(
    tmp_path: Path, write: Callable[[str, str | bytes], Path], policy_text: Callable[[str], Policy]
) -> None:
    from ciphergate import inspect_file
    from ciphergate.errors import InputLimitError

    deep = write("deep.json", "[" * 10_000 + "]" * 10_000)
    giant = write("giant.log", "x" * (2 * 1024 * 1024) + "\n")
    for path in (deep, giant):
        try:
            inspect_file(path, POLICY)
        except InputLimitError:
            continue
        raise AssertionError(f"limit not enforced for {path.name}")
