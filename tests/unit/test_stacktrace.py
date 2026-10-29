"""Stack-trace format (#47): classification, fail-closed scanning, limits and the text superset."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ciphergate import RunStatus, inspect_file, rescan_file, sanitize_file
from ciphergate.config import RuntimeSettings
from ciphergate.constants import InputFormat
from ciphergate.errors import InputLimitError
from ciphergate.pipeline.sanitizer import SanitizeOptions
from ciphergate.policy.validator import Policy
from ciphergate.readers.stacktrace_reader import (
    CONTEXT,
    EXCEPTION,
    FRAME,
    SOURCE,
    TraceState,
    classify,
)
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import MINIMAL_POLICY, SYNTHETIC_SECRETS, ctx

DEV = ctx("dev", dest="local_dev")
FMT = InputFormat.STACKTRACE
PY_FRAME = '  File "/srv/app/handlers.py", line 42, in handle'
JVM_FRAME = "\tat com.example.billing.Invoice.total(Invoice.java:88)"
NODE_FRAME = "    at Object.<anonymous> (/srv/app/index.js:10:5)"
PYTHON = [
    "Traceback (most recent call last):",
    PY_FRAME,
    "    user = load(email)",
    "           ^^^^^^^^^^^",
    "ValueError: no user alice.test@example.com",
]
JVM = [
    'Exception in thread "main" java.lang.IllegalStateException: boom',
    JVM_FRAME,
    "\tat com.example.billing.Api.get(Api.java:12) ~[app.jar:1.0]",
    "Caused by: java.io.IOException: disk",
    "\tat java.base/java.io.File.open(File.java:1)",
    "\t... 3 more",
]
NODE = ["TypeError: x is undefined", NODE_FRAME, "    at async /srv/app/main.mjs:3:9"]

REDACT_FRAMES = """  - id: redact-stack
    priority: 100
    match: {categories: [proprietary.source]}
    action: redact
"""


def _with_rule(rule: str) -> str:
    return MINIMAL_POLICY.replace("rules:\n", "rules:\n" + rule, 1)


def _roles(lines: list[str]) -> list[tuple[str, str, str] | None]:
    state = TraceState()
    out: list[tuple[str, str, str] | None] = []
    for line in lines:
        trace = classify(line, state)
        out.append(None if trace is None else (trace.role, trace.pointer, trace.family))
    return out


def _items(
    tmp_path: Path, text: str, policy: Policy, fmt: InputFormat = FMT
) -> list[dict[str, object]]:
    src = tmp_path / f"in-{fmt}.log"
    src.write_bytes(text.encode("utf-8"))
    return inspect_file(src, policy, DEV, fmt=fmt).items


def _sanitize(tmp_path: Path, text: str, policy: Policy) -> tuple[object, Path]:
    src = tmp_path / "in.log"
    src.write_bytes(text.encode("utf-8"))
    out = tmp_path / "out.log"
    report = sanitize_file(src, out, policy, DEV, SanitizeOptions(format=FMT, keys=KeyProvider({})))
    return report, out


# ----------------------------------------------------------------------------- classification


def test_python_traceback_roles() -> None:
    assert _roles(PYTHON) == [
        (CONTEXT, "/stack", ""),
        (FRAME, "/stack/frames/0", "python_frame"),
        (SOURCE, "/stack/frames/0/source", "python_source"),
        (SOURCE, "/stack/frames/0/source", "python_source"),
        (EXCEPTION, "/stack/exception", ""),
    ]


def test_jvm_trace_roles_with_cause_and_more() -> None:
    assert _roles(JVM) == [
        None,  # no lookahead: the header is only known to be one after it was read
        (FRAME, "/stack/frames/0", "jvm_frame"),
        (FRAME, "/stack/frames/1", "jvm_frame"),
        (EXCEPTION, "/stack/caused_by", ""),
        (FRAME, "/stack/frames/2", "jvm_frame"),
        (CONTEXT, "/stack", ""),
    ]
    assert _roles([JVM_FRAME, "\tSuppressed: a.B: c"])[1] == (EXCEPTION, "/stack/suppressed", "")


def test_node_frames() -> None:
    assert _roles(NODE) == [
        None,
        (FRAME, "/stack/frames/0", "node_frame"),
        (FRAME, "/stack/frames/1", "node_frame"),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "at com.example.Foo.bar(Foo.java:1)",  # a frame needs indentation
        "  at nothing",  # no location
        "Caused by: x.Y: z",  # only inside a run of frames
        "\t... 3 more",
        "    indented text outside a traceback",
        "",
    ],
)
def test_lines_outside_a_trace_are_not_classified(line: str) -> None:
    assert _roles([line]) == [None]


def test_interleaved_lines_end_a_trace_and_frames_still_count() -> None:
    roles = _roles([JVM_FRAME, "2026-01-05 INFO other request", JVM_FRAME])
    assert roles == [
        (FRAME, "/stack/frames/0", "jvm_frame"),
        None,
        (FRAME, "/stack/frames/0", "jvm_frame"),  # a new run: numbering restarts
    ]
    # A Python traceback ends at the first unindented line; a log line is no exception line.
    roles = _roles([*PYTHON[:3], "2026-01-05 INFO other request", "    not source any more"])
    assert roles[3:] == [None, None]


def test_python_frame_without_header_starts_a_traceback() -> None:
    roles = _roles(["2026-01-05 ERROR x Traceback (most recent call last):", *PYTHON[1:]])
    assert roles[0] is None
    assert roles[1] == (FRAME, "/stack/frames/0", "python_frame")
    assert roles[2] == (SOURCE, "/stack/frames/0/source", "python_source")


def test_classification_is_bounded() -> None:
    started = time.perf_counter()
    for line in (
        "  at " + "a" * 200_000,
        "  at " + "(" * 100_000,
        "  at a(" + "b" * 200_000,
        '  File "' + "x" * 200_000,
        "  File " + '"x", line 1' * 20_000,
        "\t" + "... 1 " * 40_000,
    ):
        classify(line, TraceState())
        classify(line, TraceState(kind="frames", frames=3))
    assert time.perf_counter() - started < 5


# ----------------------------------------------------------------------------- detection


def test_frames_and_source_lines_get_a_policy_finding(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(_with_rule(REDACT_FRAMES))
    text = "\n".join([*PYTHON, *JVM, *NODE]) + "\n"
    found = {
        (i["location"]["line"], i["category"], i["location"].get("field_path"))  # type: ignore[index,union-attr]
        for i in _items(tmp_path, text, policy)
    }
    assert (2, "proprietary.source", "/stack/frames/0") in found
    assert (3, "proprietary.source", "/stack/frames/0/source") in found
    assert (5, "pii.email", "/stack/exception") in found  # per-line finding, trace path added
    assert sum(1 for f in found if f[1] == "proprietary.source") == 3 + 3 + 2
    stack = [i for i in _items(tmp_path, text, policy) if i["detector"] == "stack_trace"]
    assert {(i["confidence"], i["band"]) for i in stack} == {(0.9, "high"), (0.8, "high")}


def test_text_mode_is_unchanged(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    policy = policy_text(_with_rule(REDACT_FRAMES))
    items = _items(tmp_path, "\n".join(PYTHON) + "\n", policy, InputFormat.TEXT)
    assert {i["category"] for i in items} == {"pii.email"}
    assert not any(i["location"].get("field_path") for i in items)  # type: ignore[union-attr]


def test_not_inferred_from_extension(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    src = tmp_path / "trace.log"
    src.write_bytes(("\n".join(PYTHON) + "\n").encode("utf-8"))
    assert inspect_file(src, policy_text(MINIMAL_POLICY), DEV).input["format"] == "text"


def test_allowing_frames_never_hides_other_findings(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    allow = REDACT_FRAMES.replace("action: redact", "action: allow")
    fake = SYNTHETIC_SECRETS[0]
    param = "api" + "_key"  # split so the repo secret scanner does not flag the fixture
    lines = [
        "Traceback (most recent call last):",
        '  File "/srv/alice.test@example.com/app.py", line 1, in f',
        f'    {param} = "{fake}"',
        "KeyError: x",
    ]
    report, out = _sanitize(tmp_path, "\n".join(lines) + "\n", policy_text(_with_rule(allow)))
    assert report.ok  # type: ignore[attr-defined]
    output = out.read_text(encoding="utf-8")
    assert fake not in output
    assert "alice.test@example.com" not in output
    assert 'File "/srv/' in output and "app.py" in output  # the allowed frame stays useful


def test_no_rule_for_frames_requires_review(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    report, out = _sanitize(tmp_path, "\n".join(JVM) + "\n", policy_text(MINIMAL_POLICY))
    assert report.status == RunStatus.REVIEW_REQUIRED  # type: ignore[attr-defined]
    assert not out.exists()


def test_block_rule_by_detector_publishes_nothing(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    block = """  - id: no-traces
    priority: 900
    match: {detectors: [stack_trace]}
    action: block
"""
    report, out = _sanitize(tmp_path, "\n".join(NODE) + "\n", policy_text(_with_rule(block)))
    assert report.status == RunStatus.BLOCKED  # type: ignore[attr-defined]
    assert not out.exists()


def test_pem_block_resets_the_trace(tmp_path: Path, policy_text: Callable[[str], Policy]) -> None:
    lines = [JVM_FRAME, "-----BEGIN PRIVATE KEY-----", "\tat a.B.c(B.java:1)"]  # TEST_ONLY
    lines += ["-----END PRIVATE KEY-----", "\t... 3 more"]
    items = _items(tmp_path, "\n".join(lines) + "\n", policy_text(_with_rule(REDACT_FRAMES)))
    by_line: dict[object, set[object]] = {}
    for i in items:
        by_line.setdefault(i["location"]["line"], set()).add(i["category"])  # type: ignore[index]
    assert by_line[3] == {"credential.secret"}  # key material is never read as a frame
    assert 5 not in by_line  # the run of frames ended at the key block


# ----------------------------------------------------------------------------- output


def test_sanitized_trace_keeps_messages_and_rescans_clean(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(_with_rule(REDACT_FRAMES))
    report, out = _sanitize(tmp_path, "\r\n".join([*PYTHON, *JVM, *NODE]) + "\r\n", policy)
    assert report.ok  # type: ignore[attr-defined]
    lines = out.read_bytes().decode("utf-8").split("\r\n")
    assert lines[0] == PYTHON[0]
    assert lines[1] == "  [REDACTED:proprietary.source]"
    assert lines[4] == "ValueError: no user [REDACTED:pii.email]"
    assert lines[8] == "Caused by: java.io.IOException: disk"
    assert lines[11].startswith("TypeError")
    rescan = rescan_file(out, policy, DEV, strict=True, fmt=FMT)
    assert rescan.status == RunStatus.PASSED


def test_truncated_trace_at_end_of_file(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    text = "\n".join(PYTHON[:3])  # no exception line, no final newline
    report, out = _sanitize(tmp_path, text, policy_text(_with_rule(REDACT_FRAMES)))
    assert report.ok  # type: ignore[attr-defined]
    assert out.read_text(encoding="utf-8") == (
        PYTHON[0] + "\n  [REDACTED:proprietary.source]\n    [REDACTED:proprietary.source]"
    )


def test_huge_trace_is_streamed_and_every_frame_protected(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    frames = 20_000
    text = PYTHON[0] + "\n" + (PY_FRAME + "\n    x()\n") * frames + "KeyError: k\n"
    started = time.perf_counter()
    report, out = _sanitize(tmp_path, text, policy_text(_with_rule(REDACT_FRAMES)))
    assert report.ok  # type: ignore[attr-defined]
    assert time.perf_counter() - started < 60
    assert "handlers.py" not in out.read_text(encoding="utf-8")
    assert report.summary["by_category"]["proprietary.source"] == 2 * frames  # type: ignore[attr-defined]


def test_a_trace_line_over_the_line_limit_fails(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    src = tmp_path / "big.log"
    src.write_bytes((PYTHON[0] + "\n" + PY_FRAME + "x" * 2_000 + "\n").encode("utf-8"))
    runtime = RuntimeSettings(max_record_bytes=1_024)
    with pytest.raises(InputLimitError) as err:
        inspect_file(src, policy_text(MINIMAL_POLICY), DEV, fmt=FMT, runtime=runtime)
    assert err.value.code == "record_too_large"


def test_reports_never_echo_frames_or_values(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    policy = policy_text(_with_rule(REDACT_FRAMES))
    report, out = _sanitize(tmp_path, "\n".join([*PYTHON, *JVM]) + "\n", policy)
    assert report.ok  # type: ignore[attr-defined]
    dumped = json.dumps(report.to_dict())  # type: ignore[attr-defined]
    output = out.read_text(encoding="utf-8")
    for raw in ("handlers.py", "load(email)", "Invoice.java", "alice.test@example.com"):
        assert raw not in dumped
        assert raw not in output


# ----------------------------------------------------------------------------- property

_POOL = st.sampled_from(
    [
        *PYTHON,
        *JVM,
        *NODE,
        "2026-01-05 INFO mail alice.test@example.com",
        "    indented alice.test@example.com",
        "  at x (" + SYNTHETIC_SECRETS[2] + ")",
        "\tat a.B.c(B.java:1) 192.0.2.10",
        "",
    ]
)


@given(st.lists(_POOL, min_size=1, max_size=8))
@settings(
    max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_stacktrace_never_finds_less_than_text(
    tmp_path_factory: pytest.TempPathFactory,
    policy_text: Callable[[str], Policy],
    lines: list[str],
) -> None:
    policy = policy_text(_with_rule(REDACT_FRAMES))
    tmp = tmp_path_factory.mktemp("st")
    text = "\n".join(lines) + "\n"

    def covered(items: list[dict[str, object]]) -> dict[tuple[object, object], set[int]]:
        out: dict[tuple[object, object], set[int]] = {}
        for i in items:
            loc = i["location"]
            assert isinstance(loc, dict)
            span = loc.get("span") or (0, 0)
            out.setdefault((i["category"], loc["line"]), set()).update(range(*span))
        return out

    as_text = covered(_items(tmp, text, policy, InputFormat.TEXT))
    as_trace = covered(_items(tmp, text, policy))
    for key, chars in as_text.items():
        assert chars <= as_trace.get(key, set()), key

    report, out = _sanitize(tmp, text, policy)
    if report.ok:  # type: ignore[attr-defined]
        written = out.read_text(encoding="utf-8")
        assert written.count("\n") == text.count("\n")
        assert "alice.test@example.com" not in written
