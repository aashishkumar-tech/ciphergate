"""Python API for streams and directories (#38): same fail-closed contract as the CLI."""

from __future__ import annotations

import io
import json
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

import ciphergate
from ciphergate import (
    BatchReport,
    ContextInput,
    InputFormat,
    RuntimeSettings,
    SanitizeOptions,
    inspect_directory,
    inspect_file,
    inspect_stream,
    load_policy,
    plan_directory,
    plan_stream,
    rescan_directory,
    rescan_stream,
    sanitize_directory,
    sanitize_file,
    sanitize_stream,
)
from ciphergate.errors import (
    InputLimitError,
    OutputWriteError,
    UnsafePathError,
    UsageError,
)
from ciphergate.pipeline.paths import file_digest
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import EXAMPLES, POLICIES, SYNTHETIC_SECRETS

POLICY = load_policy(POLICIES / "prd_external_ai.yml")
CTX = ContextInput(environment="prd", target_environment="external", destination="external_ai")
SECRET_LINE = b"login failed password=TEST_ONLY_NOT_A_CREDENTIAL\n"
LEAKS = [*SYNTHETIC_SECRETS, "alice.test"]
CSV = (EXAMPLES / "sample.csv").read_bytes()


@pytest.fixture
def options(keys: KeyProvider) -> SanitizeOptions:
    return SanitizeOptions(apply=True, keys=keys, format=InputFormat.CSV)


@pytest.fixture(autouse=True)
def private_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point tempfile at a private dir so a leftover spool workspace is detected."""
    temp = tmp_path / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    yield temp
    assert not any(temp.iterdir()), "stream workspace was not cleaned up"


def _no_leaks(*blobs: str | bytes) -> None:
    for blob in blobs:
        text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        for secret in LEAKS:
            assert secret not in text


def _report_text(report: object) -> str:
    return json.dumps(report.to_dict())  # type: ignore[attr-defined]


def test_public_exports() -> None:
    for name in (
        "BatchReport", "inspect_stream", "plan_stream", "rescan_stream", "sanitize_stream",
        "inspect_directory", "plan_directory", "rescan_directory", "sanitize_directory",
    ):  # fmt: skip
        assert name in ciphergate.__all__ and hasattr(ciphergate, name)


# --------------------------------------------------------------------------- streams


def test_inspect_and_plan_stream_match_file_runs(keys: KeyProvider) -> None:
    from_file = inspect_file(EXAMPLES / "sample.csv", POLICY, CTX, keys=keys)
    report = inspect_stream(io.BytesIO(CSV), POLICY, CTX, fmt=InputFormat.CSV, keys=keys)
    assert report.summary == from_file.summary and report.status == from_file.status
    assert report.input["path"] == "<stream>"
    plan = plan_stream(io.BytesIO(CSV), POLICY, CTX, fmt=InputFormat.CSV, keys=keys)
    assert plan.command == "plan" and plan.output["written"] is False
    _no_leaks(_report_text(report), _report_text(plan))


def test_sanitize_stream_matches_sanitize_file(tmp_path: Path, options: SanitizeOptions) -> None:
    out = io.BytesIO()
    report = sanitize_stream(io.BytesIO(CSV), out, POLICY, CTX, options)
    assert report.ok and report.output == {"written": True, "path": "<stream>"}
    target = tmp_path / "file.csv"
    file_report = sanitize_file(
        EXAMPLES / "sample.csv", target, POLICY, CTX,
        SanitizeOptions(apply=True, keys=options.keys),
    )  # fmt: skip
    assert file_report.ok
    assert out.getvalue() == target.read_bytes()
    _no_leaks(out.getvalue(), _report_text(report))
    residual = rescan_stream(io.BytesIO(out.getvalue()), POLICY, CTX, fmt=InputFormat.CSV)
    assert residual.ok and residual.input["path"] == "<stream>"


def test_blocked_stream_writes_nothing(keys: KeyProvider) -> None:
    out = io.BytesIO()
    opts = SanitizeOptions(apply=True, keys=keys, format=InputFormat.TEXT)
    report = sanitize_stream(io.BytesIO(SECRET_LINE), out, POLICY, CTX, opts)
    assert report.exit_code == 1 and not report.output["written"]
    assert out.getvalue() == b""
    _no_leaks(_report_text(report))


def test_missing_key_writes_nothing() -> None:
    out = io.BytesIO()
    opts = SanitizeOptions(apply=True, keys=KeyProvider({}), format=InputFormat.CSV)
    report = sanitize_stream(io.BytesIO(CSV), out, POLICY, CTX, opts)
    assert report.exit_code == 6 and out.getvalue() == b""


def test_dry_run_writes_nothing(keys: KeyProvider) -> None:
    out = io.BytesIO()
    opts = SanitizeOptions(apply=False, keys=keys, format=InputFormat.CSV)
    report = sanitize_stream(io.BytesIO(CSV), out, POLICY, CTX, opts)
    assert report.output["withheld_reason"] == "apply_not_set" and out.getvalue() == b""


def test_stream_argument_errors(keys: KeyProvider) -> None:
    with pytest.raises(UsageError) as exc:
        inspect_stream(io.BytesIO(CSV), POLICY, CTX, fmt=None)  # type: ignore[arg-type]
    assert exc.value.code == "format_required"
    with pytest.raises(UsageError) as exc:
        sanitize_stream(io.BytesIO(CSV), io.BytesIO(), POLICY, CTX, SanitizeOptions(keys=keys))
    assert exc.value.code == "format_required"
    with pytest.raises(UsageError) as exc:
        inspect_stream(io.StringIO("a,b\n"), POLICY, CTX, fmt=InputFormat.CSV)  # type: ignore[arg-type]
    assert exc.value.code == "stream_not_binary"
    opts = SanitizeOptions(apply=True, keys=keys, format=InputFormat.CSV)
    with pytest.raises(UsageError) as exc:
        sanitize_stream(io.BytesIO(CSV), io.StringIO(), POLICY, CTX, opts)  # type: ignore[arg-type]
    assert exc.value.code == "stream_not_binary"


def test_stream_size_limit_never_truncates() -> None:
    with pytest.raises(InputLimitError) as exc:
        inspect_stream(
            io.BytesIO(CSV), POLICY, CTX, fmt=InputFormat.CSV,
            runtime=RuntimeSettings(max_input_bytes=16),
        )  # fmt: skip
    assert exc.value.code == "size_limit_exceeded"


def test_output_write_failure_is_reported(options: SanitizeOptions) -> None:
    class Broken(io.BytesIO):
        def write(self, data: object) -> int:  # type: ignore[override]
            raise OSError("disk full")

    with pytest.raises(OutputWriteError) as exc:
        sanitize_stream(io.BytesIO(CSV), Broken(), POLICY, CTX, options)
    assert exc.value.code == "stream_write_failed" and "incomplete" in exc.value.message


# --------------------------------------------------------------------------- directories


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "in"
    (root / "sub").mkdir(parents=True)
    (root / "a.csv").write_bytes(CSV)
    (root / "sub" / "b.jsonl").write_bytes((EXAMPLES / "sample.jsonl").read_bytes())
    return root


def _digests(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): file_digest(p) for p in root.rglob("*") if p.is_file()}


def test_directory_analysis_is_read_only(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    before = _digests(root)
    for fn in (inspect_directory, plan_directory, rescan_directory):
        report = fn(str(root), POLICY, CTX, recursive=True)
        assert isinstance(report, BatchReport)
        assert [f.display for f in report.files] == ["a.csv", "sub/b.jsonl"]
        _no_leaks(_report_text(report))
    flat = inspect_directory(root, POLICY, CTX)
    assert [f.display for f in flat.files] == ["a.csv"]
    assert _digests(root) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in", "tmp"]


def test_sanitize_directory_defaults_and_publish(tmp_path: Path, keys: KeyProvider) -> None:
    root = _tree(tmp_path)
    out = tmp_path / "out"
    # options=None means apply=True (as in sanitize_file); without a key nothing is published.
    keyless = sanitize_directory(root, out, POLICY, CTX, recursive=True)
    assert keyless.output["withheld_reason"] == "file_failed" and not out.exists()
    dry = sanitize_directory(
        root, out, POLICY, CTX, SanitizeOptions(apply=False, keys=keys), recursive=True
    )
    assert dry.output["withheld_reason"] == "apply_not_set" and not out.exists()
    report = sanitize_directory(
        root, out, POLICY, CTX, SanitizeOptions(apply=True, keys=keys), recursive=True
    )
    assert report.exit_code == 0 and report.output == {"written": True, "path": "out"}
    assert (out / "sub" / "b.jsonl").is_file()
    _no_leaks(_report_text(report), (out / "a.csv").read_bytes())


def test_sanitize_directory_fails_closed(tmp_path: Path, keys: KeyProvider) -> None:
    root = _tree(tmp_path)
    (root / "z.log").write_bytes(SECRET_LINE)
    out = tmp_path / "out"
    report = sanitize_directory(root, out, POLICY, CTX, SanitizeOptions(apply=True, keys=keys))
    assert report.exit_code == 1 and not out.exists()
    assert report.output["withheld_reason"] == "file_failed"
    missing_key = sanitize_directory(
        root, out, POLICY, CTX, SanitizeOptions(apply=True, keys=KeyProvider({}))
    )
    assert missing_key.exit_code == 6 and not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in", "tmp"]


def test_sanitize_directory_path_rules(tmp_path: Path, keys: KeyProvider) -> None:
    root = _tree(tmp_path)
    with pytest.raises(UsageError) as exc:
        sanitize_directory(root, tmp_path / "out", POLICY, CTX, SanitizeOptions(force=True))
    assert exc.value.code == "force_unsupported_for_directory"
    with pytest.raises(UnsafePathError) as exc2:
        sanitize_directory(root, root / "out", POLICY, CTX, SanitizeOptions(keys=keys))
    assert exc2.value.code == "output_inside_input"
    (tmp_path / "exists").mkdir()
    with pytest.raises(OutputWriteError) as exc3:
        sanitize_directory(root, tmp_path / "exists", POLICY, CTX, SanitizeOptions(keys=keys))
    assert exc3.value.code == "output_exists"
