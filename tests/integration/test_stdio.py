"""stdin/stdout streaming (#8): real pipes, output/report separation, fail-closed and cleanup."""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate.constants import InputFormat
from ciphergate.errors import InputLimitError, OutputWriteError, UsageError
from ciphergate.pipeline import stdio
from ciphergate.pipeline.stdio import StdioWorkspace, copy_to_stdout, require_stdin_format
from tests.conftest import EXAMPLES, POLICIES, SYNTHETIC_SECRETS

PRD_EXTERNAL = [
    "--policy",
    str(POLICIES / "prd_external_ai.yml"),
    "--environment",
    "prd",
    "--target-environment",
    "external",
    "--destination",
    "external_ai",
]
DEV_LOCAL = [
    "--policy",
    str(POLICIES / "developer_logs.yml"),
    "--environment",
    "dev",
    "--destination",
    "local_dev",
]
SECRET_LINE = b"login failed password=TEST_ONLY_NOT_A_CREDENTIAL user=alice.test@example.com\n"
LEAKS = [s.encode() for s in [*SYNTHETIC_SECRETS, "alice.test"]]

Run = Callable[..., subprocess.CompletedProcess[bytes]]


@pytest.fixture
def run(tmp_path: Path, hmac_key: str) -> Run:
    """Run the real CLI with a private temp dir, so a leftover stdio workspace is visible."""
    temp = tmp_path / "tmp"
    temp.mkdir()
    env = {
        **os.environ,
        "PYTHONIOENCODING": "utf-8",
        "CIPHERGATE_HMAC_KEY": hmac_key,
        "TMPDIR": str(temp),
        "TEMP": str(temp),
        "TMP": str(temp),
    }

    def _run(*args: str | Path, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [sys.executable, "-m", "ciphergate", *(str(a) for a in args)],
            input=stdin,
            capture_output=True,
            timeout=120,
            env=env,
            check=False,
        )
        assert not any(temp.iterdir()), "stdio workspace was not cleaned up"
        return result

    return _run


def _no_leaks(*blobs: bytes) -> None:
    for secret in LEAKS:
        for blob in blobs:
            assert secret not in blob


def test_stdin_to_stdout_matches_file_to_file(run: Run, tmp_path: Path) -> None:
    src = EXAMPLES / "sample.csv"
    out = tmp_path / "file.csv"
    assert run("sanitize", src, *PRD_EXTERNAL, "-o", out, "--apply", "-q").returncode == 0
    piped = run(
        "sanitize", "-", "--format", "csv", *PRD_EXTERNAL, "-o", "-", "--apply",
        stdin=src.read_bytes(),
    )  # fmt: skip
    assert piped.returncode == 0
    assert piped.stdout == out.read_bytes()  # stdout carries the data and nothing else
    assert b"SANITIZED" in piped.stderr and b"<stdin>" in piped.stderr
    _no_leaks(piped.stdout, piped.stderr)


def test_file_to_stdout_with_report(run: Run, tmp_path: Path) -> None:
    src = EXAMPLES / "sample.csv"
    ref = tmp_path / "ref.csv"
    assert run("sanitize", src, *DEV_LOCAL, "-o", ref, "--apply", "-q").returncode == 0
    r = run("sanitize", src, *DEV_LOCAL, "-o", "-", "--apply", "--report", tmp_path / "r.json")
    assert r.returncode == 0 and r.stdout == ref.read_bytes()
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["output"] == {"written": True, "path": "<stdout>"}


def test_stdin_to_file(run: Run, tmp_path: Path) -> None:
    src = EXAMPLES / "sample.csv"
    ref, out = tmp_path / "ref.csv", tmp_path / "out.csv"
    assert run("sanitize", src, *DEV_LOCAL, "-o", ref, "--apply", "-q").returncode == 0
    r = run(
        "sanitize", "-", "--format", "csv", *DEV_LOCAL, "-o", out, "--apply", "-q",
        stdin=src.read_bytes(),
    )  # fmt: skip
    assert r.returncode == 0 and r.stdout == b"" and out.read_bytes() == ref.read_bytes()


def test_blocked_run_writes_nothing_to_stdout(run: Run) -> None:
    r = run(
        "sanitize", "-", "--format", "text", *PRD_EXTERNAL, "-o", "-", "--apply",
        stdin=SECRET_LINE,
    )  # fmt: skip
    assert r.returncode == 1 and r.stdout == b""
    _no_leaks(r.stderr)


def test_dry_run_to_stdout_writes_no_data(run: Run) -> None:
    r = run("sanitize", EXAMPLES / "sample.csv", *DEV_LOCAL, "-o", "-")
    assert r.returncode == 0 and r.stdout == b"" and b"dry run" in r.stderr


@pytest.mark.parametrize("command", ["inspect", "plan", "rescan"])
def test_analysis_commands_read_stdin(run: Run, command: str) -> None:
    data = (EXAMPLES / "sample.jsonl").read_bytes()
    r = run(command, "-", "--format", "jsonl", *DEV_LOCAL, "--report-format", "json", stdin=data)
    report = json.loads(r.stdout)
    assert report["input"]["path"] == "<stdin>" and report["input"]["format"] == "jsonl"
    assert report["input"]["bytes"] == len(data)
    _no_leaks(r.stdout, r.stderr)


def test_stdin_plan_matches_file_plan(run: Run) -> None:
    src = EXAMPLES / "sample.log"
    from_file = json.loads(run("plan", src, *DEV_LOCAL, "--report-format", "json").stdout)
    piped = run(
        "plan", "-", "--format", "text", *DEV_LOCAL, "--report-format", "json",
        stdin=src.read_bytes(),
    )  # fmt: skip
    from_pipe = json.loads(piped.stdout)
    assert from_pipe["summary"] == from_file["summary"]
    assert from_pipe["status"] == from_file["status"]


@pytest.mark.parametrize(
    ("args", "code", "error"),
    [
        (["inspect", "-", *DEV_LOCAL], 2, b"format_required"),
        (
            ["inspect", "-", "--format", "csv", "--report", "-", *DEV_LOCAL],
            2,
            b"report_stdout_unsupported",
        ),
        (
            ["sanitize", "-", "--format", "csv", "-o", "-", "--apply", "--report-format", "json",
             *DEV_LOCAL],
            2,
            b"stdout_conflict",
        ),
        (
            ["inspect", "-", "--format", "text", "--max-bytes", "100", *DEV_LOCAL],
            4,
            b"size_limit_exceeded",
        ),
    ],
)  # fmt: skip
def test_stdio_usage_errors_and_limits(run: Run, args: list[str], code: int, error: bytes) -> None:
    r = run(*args, stdin=b"a,b\n" + b"x" * 500 + b"\n")
    assert r.returncode == code and error in r.stderr and r.stdout == b""


def test_stdin_decode_error_fails_closed(run: Run) -> None:
    r = run(
        "sanitize", "-", "--format", "text", *DEV_LOCAL, "-o", "-", "--apply",
        stdin=b"ok\n\xff\xfe broken\n",
    )  # fmt: skip
    assert r.returncode == 4 and r.stdout == b"" and b"decode_error" in r.stderr


def test_broken_pipe_is_an_output_error(tmp_path: Path, hmac_key: str) -> None:
    big = tmp_path / "big.csv"
    # Output must exceed the OS pipe buffer (64 KiB) so the writer is still writing when the
    # reader closes; few long rows keep the run fast.
    big.write_text("a,b\n" + f"{'x' * 900},{'y' * 900}\n" * 1_000, encoding="utf-8")
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "CIPHERGATE_HMAC_KEY": hmac_key}
    cmd = [sys.executable, "-m", "ciphergate", "sanitize", str(big), *DEV_LOCAL]
    proc = subprocess.Popen(
        [*cmd, "-o", "-", "--apply", "-q"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.read(16)
    proc.stdout.close()  # the reader goes away mid-stream
    err = proc.stderr.read()
    assert proc.wait(timeout=120) == 5
    assert b"stdout_broken_pipe" in err and b"Traceback" not in err and b"Exception" not in err


# ----------------------------------------------------------------------------- unit level


class _Stream(io.BytesIO):
    def __init__(self, data: bytes = b"", tty: bool = False) -> None:
        super().__init__(data)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_require_stdin_format() -> None:
    with pytest.raises(UsageError) as exc:
        require_stdin_format(None, _Stream())
    assert exc.value.code == "format_required"
    with pytest.raises(UsageError) as exc:
        require_stdin_format(InputFormat.CSV, _Stream(tty=True))
    assert exc.value.code == "stdin_is_terminal"
    assert require_stdin_format(InputFormat.TEXT, _Stream()) == InputFormat.TEXT


def test_workspace_removed_on_limit_and_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stdio.tempfile, "tempdir", str(tmp_path))
    with pytest.raises(InputLimitError), StdioWorkspace() as ws:
        ws.spool_input(_Stream(b"x" * 20), InputFormat.TEXT, max_bytes=10)
    with pytest.raises(KeyboardInterrupt), StdioWorkspace() as ws:
        ws.spool_input(_Stream(b"data\n"), InputFormat.TEXT, max_bytes=10)
        raise KeyboardInterrupt
    assert not any(tmp_path.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_workspace_is_owner_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stdio.tempfile, "tempdir", str(tmp_path))
    with StdioWorkspace() as ws:
        spooled = ws.spool_input(_Stream(b"a\n"), InputFormat.TEXT, max_bytes=10)
        assert ws.root is not None
        assert stat.S_IMODE(ws.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(spooled.stat().st_mode) == 0o600
        assert spooled.read_bytes() == b"a\n"


def test_copy_to_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    silenced: list[bool] = []
    monkeypatch.setattr(stdio, "silence_stdout", lambda: silenced.append(True))
    staged = tmp_path / "s.out"
    staged.write_bytes(b"data")

    class Closed(io.BytesIO):
        def write(self, b: object, /) -> int:
            raise BrokenPipeError

    with pytest.raises(OutputWriteError) as exc:
        copy_to_stdout(staged, Closed())
    assert exc.value.code == "stdout_broken_pipe" and silenced
    sink = io.BytesIO()
    copy_to_stdout(staged, sink)
    assert sink.getvalue() == b"data"

    class Interrupted(io.BytesIO):
        def write(self, b: object, /) -> int:
            raise KeyboardInterrupt

    # Data may already be downstream: never reported as the generic "nothing published".
    with pytest.raises(OutputWriteError) as exc:
        copy_to_stdout(staged, Interrupted())
    assert exc.value.code == "stdout_interrupted" and "incomplete" in exc.value.message


# ----------------------------------------------------------------------------- in-process CLI


def test_cli_in_process_stdin_stdout(key_env: str, tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from ciphergate.cli import app

    runner = CliRunner()
    src = (EXAMPLES / "sample.csv").read_bytes()
    args = ["sanitize", "-", "--format", "csv", *DEV_LOCAL, "-o", "-", "--apply"]
    r = runner.invoke(app, [*args, "--report", str(tmp_path / "r.json")], input=src)
    assert r.exit_code == 0 and r.stdout_bytes and b"SANITIZED" in r.stderr_bytes
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["input"]["path"] == "<stdin>" and report["output"]["path"] == "<stdout>"
    r = runner.invoke(app, ["sanitize", "-", "--format", "csv", *DEV_LOCAL, "-o", "-"], input=src)
    assert r.exit_code == 0 and r.stdout_bytes == b"" and b"dry run" in r.stderr_bytes
    r = runner.invoke(app, ["inspect", "-", "--format", "csv", *DEV_LOCAL], input=src)
    assert r.exit_code == 0 and b"<stdin>" in r.stdout_bytes
    _no_leaks(r.stdout_bytes, r.stderr_bytes)
