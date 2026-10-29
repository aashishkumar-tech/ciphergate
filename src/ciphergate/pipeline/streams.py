"""Binary-stream variants of the single-file operations (Python API counterpart of CLI ``-``).

The pipeline reads its input twice and checks it did not change, so a stream is first spooled
into a private workspace (``StdioWorkspace``: owner-only on POSIX), capped at
``max_input_bytes`` while reading. ``sanitize_stream`` sanitizes into the same workspace and
copies to ``output`` only after every check passed; a blocked, review or failed run writes
nothing to it. The workspace is removed on success, failure and interruption.

Streams must be binary (``open(..., "rb")``, ``io.BytesIO``); the format is always required
because there is no file name to infer it from. Reports show ``<stream>`` as the path.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import IO

from ciphergate.config import RuntimeSettings
from ciphergate.constants import InputFormat
from ciphergate.errors import OutputWriteError, UsageError
from ciphergate.models.context import ContextInput
from ciphergate.models.report import RunReport
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.pipeline.stdio import StdioWorkspace
from ciphergate.policy.validator import Policy
from ciphergate.transforms.keys import KeyProvider

STREAM_DISPLAY = "<stream>"
_CHUNK = 1024 * 1024


def _require_format(fmt: InputFormat | None) -> InputFormat:
    if fmt is None:
        raise UsageError("a stream needs an explicit format", code="format_required")
    return InputFormat(fmt)


def _spool(
    ws: StdioWorkspace, stream: IO[bytes], fmt: InputFormat, runtime: RuntimeSettings
) -> Path:
    return ws.spool_input(stream, fmt, runtime.max_input_bytes, label="input stream")


def inspect_stream(
    stream: IO[bytes],
    policy: Policy,
    context: ContextInput | None = None,
    *,
    fmt: InputFormat,
    runtime: RuntimeSettings | None = None,
    keys: KeyProvider | None = None,
) -> RunReport:
    """Detect and evaluate data read from a binary stream; writes no data anywhere."""
    fmt, runtime = _require_format(fmt), runtime or RuntimeSettings()
    with StdioWorkspace() as ws:
        report = inspect_file(_spool(ws, stream, fmt, runtime), policy, context,
                              runtime=runtime, fmt=fmt, keys=keys)  # fmt: skip
    report.input["path"] = STREAM_DISPLAY
    return report


def plan_stream(
    stream: IO[bytes],
    policy: Policy,
    context: ContextInput | None = None,
    *,
    fmt: InputFormat,
    runtime: RuntimeSettings | None = None,
    keys: KeyProvider | None = None,
) -> RunReport:
    """Preview the decisions ``sanitize_stream`` would make; writes no data anywhere."""
    fmt, runtime = _require_format(fmt), runtime or RuntimeSettings()
    with StdioWorkspace() as ws:
        report = plan_file(_spool(ws, stream, fmt, runtime), policy, context,
                           runtime=runtime, fmt=fmt, keys=keys)  # fmt: skip
    report.input["path"] = STREAM_DISPLAY
    return report


def rescan_stream(
    stream: IO[bytes],
    policy: Policy,
    context: ContextInput | None = None,
    *,
    fmt: InputFormat,
    strict: bool | None = None,
    runtime: RuntimeSettings | None = None,
) -> RunReport:
    """Report residual findings in (sanitized) data read from a binary stream. Read-only."""
    fmt, runtime = _require_format(fmt), runtime or RuntimeSettings()
    with StdioWorkspace() as ws:
        report = rescan_file(_spool(ws, stream, fmt, runtime), policy, context,
                             strict=strict, runtime=runtime, fmt=fmt)  # fmt: skip
    report.input["path"] = STREAM_DISPLAY
    return report


def sanitize_stream(
    stream: IO[bytes],
    output: IO[bytes],
    policy: Policy,
    context: ContextInput | None = None,
    options: SanitizeOptions | None = None,
) -> RunReport:
    """Sanitize a binary stream into ``output``; ``output`` is written only if the run succeeded.

    ``options.format`` is required. Without ``options.apply`` this is a plan and nothing is
    written. If copying to ``output`` fails part-way, ``OutputWriteError`` says so explicitly:
    ``output`` may then hold an incomplete (but sanitized) prefix.
    """
    options = options or SanitizeOptions()
    fmt = _require_format(options.format)
    runtime = options.runtime or RuntimeSettings()
    run_options = SanitizeOptions(
        apply=options.apply, force=False, keys=options.keys, format=fmt, runtime=runtime
    )
    with StdioWorkspace() as ws:
        staged = ws.output_path()
        report = sanitize_file(_spool(ws, stream, fmt, runtime), staged, policy, context,
                               run_options)  # fmt: skip
        report.input["path"] = STREAM_DISPLAY
        report.output["path"] = STREAM_DISPLAY
        if report.output.get("written"):
            _copy(staged, output)
    return report


def _copy(path: Path, output: IO[bytes]) -> None:
    try:
        with path.open("rb") as fh:
            shutil.copyfileobj(fh, output, _CHUNK)
        output.flush()
    except KeyboardInterrupt:
        raise OutputWriteError(
            "interrupted while writing the output stream; it may be incomplete",
            code="stream_interrupted",
        ) from None
    except TypeError:
        raise UsageError(
            "output must be a binary stream (open it with 'wb')", code="stream_not_binary"
        ) from None
    except OSError:
        raise OutputWriteError(
            "failed to write the output stream; it may be incomplete", code="stream_write_failed"
        ) from None
