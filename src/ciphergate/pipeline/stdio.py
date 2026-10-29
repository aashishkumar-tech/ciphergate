"""Standard input/output support for the CLI (``-`` as INPUT or ``--output``).

The pipeline reads its input twice (plan, then apply) and verifies it did not change, and it
publishes output only after every check passes. A pipe allows neither, so:

* stdin is spooled into a private workspace (``mkdtemp``: owner-only on POSIX, the user's temp
  directory ACL on Windows) as a ``0600`` file, capped at ``max_input_bytes`` while reading;
* ``--output -`` is sanitized into the same workspace and copied to stdout only after the run
  succeeded, so a blocked, review or failed run writes nothing to stdout;
* the workspace is removed on success, failure and interruption. A hard kill (``SIGKILL``,
  power loss) can leave it behind in the temp directory; the name is ``ciphergate-stdio-*``.

The spool holds raw input for the duration of the run, exactly like the input file would.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
from pathlib import Path
from types import TracebackType
from typing import IO

from ciphergate.constants import InputFormat
from ciphergate.errors import InputLimitError, OutputWriteError, UsageError
from ciphergate.reporting.safe_text import escape_control

logger = logging.getLogger("ciphergate")

STDIO = "-"
STDIN_DISPLAY = "<stdin>"
STDOUT_DISPLAY = "<stdout>"
_CHUNK = 1024 * 1024
_SUFFIX = {
    InputFormat.CSV: ".csv",
    InputFormat.JSON: ".json",
    InputFormat.JSONL: ".jsonl",
    InputFormat.TEXT: ".txt",
    InputFormat.LOGFMT: ".log",
}


def is_stdio(path: Path | None) -> bool:
    return path is not None and str(path) == STDIO


class StdioWorkspace:
    """Private temporary directory holding the stdin spool and the stdout staging file."""

    def __init__(self) -> None:
        self.root: Path | None = None

    def __enter__(self) -> StdioWorkspace:
        try:
            self.root = Path(tempfile.mkdtemp(prefix="ciphergate-stdio-"))
        except OSError:
            raise OutputWriteError(
                "cannot create a private temporary workspace for stdin/stdout",
                code="stdio_workspace_failed",
            ) from None
        with contextlib.suppress(OSError):
            os.chmod(self.root, 0o700)
        return self

    def _dir(self) -> Path:
        if self.root is None:
            raise OutputWriteError("stdio workspace is not open", code="stdio_workspace_failed")
        return self.root

    def spool_input(
        self, stream: IO[bytes], fmt: InputFormat, max_bytes: int, *, label: str = "stdin"
    ) -> Path:
        """Copy ``stream`` into the workspace; fail (never truncate) beyond ``max_bytes``."""
        path = self._dir() / f"input{_SUFFIX[fmt]}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        total = 0
        try:
            with os.fdopen(os.open(path, flags, 0o600), "wb") as out:
                while True:
                    chunk = stream.read(_CHUNK)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes | bytearray | memoryview):
                        raise UsageError(
                            f"{label} must be a binary stream (open it with 'rb')",
                            code="stream_not_binary",
                        )
                    total += len(chunk)
                    if total > max_bytes:
                        raise InputLimitError(
                            f"{label} exceeds max_input_bytes ({max_bytes})",
                            code="size_limit_exceeded",
                        )
                    out.write(chunk)
        except OSError:
            raise OutputWriteError(
                f"cannot spool {label} into the temporary workspace", code="stdin_spool_failed"
            ) from None
        return path

    def output_path(self) -> Path:
        return self._dir() / "sanitized.out"

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self.root is None:
            return
        shutil.rmtree(self.root, ignore_errors=True)
        if self.root.exists():
            logger.warning(
                "could not remove temporary stdin/stdout workspace %s; delete it manually",
                escape_control(str(self.root)),
            )


def require_stdin_format(fmt: InputFormat | None, stdin: IO[bytes]) -> InputFormat:
    if fmt is None:
        raise UsageError(
            "reading stdin ('-') requires --format csv|json|jsonl|text", code="format_required"
        )
    if stdin.isatty():
        raise UsageError(
            "INPUT is '-' but stdin is a terminal; pipe or redirect the data in",
            code="stdin_is_terminal",
        )
    return fmt


def copy_to_stdout(path: Path, stdout: IO[bytes]) -> None:
    """Write the published staging file to stdout. A closed pipe is an output error.

    Once copying starts, data may already be downstream, so an interruption here must not be
    reported as "no output was published" (the generic Ctrl-C message): it is an output error.
    """
    try:
        with path.open("rb") as fh:
            shutil.copyfileobj(fh, stdout, _CHUNK)
        stdout.flush()
    except KeyboardInterrupt:
        raise OutputWriteError(
            "interrupted while writing to stdout; the output received downstream is incomplete",
            code="stdout_interrupted",
        ) from None
    except BrokenPipeError:
        silence_stdout()
        raise OutputWriteError(
            "stdout was closed before the sanitized output was fully written; "
            "the output received downstream is incomplete",
            code="stdout_broken_pipe",
        ) from None
    except OSError:
        raise OutputWriteError(
            "failed to write the output to stdout", code="stdout_failed"
        ) from None


def silence_stdout() -> None:
    """Point fd 1 at devnull so the interpreter's exit-time flush cannot raise again."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.close(devnull)
