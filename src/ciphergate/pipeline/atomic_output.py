"""Atomic, no-overwrite-by-default output publishing.

Contract:

1. A temp file is created with ``mkstemp`` in the destination directory (same filesystem; owner-only
   ``0600`` permissions on POSIX; on Windows the file inherits the directory ACL).
2. Content is written, flushed and ``fsync``-ed, then the temp file is closed.
3. Only after every check passes, ``publish()`` moves it into place:
   * without ``force``: ``os.link`` + unlink on POSIX (fails if the target appeared meanwhile),
     ``os.rename`` on Windows (fails if the target exists) — never replaces an existing file;
   * with ``force``: ``os.replace`` (atomic replacement; the previous file stays intact until then).
4. On any exception, ``KeyboardInterrupt`` or ``abort()``, the temp file is removed. If removal
   fails, a warning naming the temp path is logged to stderr (the name is CipherGate-generated and
   contains no data) and ``cleanup_failed_path`` is set.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from pathlib import Path
from types import TracebackType
from typing import IO

from ciphergate.errors import OutputWriteError
from ciphergate.reporting.safe_text import escape_control

logger = logging.getLogger("ciphergate")


class AtomicOutput:
    def __init__(self, final_path: Path, *, force: bool, encoding: str = "utf-8") -> None:
        self.final_path = final_path
        self.force = force
        self.encoding = encoding
        self.temp_path: Path | None = None
        self._stream: IO[str] | None = None
        self.published = False
        self.cleanup_failed_path: Path | None = None

    def __enter__(self) -> AtomicOutput:
        parent = self.final_path.parent if str(self.final_path.parent) else Path(".")
        try:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, name = tempfile.mkstemp(prefix=".ciphergate-", suffix=".tmp", dir=parent)
        except OSError:
            raise OutputWriteError(
                "cannot create a temporary output file in the destination directory",
                code="output_temp_failed",
            ) from None
        self.temp_path = Path(name)
        with contextlib.suppress(OSError):
            os.chmod(name, 0o600)
        self._stream = os.fdopen(fd, "w", encoding=self.encoding, newline="", errors="strict")
        return self

    @property
    def stream(self) -> IO[str]:
        if self._stream is None:
            raise OutputWriteError("output stream is not open", code="output_closed")
        return self._stream

    def finish_writing(self) -> None:
        """Flush, fsync and close the temp file (content complete, not yet published)."""
        if self._stream is None:
            return
        try:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
        except UnicodeEncodeError:
            raise OutputWriteError(
                "output contains characters not representable in the output encoding",
                code="output_encoding",
            ) from None
        except OSError:
            raise OutputWriteError(
                "failed to flush output to disk", code="output_flush_failed"
            ) from None
        finally:
            self._stream = None

    def publish(self) -> None:
        self.finish_writing()
        if self.temp_path is None:
            raise OutputWriteError("output was never opened", code="output_closed")
        try:
            if self.force:
                os.replace(self.temp_path, self.final_path)
            elif os.name == "nt":
                os.rename(self.temp_path, self.final_path)
            else:
                os.link(self.temp_path, self.final_path)
                os.unlink(self.temp_path)
        except FileExistsError:
            raise OutputWriteError(
                "output file appeared while processing; not replaced (use --force)",
                code="output_exists",
            ) from None
        except OSError:
            raise OutputWriteError(
                "failed to publish output atomically", code="output_publish_failed"
            ) from None
        self.published = True
        if os.name != "nt":
            with contextlib.suppress(OSError):
                dir_fd = os.open(self.final_path.parent or Path("."), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)

    def abort(self) -> None:
        if self._stream is not None:
            with contextlib.suppress(OSError, ValueError, UnicodeEncodeError):
                self._stream.close()
            self._stream = None
        if self.temp_path is not None and not self.published:
            try:
                if self.temp_path.exists():
                    self.temp_path.unlink()
            except OSError:
                self.cleanup_failed_path = self.temp_path
                logger.warning(
                    "could not remove temporary output file %s; delete it manually",
                    escape_control(str(self.temp_path)),
                )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self.published:
            self.abort()
        if exc_type is not None and issubclass(exc_type, UnicodeEncodeError):
            raise OutputWriteError(
                "output contains characters not representable in the output encoding",
                code="output_encoding",
            ) from None
