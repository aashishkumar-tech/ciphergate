"""Format adapter contracts shared by all readers/writers."""

from __future__ import annotations

import codecs
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Protocol

from ciphergate.config import RuntimeSettings
from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError, InputLimitError, UsageError
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import PolicySettings

# Readers split lines on bytes, so only ASCII-compatible encodings are supported.
SUPPORTED_ENCODINGS = frozenset({"utf-8", "utf-8-sig", "ascii", "latin-1", "cp1252"})


def normalize_encoding(name: str) -> str:
    try:
        canonical = codecs.lookup(name).name
    except LookupError:
        raise UsageError("unknown encoding", code="unsupported_encoding") from None
    aliases = {
        "utf-8": "utf-8",
        "utf-8-sig": "utf-8-sig",
        "ascii": "ascii",
        "iso8859-1": "latin-1",
        "latin-1": "latin-1",
        "cp1252": "cp1252",
    }
    if canonical not in aliases:
        raise UsageError(
            "unsupported encoding; supported: " + ", ".join(sorted(SUPPORTED_ENCODINGS)),
            code="unsupported_encoding",
        )
    return aliases[canonical]


@dataclass(slots=True)
class Record:
    index: int
    line: int | None
    data: Any
    line_ending: str = ""
    malformed: bool = False
    error_code: str | None = None


@dataclass(slots=True)
class ReadStats:
    bytes_read: int = 0
    records: int = 0
    blank_lines: int = 0
    parse_errors: list[tuple[int | None, str]] = field(default_factory=list)


class Reader(Protocol):
    format: InputFormat
    stats: ReadStats

    def records(self) -> Iterator[Record]: ...

    def iter_items(self, record: Record) -> Iterator[ScanItem]: ...


class Writer(Protocol):
    def write_record(self, record: Record, data: Any) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ReaderOptions:
    runtime: RuntimeSettings
    policy_settings: PolicySettings
    encoding: str = "utf-8"


def read_bounded_lines(
    stream: IO[bytes], options: ReaderOptions, stats: ReadStats
) -> Iterator[tuple[int, bytes]]:
    """Yield (line_number, raw line bytes incl. terminator) enforcing per-line and total limits."""
    max_line = options.runtime.max_record_bytes
    line_no = 0
    while True:
        raw = stream.readline(max_line + 2)
        if not raw:
            return
        line_no += 1
        stats.bytes_read += len(raw)
        if stats.bytes_read > options.runtime.max_input_bytes:
            raise InputLimitError("input exceeds max_input_bytes", code="size_limit_exceeded")
        content_len = len(raw.rstrip(b"\r\n"))
        if content_len > max_line:
            raise InputLimitError(
                f"line {line_no} exceeds max_record_bytes ({max_line})", code="record_too_large"
            )
        yield line_no, raw


def split_line_ending(text: str) -> tuple[str, str]:
    if text.endswith("\r\n"):
        return text[:-2], "\r\n"
    if text.endswith("\n") or text.endswith("\r"):
        return text[:-1], text[-1]
    return text, ""


def decode_line(raw: bytes, encoding: str, line_no: int, *, first: bool) -> str:
    if first and raw.startswith(codecs.BOM_UTF8) and encoding.startswith("utf-8"):
        raw = raw[len(codecs.BOM_UTF8) :]
    try:
        return raw.decode(encoding.replace("-sig", ""))
    except UnicodeDecodeError:
        raise InputFormatError(
            f"line {line_no} is not valid {encoding}", code="decode_error"
        ) from None


def has_utf8_bom(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(3) == codecs.BOM_UTF8


def detect_newline(path: Path) -> str:
    with path.open("rb") as fh:
        chunk = fh.read(64 * 1024)
    return "\r\n" if b"\r\n" in chunk else "\n"
