"""Format adapters (readers + writers) for CSV, JSON, JSONL/NDJSON, text/log and logfmt."""

from __future__ import annotations

from pathlib import Path
from typing import IO

from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError, UsageError
from ciphergate.readers.base import Reader, ReaderOptions, Record, Writer
from ciphergate.readers.csv_reader import CSVReader, CSVWriter
from ciphergate.readers.json_reader import JSONReader, JSONWriter
from ciphergate.readers.jsonl_reader import JSONLReader, JSONLWriter
from ciphergate.readers.logfmt_reader import LogfmtReader
from ciphergate.readers.text_reader import TextReader, TextWriter

EXTENSION_FORMATS: dict[str, InputFormat] = {
    ".csv": InputFormat.CSV,
    ".json": InputFormat.JSON,
    ".jsonl": InputFormat.JSONL,
    ".ndjson": InputFormat.JSONL,
    ".txt": InputFormat.TEXT,
    ".log": InputFormat.TEXT,
}

_JSON_PREFIXES = (
    b"{",
    b"[",
    b'"',
    b"-",
    b"true",
    b"false",
    b"null",
    *(bytes([d]) for d in b"0123456789"),
)


def detect_format(path: Path, explicit: InputFormat | None = None) -> InputFormat:
    """Explicit ``--format`` wins; else use the extension, refusing contradicting content."""
    if explicit is not None:
        return explicit
    fmt = EXTENSION_FORMATS.get(path.suffix.lower())
    if fmt is None:
        raise UsageError(
            "cannot infer the input format from this file extension; pass --format "
            "csv|json|jsonl|text",
            code="format_required",
        )
    if fmt in (InputFormat.JSON, InputFormat.JSONL):
        with path.open("rb") as fh:
            head = fh.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        if head and not head.startswith(_JSON_PREFIXES):
            raise InputFormatError(
                "file content does not look like JSON despite its extension; pass --format",
                code="format_mismatch",
            )
    return fmt


def open_reader(path: Path, fmt: InputFormat, options: ReaderOptions) -> Reader:
    if fmt == InputFormat.CSV:
        return CSVReader(path, options)
    if fmt == InputFormat.JSON:
        return JSONReader(path, options)
    if fmt == InputFormat.JSONL:
        return JSONLReader(path, options)
    if fmt == InputFormat.LOGFMT:
        return LogfmtReader(path, options)
    return TextReader(path, options)


def make_writer(stream: IO[str], reader: Reader, dropped_columns: set[int]) -> Writer:
    if isinstance(reader, CSVReader):
        return CSVWriter(stream, reader, dropped_columns)
    if isinstance(reader, JSONReader):
        return JSONWriter(stream, reader)
    if isinstance(reader, JSONLReader):
        return JSONLWriter(stream)
    if isinstance(reader, TextReader):
        return TextWriter(stream, reader)
    raise TypeError("unsupported reader")


__all__ = [
    "EXTENSION_FORMATS",
    "Reader",
    "ReaderOptions",
    "Record",
    "Writer",
    "detect_format",
    "make_writer",
    "open_reader",
]
