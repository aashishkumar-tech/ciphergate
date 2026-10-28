"""CSV adapter built on the standard ``csv`` module (never naive comma splitting).

* Header row is required. Header cells are scanned like JSON keys (``header_items``, record index
  ``-1``): a label can itself contain data. Duplicate headers are rejected by default; with
  ``csv_duplicate_headers: disambiguate`` they are labelled ``name#2`` internally while the
  original header text is written back unchanged.
* Empty header cells are labelled ``#<column number>`` and are not used for field-name heuristics.
* Rows with a different width than the header are parse errors (fail, or drop when configured).
* BOM and CRLF/LF line endings are preserved on output. All values stay text (CSV is untyped).
"""

from __future__ import annotations

import csv
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError, InputLimitError
from ciphergate.models.finding import ScanItem
from ciphergate.readers.base import (
    ReaderOptions,
    ReadStats,
    Record,
    detect_newline,
    has_utf8_bom,
)


@contextmanager
def _field_limit(limit: int) -> Iterator[None]:
    previous = csv.field_size_limit()
    csv.field_size_limit(limit)
    try:
        yield
    finally:
        csv.field_size_limit(previous)


class _CountingText:
    """Wraps a text stream, counting encoded bytes so the total input limit is enforced."""

    def __init__(self, inner: IO[str], encoding: str, limit: int, stats: ReadStats) -> None:
        self._inner = inner
        self._encoding = encoding
        self._limit = limit
        self._stats = stats

    def readline(self, size: int = -1) -> str:
        line = self._inner.readline(size)
        self._stats.bytes_read += len(line.encode(self._encoding, errors="replace"))
        if self._stats.bytes_read > self._limit:
            raise InputLimitError("input exceeds max_input_bytes", code="size_limit_exceeded")
        return line

    def __iter__(self) -> Iterator[str]:
        return self

    def __next__(self) -> str:
        line = self.readline()
        if not line:
            raise StopIteration
        return line


class CSVReader:
    format = InputFormat.CSV

    def __init__(self, path: Path, options: ReaderOptions) -> None:
        self.path = path
        self.options = options
        self.stats = ReadStats()
        self.header: list[str] | None = None
        self.labels: list[str] = []
        self.field_names: list[str | None] = []
        self.has_bom = options.encoding.startswith("utf-8") and has_utf8_bom(path)
        self.newline = detect_newline(path)
        self.delimiter = options.runtime.csv_delimiter

    def _build_labels(self, header: list[str]) -> None:
        labels: list[str] = []
        names: list[str | None] = []
        counts: dict[str, int] = {}
        for i, name in enumerate(header):
            if name == "":
                labels.append(f"#{i + 1}")
                names.append(None)
                continue
            counts[name] = counts.get(name, 0) + 1
            if counts[name] > 1:
                if self.options.policy_settings.csv_duplicate_headers == "reject":
                    raise InputFormatError(
                        f"duplicate CSV header in column {i + 1}", code="csv_duplicate_header"
                    )
                labels.append(f"{name}#{counts[name]}")
            else:
                labels.append(name)
            names.append(name)
        self.labels, self.field_names = labels, names

    def header_items(self) -> Iterator[ScanItem]:
        """Header cells as key items. Reads only up to the first data row to learn the header."""
        rows = self.records()
        try:
            next(rows, None)
        finally:
            rows.close()
        for col, name in enumerate(self.header or []):
            if name:
                yield ScanItem(
                    record_index=-1,
                    line=1,
                    field_path=self.labels[col],
                    field_name=None,
                    value=name,
                    column_index=col,
                    in_key=True,
                )

    def records(self) -> Generator[Record, None, None]:
        self.header = None
        self.stats = ReadStats()
        encoding = (
            "utf-8-sig" if self.options.encoding.startswith("utf-8") else self.options.encoding
        )
        runtime = self.options.runtime
        try:
            with (
                _field_limit(runtime.max_record_bytes),
                self.path.open("r", encoding=encoding, newline="", errors="strict") as fh,
            ):
                counted = _CountingText(fh, encoding, runtime.max_input_bytes, self.stats)
                reader = csv.reader(counted, delimiter=self.delimiter, strict=True)
                index = 0
                for row in reader:
                    line = reader.line_num
                    if self.header is None:
                        self.header = row
                        self._build_labels(row)
                        continue
                    if not row:
                        self.stats.blank_lines += 1
                        if self.options.policy_settings.preserve_blank_lines:
                            yield Record(index=-1, line=line, data=[])
                        continue
                    if len(row) != len(self.header):
                        self.stats.parse_errors.append((line, "csv_row_width"))
                        if self.options.policy_settings.fail_on_parse_error:
                            raise InputFormatError(
                                f"CSV row ending at line {line} has {len(row)} fields, header has "
                                f"{len(self.header)}",
                                code="csv_row_width",
                            )
                        yield Record(
                            index=index,
                            line=line,
                            data=row,
                            malformed=True,
                            error_code="csv_row_width",
                        )
                    else:
                        yield Record(index=index, line=line, data=row)
                    index += 1
                    self.stats.records = index
        except UnicodeDecodeError:
            raise InputFormatError(
                f"input is not valid {self.options.encoding}", code="decode_error"
            ) from None
        except csv.Error as exc:
            line = None
            if "field larger than field limit" in str(exc):
                raise InputLimitError(
                    "a CSV field exceeds max_record_bytes", code="record_too_large"
                ) from None
            raise InputFormatError(
                f"malformed CSV near line {line or 'unknown'}", code="csv_syntax"
            ) from None

    def iter_items(self, record: Record) -> Iterator[ScanItem]:
        if record.malformed or record.index < 0:
            return
        for col, value in enumerate(record.data):
            yield ScanItem(
                record_index=record.index,
                line=record.line,
                field_path=self.labels[col],
                field_name=self.field_names[col],
                value=value,
                column_index=col,
            )


class CSVWriter:
    """Writes the header lazily: the reader only knows it once pass two has started reading."""

    def __init__(self, stream: IO[str], reader: CSVReader, dropped_columns: set[int]) -> None:
        self._stream = stream
        self._reader = reader
        self._dropped = dropped_columns
        self._keep: list[int] | None = None
        self._writer = csv.writer(
            stream,
            delimiter=reader.delimiter,
            lineterminator=reader.newline,
            quoting=csv.QUOTE_MINIMAL,
        )
        # QUOTE_MINIMAL only quotes characters of ``lineterminator``; a lone CR/LF inside a field
        # would otherwise be written unquoted and corrupt the value.
        self._quote_all = csv.writer(
            stream,
            delimiter=reader.delimiter,
            lineterminator=reader.newline,
            quoting=csv.QUOTE_ALL,
        )

    def _writerow(self, row: list[Any]) -> None:
        needs_quotes = any(isinstance(v, str) and ("\r" in v or "\n" in v) for v in row)
        (self._quote_all if needs_quotes else self._writer).writerow(row)

    def _ensure_header(self) -> list[int]:
        if self._keep is None:
            header = self._reader.header
            self._keep = [i for i in range(len(header or [])) if i not in self._dropped]
            if self._reader.has_bom:
                self._stream.write("﻿")
            if header is not None:
                self._writerow([header[i] for i in self._keep])
        return self._keep

    def write_record(self, record: Record, data: Any) -> None:
        keep = self._ensure_header()
        if record.index < 0:
            self._writerow([])
            return
        self._writerow([data[i] for i in keep])

    def close(self) -> None:
        self._ensure_header()
        self._stream.flush()
