"""Plain text / log adapter: each line is one record, scanned as free text.

Lines are never interpreted as structured key/value data. Original line endings (LF, CRLF, CR) are
preserved. Multi-line private key blocks are tracked across lines by the detector set.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from ciphergate.constants import InputFormat
from ciphergate.models.finding import ScanItem
from ciphergate.readers.base import (
    ReaderOptions,
    ReadStats,
    Record,
    decode_line,
    has_utf8_bom,
    read_bounded_lines,
    split_line_ending,
)


class TextReader:
    format = InputFormat.TEXT

    def __init__(self, path: Path, options: ReaderOptions) -> None:
        self.path = path
        self.options = options
        self.stats = ReadStats()
        self.has_bom = options.encoding.startswith("utf-8") and has_utf8_bom(path)

    def records(self) -> Iterator[Record]:
        with self.path.open("rb") as fh:
            for line_no, raw in read_bounded_lines(fh, self.options, self.stats):
                text = decode_line(raw, self.options.encoding, line_no, first=line_no == 1)
                content, ending = split_line_ending(text)
                self.stats.records = line_no
                yield Record(index=line_no - 1, line=line_no, data=content, line_ending=ending)

    def iter_items(self, record: Record) -> Iterator[ScanItem]:
        yield ScanItem(record.index, record.line, "", None, record.data)


class TextWriter:
    def __init__(self, stream: IO[str], reader: TextReader) -> None:
        self._stream = stream
        self._bom_pending = reader.has_bom

    def write_record(self, record: Record, data: Any) -> None:
        if self._bom_pending:
            self._stream.write("﻿")
            self._bom_pending = False
        self._stream.write(str(data) + record.line_ending)

    def close(self) -> None:
        self._stream.flush()
