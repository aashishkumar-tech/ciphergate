"""JSONL / NDJSON adapter: one JSON value per non-empty line, streamed with bounded memory.

Blank lines are dropped from output unless ``preserve_blank_lines`` is set. Malformed lines fail the
run by default; with ``fail_on_parse_error: false`` + ``malformed_record_action: drop_record`` they
are dropped and counted. A malformed line is never copied unchanged into the output.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError
from ciphergate.models.finding import ScanItem
from ciphergate.readers.base import (
    ReaderOptions,
    ReadStats,
    Record,
    decode_line,
    read_bounded_lines,
    split_line_ending,
)
from ciphergate.readers.json_reader import iter_json_items, parse_json_text


class JSONLReader:
    format = InputFormat.JSONL

    def __init__(self, path: Path, options: ReaderOptions) -> None:
        self.path = path
        self.options = options
        self.stats = ReadStats()

    def records(self) -> Iterator[Record]:
        settings = self.options.policy_settings
        index = 0
        with self.path.open("rb") as fh:
            for line_no, raw in read_bounded_lines(fh, self.options, self.stats):
                text = decode_line(raw, self.options.encoding, line_no, first=line_no == 1)
                content, ending = split_line_ending(text)
                if not content.strip():
                    self.stats.blank_lines += 1
                    if settings.preserve_blank_lines:
                        yield Record(index=-1, line=line_no, data=content, line_ending=ending)
                    continue
                try:
                    data = parse_json_text(
                        content, self.options.runtime.max_json_depth, where=f"line {line_no}"
                    )
                except InputFormatError as exc:
                    self.stats.parse_errors.append((line_no, exc.code))
                    if settings.fail_on_parse_error:
                        raise InputFormatError(
                            f"invalid JSON on line {line_no}", code=exc.code
                        ) from None
                    yield Record(
                        index=index,
                        line=line_no,
                        data=None,
                        line_ending=ending,
                        malformed=True,
                        error_code=exc.code,
                    )
                else:
                    yield Record(index=index, line=line_no, data=data, line_ending=ending)
                index += 1
                self.stats.records = index

    def iter_items(self, record: Record) -> Iterator[ScanItem]:
        if record.malformed or record.index < 0:
            return
        yield from iter_json_items(
            record.data,
            "",
            None,
            record.index,
            record.line,
            self.options.policy_settings.scan_json_keys,
        )


class JSONLWriter:
    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream

    def write_record(self, record: Record, data: Any) -> None:
        ending = record.line_ending or "\n"
        if record.index < 0:
            self._stream.write(ending)
            return
        self._stream.write(json.dumps(data, ensure_ascii=False, allow_nan=False) + ending)

    def close(self) -> None:
        self._stream.flush()
