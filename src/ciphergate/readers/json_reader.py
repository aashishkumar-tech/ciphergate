"""JSON adapter (whole-document parse, bounded by ``max_json_document_bytes``).

* A top-level array is treated as a sequence of records (``/0``, ``/1``, ...); any other top-level
  value is a single record.
* Paths are RFC 6901 JSON Pointers (``~`` -> ``~0``, ``/`` -> ``~1``).
* Nesting depth is checked by a string-aware pre-scan before parsing.
* Duplicate object keys and NaN/Infinity are rejected (strict JSON).
* Parser error messages are replaced with position-only messages (never source excerpts).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError, InputLimitError
from ciphergate.models.finding import ScanItem
from ciphergate.readers.base import ReaderOptions, ReadStats, Record, detect_newline


class _DuplicateKey(Exception):
    pass


class _BadConstant(Exception):
    pass


def pointer_escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def check_depth(text: str, max_depth: int) -> None:
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                raise InputLimitError(
                    f"JSON nesting exceeds max depth {max_depth}", code="json_too_deep"
                )
        elif ch in "]}":
            depth -= 1


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey
        out[key] = value
    return out


def _reject_constant(_: str) -> Any:
    raise _BadConstant


def parse_json_text(text: str, max_depth: int, *, where: str = "document") -> Any:
    check_depth(text, max_depth)
    try:
        return json.loads(text, object_pairs_hook=_pairs_hook, parse_constant=_reject_constant)
    except _DuplicateKey:
        raise InputFormatError(
            f"duplicate object key in JSON {where}", code="json_duplicate_key"
        ) from None
    except _BadConstant:
        raise InputFormatError(
            f"NaN/Infinity are not valid JSON ({where})", code="json_invalid_constant"
        ) from None
    except json.JSONDecodeError as exc:
        raise InputFormatError(
            f"invalid JSON {where} at line {exc.lineno}, column {exc.colno}", code="json_syntax"
        ) from None
    except RecursionError:
        raise InputLimitError("JSON nesting too deep", code="json_too_deep") from None


def iter_json_items(
    node: Any,
    pointer: str,
    field_name: str | None,
    record_index: int,
    line: int | None,
    scan_keys: bool,
) -> Iterator[ScanItem]:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{pointer}/{pointer_escape(key)}"
            if scan_keys:
                yield ScanItem(record_index, line, child, None, key, in_key=True)
            yield from iter_json_items(value, child, key, record_index, line, scan_keys)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from iter_json_items(
                value, f"{pointer}/{i}", field_name, record_index, line, scan_keys
            )
    else:
        yield ScanItem(record_index, line, pointer, field_name, node)


class JSONReader:
    format = InputFormat.JSON

    def __init__(self, path: Path, options: ReaderOptions) -> None:
        self.path = path
        self.options = options
        self.stats = ReadStats()
        self.top_level_array = False
        self.newline = detect_newline(path)

    def records(self) -> Iterator[Record]:
        runtime = self.options.runtime
        limit = min(runtime.max_json_document_bytes, runtime.max_input_bytes)
        with self.path.open("rb") as fh:
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise InputLimitError(
                f"JSON document exceeds {limit} bytes", code="size_limit_exceeded"
            )
        self.stats.bytes_read = len(data)
        encoding = self.options.encoding
        try:
            text = data.decode("utf-8-sig" if encoding.startswith("utf-8") else encoding)
        except UnicodeDecodeError:
            raise InputFormatError(f"input is not valid {encoding}", code="decode_error") from None
        doc = parse_json_text(text, runtime.max_json_depth)
        if isinstance(doc, list):
            self.top_level_array = True
            for i, element in enumerate(doc):
                self.stats.records = i + 1
                yield Record(index=i, line=None, data=element)
        else:
            self.stats.records = 1
            yield Record(index=0, line=None, data=doc)

    def iter_items(self, record: Record) -> Iterator[ScanItem]:
        prefix = f"/{record.index}" if self.top_level_array else ""
        yield from iter_json_items(
            record.data,
            prefix,
            None,
            record.index,
            None,
            self.options.policy_settings.scan_json_keys,
        )


class JSONWriter:
    """Buffers records and writes one UTF-8 JSON document (indent 2) on close."""

    def __init__(self, stream: IO[str], reader: JSONReader) -> None:
        self._stream = stream
        self._reader = reader
        self._newline = reader.newline
        self._items: list[Any] = []

    def write_record(self, record: Record, data: Any) -> None:
        self._items.append(data)

    def close(self) -> None:
        doc: Any = (
            self._items
            if self._reader.top_level_array
            else (self._items[0] if self._items else None)
        )
        text = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False)
        self._stream.write(text.replace("\n", self._newline) + self._newline)
        self._stream.flush()
