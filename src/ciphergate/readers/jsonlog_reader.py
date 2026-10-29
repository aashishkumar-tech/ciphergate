"""JSON-in-log adapter: text/log lines that embed JSON objects (``ERROR {"user": ...}``).

Detection never relies on the parse alone. Every line is scanned exactly like ``text``; the
parse only adds field context on top, for each JSON object found in the line:

* findings inside a value are attributed to it (``field_path`` = JSON Pointer inside the object,
  ``field_name`` = its key), so policy ``field_names``/``field_paths`` rules apply;
* field-name heuristics and policy classifications run on every key and cover the whole value;
* string values that contain JSON escapes (``\\u0040``) are also decoded and scanned, because the
  raw-text scan cannot see through escapes; a match there covers the whole value.

Output keeps the line as it was; only protected spans change. Replacements inside a JSON string
are JSON-escaped, and a replaced number/boolean/null becomes a JSON string, so every embedded
object stays valid JSON; this is re-checked after rewriting and a violation fails the run.

Only objects (``{...}``) are recognised, at most ``MAX_CANDIDATES`` start positions per line,
nested at most ``max_depth`` levels. Text that is not valid JSON gets no field context (it is
still scanned as text). ``drop_field`` is not supported (it becomes ``review``).
"""

from __future__ import annotations

import json
import re
from typing import Any

from ciphergate.constants import InputFormat
from ciphergate.readers.json_reader import pointer_escape
from ciphergate.readers.line_structure import FieldRegion, FieldToken, LineStructure
from ciphergate.readers.text_reader import TextReader

MAX_CANDIDATES = 16
_WS = " \t\r\n"
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]{0,400})(?:\.[0-9]{1,400})?(?:[eE][+-]?[0-9]{1,5})?")
_LITERALS = (("true", True), ("false", False), ("null", None))


class _Invalid(Exception):
    pass


class _Parser:
    def __init__(self, line: str, max_depth: int) -> None:
        self.s = line
        self.n = len(line)
        self.max_depth = max_depth
        self.tokens: list[FieldToken] = []

    def ws(self, i: int) -> int:
        while i < self.n and self.s[i] in _WS:
            i += 1
        return i

    def string(self, i: int) -> tuple[str, int, bool]:
        """Parse a JSON string at ``i`` (the opening quote); returns (value, end, escaped)."""
        j = i + 1
        escaped = False
        while j < self.n:
            ch = self.s[j]
            if ch == '"':
                raw = self.s[i : j + 1]
                try:
                    value = json.loads(raw)
                except ValueError:
                    raise _Invalid from None
                return value, j + 1, escaped
            if ch == "\\":
                escaped = True
                j += 2
                continue
            if ord(ch) < 0x20:
                raise _Invalid
            j += 1
        raise _Invalid

    def value(self, i: int, pointer: str, key: str | None, depth: int) -> int:
        if i >= self.n:
            raise _Invalid
        ch = self.s[i]
        if ch == "{":
            return self.obj(i, pointer, depth + 1)
        if ch == "[":
            return self.array(i, pointer, key, depth + 1)
        if ch == '"':
            value, end, escaped = self.string(i)
            self.tokens.append(FieldToken("string", i + 1, end - 1, pointer, key, value, escaped))
            return end
        for text, literal in _LITERALS:
            if self.s.startswith(text, i):
                self.tokens.append(FieldToken("literal", i, i + len(text), pointer, key, literal))
                return i + len(text)
        m = _NUMBER_RE.match(self.s, i)
        if not m:
            raise _Invalid
        number = json.loads(m.group())
        self.tokens.append(FieldToken("literal", i, m.end(), pointer, key, number))
        return m.end()

    def obj(self, i: int, pointer: str, depth: int) -> int:
        if depth > self.max_depth:
            raise _Invalid
        i = self.ws(i + 1)
        if i < self.n and self.s[i] == "}":
            return i + 1
        while True:
            if i >= self.n or self.s[i] != '"':
                raise _Invalid
            key, key_end, escaped = self.string(i)
            child = f"{pointer}/{pointer_escape(key)}"
            self.tokens.append(FieldToken("key", i + 1, key_end - 1, child, key, key, escaped))
            i = self.ws(key_end)
            if i >= self.n or self.s[i] != ":":
                raise _Invalid
            i = self.value(self.ws(i + 1), child, key, depth)
            i = self.ws(i)
            if i < self.n and self.s[i] == ",":
                i = self.ws(i + 1)
                continue
            if i < self.n and self.s[i] == "}":
                return i + 1
            raise _Invalid

    def array(self, i: int, pointer: str, key: str | None, depth: int) -> int:
        if depth > self.max_depth:
            raise _Invalid
        i = self.ws(i + 1)
        if i < self.n and self.s[i] == "]":
            return i + 1
        index = 0
        while True:
            i = self.ws(self.value(i, f"{pointer}/{index}", key, depth))
            index += 1
            if i < self.n and self.s[i] == ",":
                i = self.ws(i + 1)
                continue
            if i < self.n and self.s[i] == "]":
                return i + 1
            raise _Invalid


def parse_regions(line: str, max_depth: int = 64) -> list[FieldRegion]:
    """JSON objects embedded in ``line`` (non-overlapping, left to right)."""
    regions: list[FieldRegion] = []
    i = 0
    attempts = 0
    while attempts < MAX_CANDIDATES:
        start = line.find("{", i)
        if start < 0:
            break
        attempts += 1
        parser = _Parser(line, max_depth)
        try:
            end = parser.obj(start, "", 1)
        except (_Invalid, RecursionError):
            i = start + 1
            continue
        regions.append(FieldRegion(start, end, tuple(parser.tokens)))
        i = end
    return regions


def _unescape(owner: FieldToken, raw: str) -> Any:
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def _escape(owner: FieldToken, text: str) -> str:
    quoted = json.dumps(text, ensure_ascii=False)
    return quoted if owner.kind == "literal" else quoted[1:-1]


JSONLOG_STRUCTURE = LineStructure(parse=parse_regions, unescape=_unescape, escape=_escape)


class JsonLogReader(TextReader):
    format = InputFormat.JSONLOG
