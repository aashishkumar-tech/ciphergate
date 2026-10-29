"""logfmt adapter: text/log lines with ``key=value`` fields (``level=info user_email=a@b``).

Detection never relies on the parse alone. Every line is scanned exactly like ``text`` (including
multi-line private key blocks); the parse only adds field context on top:

* findings whose span lies inside a field value are attributed to that field (``field_name`` =
  key, ``field_path`` = ``/<key>``), so policy ``field_names``/``field_paths`` rules apply;
* field-name heuristics and policy classifications run on each key and, when they match, cover
  the whole value span.

Grammar: whitespace-separated tokens; a field is ``key=value`` with ``key`` matching
``[A-Za-z_][A-Za-z0-9_.-]*`` and ``value`` either bare (up to whitespace, may be empty) or
double-quoted with backslash escapes. Other tokens (timestamps, words) are free text. A line
with an unterminated quote gets no field context (it is still scanned as text). Lines inside a
PEM private key block are never parsed. Output keeps the original line; only finding spans are
replaced, so quoting is preserved. ``drop_field`` is not supported (it becomes ``review``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ciphergate.constants import InputFormat
from ciphergate.readers.text_reader import TextReader

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]{0,255}")


@dataclass(frozen=True, slots=True)
class LogfmtField:
    key: str
    value: str  # unquoted/unescaped
    start: int  # raw value span in the line (inside the quotes for quoted values)
    end: int


def parse_fields(line: str) -> list[LogfmtField] | None:
    """Fields of one line, or ``None`` when quoting is malformed (no field context then)."""
    fields: list[LogfmtField] = []
    i, n = 0, len(line)
    while i < n:
        if line[i].isspace():
            i += 1
            continue
        key_match = _KEY_RE.match(line, i)
        eq = key_match.end() if key_match else i
        if key_match and eq < n and line[eq] == "=":
            v = eq + 1
            if v < n and line[v] == '"':
                parsed = _quoted(line, v)
                if parsed is None:
                    return None
                value, end = parsed
                if end < n and not line[end].isspace():
                    return None  # text glued to a closing quote: ambiguous
                fields.append(LogfmtField(key_match.group(), value, v + 1, end - 1))
                i = end
                continue
            end = v
            while end < n and not line[end].isspace():
                end += 1
            fields.append(LogfmtField(key_match.group(), line[v:end], v, end))
            i = end
            continue
        while i < n and not line[i].isspace():  # free-text token
            if line[i] == '"':
                return None
            i += 1
    return fields


def _quoted(line: str, start: int) -> tuple[str, int] | None:
    """Parse a quoted value starting at ``start`` (the opening quote). Returns (value, end)."""
    out: list[str] = []
    i = start + 1
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            nxt = line[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return None


def field_for_span(fields: list[LogfmtField], span: tuple[int, int]) -> LogfmtField | None:
    for f in fields:
        if f.start <= span[0] and span[1] <= f.end:
            return f
    return None


class LogfmtReader(TextReader):
    format = InputFormat.LOGFMT
