"""syslog adapter: RFC 5424 and RFC 3164 lines, and CEF (bare or as a syslog message).

* RFC 5424: ``<34>1 2026-01-05T10:00:00Z host app 42 ID7 [origin ip="192.0.2.1"] message``.
  Header fields become ``/timestamp``, ``/hostname``, ``/app_name``, ``/procid``, ``/msgid``;
  structured-data parameters become ``/sd/<sd-id>/<name>`` (escapes ``\\"``, ``\\\\``, ``\\]``);
  the message is ``/msg``.
* RFC 3164 / BSD, including files written by rsyslog without ``<PRI>`` and with RFC 3339
  timestamps: ``Jan  5 10:00:00 host sshd[42]: message`` gives ``/timestamp``, ``/hostname``,
  ``/app_name`` (the tag), ``/procid`` and ``/msg``. A line needs a ``tag:`` (or a CEF message)
  to be recognised.
* CEF: ``CEF:0|Vendor|Product|1.0|100|Name|5|suser=alice src=192.0.2.1``, on its own or as
  the message of either syslog layout. Header fields become ``/cef/device_vendor`` ...
  ``/cef/severity``, with CEF ``Name`` as ``/cef/event_name`` (escapes ``\\|``, ``\\\\``);
  extensions become ``/cef/extension/<key>``
  (escapes ``\\=``, ``\\\\``, ``\\n``, ``\\r``). Common short keys get a canonical name for the
  field-name heuristics (``suser`` -> ``source_user_name``, ``src`` -> ``source_ip``), and
  ``csN``/``cnN`` fields use their ``csNLabel`` value; the raw key stays the field name.

Detection never relies on the parse alone: every line is scanned exactly like ``text`` and the
parse only adds field context. Replacements are re-escaped for their field; header fields get
``_`` for whitespace (an RFC 3164 tag also for anything outside ``[A-Za-z0-9_./-]``). Every
rewritten line must still parse with as many fields, or the run fails. ``-`` (NILVALUE) fields
get no field context. ``drop_field`` is not supported (it becomes ``review``).
"""

from __future__ import annotations

import re
from typing import Any

from ciphergate.constants import InputFormat
from ciphergate.readers.json_reader import pointer_escape
from ciphergate.readers.line_structure import FieldRegion, FieldToken, LineStructure
from ciphergate.readers.text_reader import TextReader

_PRI = r"<\d{1,3}>"
_RFC5424_RE = re.compile(
    _PRI + r"[1-9]\d{0,2} (\S{1,64}) (\S{1,255}) (\S{1,48}) (\S{1,128}) (\S{1,32}) "
)
_TS3164 = r"[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}"
_TS3339 = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"
_RFC3164_RE = re.compile(rf"(?:{_PRI})?({_TS3164}|{_TS3339}) (\S{{1,255}}) ")
_TAG_RE = re.compile(r"([A-Za-z0-9_./-]{1,48})(?:\[([0-9A-Za-z_-]{1,32})\])?: ")
_SD_NAME_RE = re.compile(r'[^\s="\]]{1,32}')
_CEF_START = "CEF:"
_CEF_VERSION_RE = re.compile(r"CEF:\d{1,2}(?:\.\d{1,2})?\|")
_CEF_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}=")
_CEF_HEADERS = (
    "device_vendor",
    "device_product",
    "device_version",
    "signature_id",
    "event_name",  # CEF "Name"; not "name", which the heuristics read as a person name
    "severity",
)
_MAX_SD_ELEMENTS = 64
_MAX_SD_PARAMS = 64
_MAX_CEF_FIELDS = 256
_MAX_VALUE = 16384

# Canonical names for common CEF extension keys, used only for field-name heuristics.
CEF_HINTS = {
    "src": "source_ip",
    "dst": "destination_ip",
    "dvc": "device_ip",
    "c6a1": "device_ipv6",
    "c6a2": "source_ipv6",
    "c6a3": "destination_ipv6",
    "shost": "source_hostname",
    "dhost": "destination_hostname",
    "dvchost": "device_hostname",
    "suser": "source_user_name",
    "duser": "destination_user_name",
    "suid": "source_user_id",
    "duid": "destination_user_id",
    "smac": "source_mac_address",
    "dmac": "destination_mac_address",
    "dvcmac": "device_mac_address",
}
_LABELLED = re.compile(r"(?:cs|cn|cfp|c6a|flexString|flexNumber|flexDate)\d{1,2}")

# Characters an RFC 3164 tag may hold (other header fields only exclude whitespace).
_TAG_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-")


def _unescape_chars(raw: str, escapes: dict[str, str]) -> str:
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "\\" and i + 1 < n and raw[i + 1] in escapes:
            out.append(escapes[raw[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_UNESCAPES = {
    "sd": {'"': '"', "\\": "\\", "]": "]"},
    "cef_header": {"|": "|", "\\": "\\"},
    "cef_ext": {"=": "=", "\\": "\\", "n": "\n", "r": "\r"},
}


def _decode(style: str, raw: str) -> str:
    escapes = _UNESCAPES.get(style)
    return _unescape_chars(raw, escapes) if escapes else raw


def _escape(owner: FieldToken, text: str) -> str:
    style = owner.style
    if style == "sd":
        return "".join("\\" + ch if ch in '"\\]' else _no_control(ch) for ch in text)
    if style == "cef_header":
        return "".join("\\" + ch if ch in "|\\" else _no_control(ch) for ch in text)
    if style == "cef_ext":
        table = {"\\": "\\\\", "=": "\\=", "\n": "\\n", "\r": "\\r"}
        return "".join(table.get(ch, _no_control(ch)) for ch in text)
    if style == "tag":
        return "".join(ch if ch in _TAG_SAFE else "_" for ch in text) or "_"
    if style == "bare":
        return "".join("_" if ch.isspace() else _no_control(ch) for ch in text) or "_"
    return "".join(_no_control(ch) for ch in text)  # free-text message


def _no_control(ch: str) -> str:
    return " " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch


def _unescape(owner: FieldToken, raw: str) -> Any:
    return _decode(owner.style, raw)


class _Tokens:
    def __init__(self, line: str) -> None:
        self.line = line
        self.items: list[FieldToken] = []

    def value(
        self,
        pointer: str,
        key: str,
        start: int,
        end: int,
        style: str,
        hint: str | None = None,
        *,
        nil: bool = True,
    ) -> None:
        raw = self.line[start:end]
        if raw == "" or (nil and raw == "-"):
            return  # NILVALUE / empty: nothing to protect
        value = _decode(style, raw)
        self.items.append(
            FieldToken("string", start, end, pointer, key, value, value != raw, style, hint)
        )

    def key(self, pointer: str, name: str, start: int, end: int) -> None:
        self.items.append(FieldToken("key", start, end, pointer, name, name))


def _structured_data(t: _Tokens, i: int) -> int | None:
    """Parse STRUCTURED-DATA at ``i``; returns its end, or ``None`` when malformed."""
    line, n = t.line, len(t.line)
    if line.startswith("-", i) and (i + 1 == n or line[i + 1] == " "):
        return i + 1
    elements = 0
    while i < n and line[i] == "[":
        elements += 1
        if elements > _MAX_SD_ELEMENTS:
            return None
        sd_id = _SD_NAME_RE.match(line, i + 1)
        if sd_id is None:
            return None
        base = f"/sd/{pointer_escape(sd_id.group())}"
        i = sd_id.end()
        params = 0
        while i < n and line[i] == " ":
            params += 1
            name = _SD_NAME_RE.match(line, i + 1)
            if params > _MAX_SD_PARAMS or name is None:
                return None
            eq = name.end()
            if not line.startswith('="', eq):
                return None
            j, limit = eq + 2, min(n, eq + 2 + _MAX_VALUE)
            while j < limit and line[j] != '"':
                j += 2 if line[j] == "\\" else 1
            if j >= limit:
                return None
            pointer = f"{base}/{pointer_escape(name.group())}"
            t.key(pointer, name.group(), name.start(), name.end())
            t.value(pointer, name.group(), eq + 2, j, "sd", nil=False)
            i = j + 1
        if i >= n or line[i] != "]":
            return None
        i += 1
    return i if elements else None


def _cef(t: _Tokens, start: int) -> int | None:
    """Parse a CEF record starting at ``start``; returns its end, or ``None`` if it is not CEF."""
    line, n = t.line, len(t.line)
    head = _CEF_VERSION_RE.match(line, start)
    if head is None:
        return None
    i = head.end()
    for name in _CEF_HEADERS:
        j, limit = i, min(n, i + _MAX_VALUE)
        while j < limit and line[j] != "|":
            j += 2 if line[j] == "\\" else 1
        if j >= limit:
            return None
        t.value(f"/cef/{name}", name, i, j, "cef_header", nil=False)
        i = j + 1
    _cef_extension(t, i, n)
    return n


def _cef_extension(t: _Tokens, start: int, end: int) -> None:
    line = t.line
    # A key starts the extension or follows a space; "=" inside values must be escaped.
    keys: list[tuple[int, int]] = []  # (key start, value start)
    i = start
    while i < end and len(keys) < _MAX_CEF_FIELDS:
        if i == start or line[i - 1] == " ":
            m = _CEF_KEY_RE.match(line, i, end)
            if m is not None:
                keys.append((i, m.end()))
                i = m.end()
                continue
        i += 1
    labels: dict[str, str] = {}
    spans: list[tuple[str, int, int]] = []
    for index, (key_start, value_start) in enumerate(keys):
        value_end = keys[index + 1][0] - 1 if index + 1 < len(keys) else end
        while value_end > value_start and line[value_end - 1] == " ":
            value_end -= 1
        name = line[key_start : value_start - 1]
        spans.append((name, value_start, value_end))
        if name.endswith("Label"):
            labels[name[: -len("Label")]] = _decode("cef_ext", line[value_start:value_end])
    for name, value_start, value_end in spans:
        hint = CEF_HINTS.get(name)
        if hint is None and _LABELLED.fullmatch(name):
            hint = labels.get(name)
        pointer = f"/cef/extension/{pointer_escape(name)}"
        t.key(pointer, name, value_start - len(name) - 1, value_start - 1)
        t.value(pointer, name, value_start, value_end, "cef_ext", hint, nil=False)


def _message(t: _Tokens, start: int) -> None:
    """A syslog MSG: CEF if it is one, else free text."""
    line = t.line
    if line.startswith("﻿", start):
        start += 1
    if line.startswith(_CEF_START, start) and _cef(t, start) is not None:
        return
    t.value("/msg", "msg", start, len(line), "msg", nil=False)


def parse_regions(line: str, max_depth: int = 64) -> list[FieldRegion]:
    """The syslog/CEF fields of ``line`` as one region, or ``[]`` for other layouts."""
    t = _Tokens(line)
    if line.startswith(_CEF_START):
        if _cef(t, 0) is None:
            return []
        return [FieldRegion(0, len(line), tuple(t.items))]
    m = _RFC5424_RE.match(line)
    if m is not None:
        for group, name in enumerate(("timestamp", "hostname", "app_name", "procid", "msgid"), 1):
            t.value("/" + name, name, m.start(group), m.end(group), "bare")
        end = _structured_data(t, m.end())
        if end is None:
            return []
        if end < len(line):
            if line[end] != " ":
                return []
            _message(t, end + 1)
        return [FieldRegion(0, len(line), tuple(t.items))]
    m = _RFC3164_RE.match(line)
    if m is None:
        return []
    t.value("/timestamp", "timestamp", m.start(1), m.end(1), "bare")
    t.value("/hostname", "hostname", m.start(2), m.end(2), "bare")
    rest = m.end()
    if line.startswith(_CEF_START, rest):
        if _cef(t, rest) is None:
            return []
        return [FieldRegion(0, len(line), tuple(t.items))]
    tag = _TAG_RE.match(line, rest)
    if tag is None:
        return []
    t.value("/app_name", "app_name", tag.start(1), tag.end(1), "tag")
    if tag.group(2) is not None:
        t.value("/procid", "procid", tag.start(2), tag.end(2), "tag")
    _message(t, tag.end())
    return [FieldRegion(0, len(line), tuple(t.items))]


SYSLOG_STRUCTURE = LineStructure(parse=parse_regions, unescape=_unescape, escape=_escape)


class SyslogReader(TextReader):
    format = InputFormat.SYSLOG
