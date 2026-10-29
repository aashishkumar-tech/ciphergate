"""Access-log adapter: NCSA common/combined lines as written by nginx and Apache httpd.

``192.0.2.10 - alice [05/Jan/2026:10:00:00 +0000] "GET /p?email=a%40b HTTP/1.1" 200 12 "ref" "ua"``

Detection never relies on the parse alone. Every line is scanned exactly like ``text``; the
parse only adds field context on top:

* fields get nginx variable names as field paths: ``/remote_addr``, ``/ident``,
  ``/remote_user``, ``/time_local``, ``/request`` (split into ``/request/method``,
  ``/request/path``, ``/request/protocol`` when it has the usual three parts), ``/status``,
  ``/body_bytes_sent``, ``/http_referer`` and ``/http_user_agent``;
* query strings of the request target and the referer become fields too
  (``/request/query/<name>``), so field-name heuristics and ``field_names`` rules apply to
  parameters such as ``email`` or ``access_token``;
* log escapes (``\\x22``, ``\\"``) and percent-encoding are decoded and the decoded value is
  scanned as well, because the raw-text scan cannot see through them.

A ``-`` field means "no value" and gets no field context. Output keeps the line as it was; only
protected spans change. Replacements are re-encoded for their field (percent-encoding in paths
and query strings, ``\\xHH`` log escapes elsewhere), and the line must still parse with as many
fields afterwards, or the run fails. Only lines that *start* with the common/combined layout are
recognised; anything after the user agent (e.g. ``$http_x_forwarded_for``) and lines in other
layouts get text-mode scanning only. ``drop_field`` is not supported (it becomes ``review``).
"""

from __future__ import annotations

import re
from typing import Any

from ciphergate.constants import InputFormat
from ciphergate.readers.json_reader import pointer_escape
from ciphergate.readers.line_structure import FieldRegion, FieldToken, LineStructure
from ciphergate.readers.text_reader import TextReader

# Three space-free fields, then the bracketed time. Classes never overlap the separators, so
# matching is linear.
_HEAD_RE = re.compile(r'([^\s"]{1,1024}) ([^\s"]{1,1024}) ([^\s"]{1,1024}) \[([^\]\n]{1,128})\] ')
_SHORT_RE = re.compile(r' ([^\s"]{1,64}) ([^\s"]{1,64})')
_REQUEST_RE = re.compile(r"([^ ]{1,64}) ([^ ]{1,8192}) ([^ ]{1,64})")
_MAX_QUOTED = 16384
_LOG_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
# Characters kept literally when percent-encoding a replacement (markers stay readable).
_URL_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$'()*,:@/[]"
)
_HEX = "0123456789abcdefABCDEF"


def _quoted(line: str, i: int) -> int | None:
    """End offset of the quoted field whose opening quote is at ``i`` (after the closing quote)."""
    if i >= len(line) or line[i] != '"':
        return None
    j, limit = i + 1, min(len(line), i + 1 + _MAX_QUOTED)
    while j < limit:
        ch = line[j]
        if ch == '"':
            return j + 1
        j += 2 if ch == "\\" else 1
    return None


def _log_unescape(raw: str) -> str:
    """Undo nginx (``\\xHH``) and Apache (``\\"``, ``\\\\``, ``\\n``) log escapes."""
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "\\" and i + 1 < n:
            nxt = raw[i + 1]
            if nxt == "x" and i + 3 < n and raw[i + 2] in _HEX and raw[i + 3] in _HEX:
                out.append(chr(int(raw[i + 2 : i + 4], 16)))
                i += 4
                continue
            if nxt in _LOG_ESCAPES:
                out.append(_LOG_ESCAPES[nxt])
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _percent_decode(text: str, *, plus: bool) -> str:
    """Percent-decoding (``+`` is a space in query strings); invalid UTF-8 becomes U+FFFD."""
    if "%" not in text and not (plus and "+" in text):
        return text
    data = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "%" and i + 2 < n and text[i + 1] in _HEX and text[i + 2] in _HEX:
            data.append(int(text[i + 1 : i + 3], 16))
            i += 3
            continue
        data.extend(b" " if plus and ch == "+" else ch.encode("utf-8"))
        i += 1
    return data.decode("utf-8", errors="replace")


def _kind(pointer: str) -> str:
    """How a field is encoded in the line, from its path."""
    if "/query/" in pointer or pointer == "/request/path":
        return "url"
    if pointer == "/http_referer":
        return "referer"
    if pointer in ("/request/method", "/request/protocol"):
        return "request_part"
    if pointer in ("/request", "/http_user_agent"):
        return "quoted"
    if pointer == "/time_local":
        return "time"
    return "bare"


def _decode(pointer: str, raw: str) -> str:
    text = _log_unescape(raw)
    if _kind(pointer) == "url":
        return _percent_decode(text, plus="/query/" in pointer)
    return text


def _hex_escape(ch: str) -> str:
    return "".join(f"\\x{b:02X}" for b in ch.encode("utf-8"))


def _escape(owner: FieldToken, text: str) -> str:
    kind = _kind(owner.pointer)
    if kind == "url":
        return "".join(
            ch if ch in _URL_SAFE else "".join(f"%{b:02X}" for b in ch.encode("utf-8"))
            for ch in text
        )
    special = {
        "quoted": '"\\',
        "referer": '"\\',
        "request_part": '"\\ ',
        "time": '"\\]',
        "bare": '"\\',
    }[kind]
    out: list[str] = []
    for ch in text:
        if ch in special or ord(ch) < 0x20 or ord(ch) == 0x7F or (kind == "bare" and ch.isspace()):
            out.append(_hex_escape(ch))
        elif kind == "referer" and ch in "?#":
            out.append(f"%{ord(ch):02X}")
        else:
            out.append(ch)
    return "".join(out)


def _unescape(owner: FieldToken, raw: str) -> Any:
    return _decode(owner.pointer, raw)


def _field(
    tokens: list[FieldToken], line: str, pointer: str, key: str, start: int, end: int
) -> None:
    raw = line[start:end]
    if raw in ("", "-"):
        return  # "-" is the log's "no value"
    value = _decode(pointer, raw)
    tokens.append(FieldToken("string", start, end, pointer, key, value, value != raw))


def _query(tokens: list[FieldToken], base: str, line: str, start: int, end: int) -> None:
    """``name=value&...`` between ``start`` and ``end`` as key and value tokens."""
    i = start
    while i <= end:
        amp = line.find("&", i, end)
        stop = end if amp < 0 else amp
        if stop > i:
            eq = line.find("=", i, stop)
            key_end = stop if eq < 0 else eq
            name_raw = line[i:key_end]
            name = _percent_decode(_log_unescape(name_raw), plus=True)
            pointer = f"{base}/query/{pointer_escape(name)}"
            tokens.append(FieldToken("key", i, key_end, pointer, name, name, name != name_raw))
            if eq >= 0:
                raw = line[eq + 1 : stop]
                value = _decode(pointer, raw)
                tokens.append(
                    FieldToken("string", eq + 1, stop, pointer, name, value, value != raw)
                )
        i = stop + 1


def _target(tokens: list[FieldToken], line: str, start: int, end: int) -> None:
    q = line.find("?", start, end)
    _field(tokens, line, "/request/path", "path", start, end if q < 0 else q)
    if q >= 0:
        _query(tokens, "/request", line, q + 1, end)


def parse_regions(line: str, max_depth: int = 64) -> list[FieldRegion]:
    """The access-log fields of ``line`` as one region, or ``[]`` if it is not in that layout."""
    head = _HEAD_RE.match(line)
    if head is None:
        return []
    request_end = _quoted(line, head.end())
    if request_end is None:
        return []
    short = _SHORT_RE.match(line, request_end)
    if short is None:
        return []
    tokens: list[FieldToken] = []
    for group, name in enumerate(("remote_addr", "ident", "remote_user", "time_local"), 1):
        _field(tokens, line, "/" + name, name, head.start(group), head.end(group))
    req_start, req_end = head.end() + 1, request_end - 1
    request = _REQUEST_RE.fullmatch(line, req_start, req_end)
    if request is None:
        _field(tokens, line, "/request", "request", req_start, req_end)
    else:
        _field(tokens, line, "/request/method", "method", request.start(1), request.end(1))
        _target(tokens, line, request.start(2), request.end(2))
        _field(tokens, line, "/request/protocol", "protocol", request.start(3), request.end(3))
    _field(tokens, line, "/status", "status", short.start(1), short.end(1))
    _field(tokens, line, "/body_bytes_sent", "body_bytes_sent", short.start(2), short.end(2))
    end = short.end()
    referer_end = _quoted(line, end + 1) if line.startswith(' "', end) else None
    if referer_end is not None:
        agent_end = _quoted(line, referer_end + 1) if line.startswith(' "', referer_end) else None
        if agent_end is not None:
            ref_start, ref_stop = end + 2, referer_end - 1
            q = line.find("?", ref_start, ref_stop)
            _field(
                tokens, line, "/http_referer", "http_referer", ref_start, ref_stop if q < 0 else q
            )
            if q >= 0:
                _query(tokens, "/http_referer", line, q + 1, ref_stop)
            _field(
                tokens, line, "/http_user_agent", "http_user_agent", referer_end + 2, agent_end - 1
            )
            end = agent_end
    return [FieldRegion(0, end, tuple(tokens))]


ACCESSLOG_STRUCTURE = LineStructure(parse=parse_regions, unescape=_unescape, escape=_escape)


class AccessLogReader(TextReader):
    format = InputFormat.ACCESSLOG
