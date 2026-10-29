"""Shared span machinery for structured line formats (JSON-in-log, access logs).

A structured line format parses a text line into *regions* (spans of recognised structure) made
of *tokens* (keys and values with raw offsets). The pipeline scans the line exactly like
``text`` and uses the parse only to add field context, to snap findings onto token boundaries,
and to re-encode replacements so that the structure survives rewriting.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class FieldToken:
    """A key or value inside a parsed region. Spans are raw offsets in the line."""

    kind: str  # "key", "string" (value) or "literal" (a value replaced as a whole)
    start: int  # strings: the raw value body (inside any quotes); literals: the literal itself
    end: int
    pointer: str  # JSON Pointer-style field path (keys: the pointer of their value)
    key: str | None  # nearest field name, None when the value has no name
    value: Any  # decoded value (keys: the decoded key)
    escaped: bool = False  # raw text differs from the decoded value


@dataclass(frozen=True, slots=True)
class FieldRegion:
    start: int
    end: int
    tokens: tuple[FieldToken, ...]


@dataclass(frozen=True, slots=True)
class LineStructure:
    """How one structured line format parses and re-encodes its tokens."""

    parse: Callable[[str, int], list[FieldRegion]]  # (line, max_depth) -> regions
    unescape: Callable[[FieldToken, str], Any]  # raw part of a token -> what a transform sees
    escape: Callable[[FieldToken, str], str]  # replacement text -> raw text for the token


def region_tokens(regions: list[FieldRegion]) -> list[FieldToken]:
    return [t for r in regions for t in r.tokens]


def token_at(tokens: list[FieldToken], start: int, end: int) -> FieldToken | None:
    """The token whose span contains ``[start, end)`` (literals: any overlap), if any."""
    for t in tokens:
        if t.kind == "literal" and start < t.end and t.start < end:
            return t
        if t.kind != "literal" and t.start <= start and end <= t.end:
            return t
    return None


def snap_span(regions: list[FieldRegion], start: int, end: int) -> list[tuple[int, int]]:
    """Split a span so that no piece crosses structural syntax.

    Parts outside every region are kept. Inside a region, the span becomes the spans of the
    value tokens it overlaps (or key tokens, if it overlaps no value); literal tokens are taken
    whole. A span over punctuation only covers every value of its region, whole; a region with
    no values yields nothing. A span already inside one string token, or covering one literal
    exactly, is returned unchanged.
    """
    pieces: list[tuple[int, int]] = []
    cursor = start
    for region in regions:
        if region.end <= start or end <= region.start:
            continue
        if cursor < region.start:
            pieces.append((cursor, region.start))
        lo, hi = max(start, region.start), min(end, region.end)
        inside = [t for t in region.tokens if t.kind != "key" and lo < t.end and t.start < hi]
        if not inside:
            inside = [t for t in region.tokens if t.kind == "key" and lo < t.end and t.start < hi]
        if not inside:
            # Only punctuation (e.g. a secret pattern that matched an opening brace): the
            # finding is about the structure itself, so protect every value in it, whole.
            lo, hi = region.start, region.end
            inside = [t for t in region.tokens if t.kind != "key"]
        for t in inside:
            if t.kind == "literal":
                pieces.append((t.start, t.end))
            else:
                pieces.append((max(lo, t.start), min(hi, t.end)))
        cursor = region.end
    if cursor < end:
        pieces.append((cursor, end))
    return [p for p in pieces if p[0] < p[1]]


class SpanCodec:
    """Decodes a span to the value a transform sees and re-encodes the replacement."""

    def __init__(self, structure: LineStructure, regions: list[FieldRegion]) -> None:
        self.structure = structure
        self.tokens = region_tokens(regions)

    def decode(self, start: int, end: int, raw: str) -> Any:
        owner = token_at(self.tokens, start, end)
        if owner is None:
            return raw
        if owner.kind == "literal" or (start, end) == (owner.start, owner.end):
            return owner.value
        return self.structure.unescape(owner, raw)

    def encode(self, start: int, end: int, replacement: Any) -> str:
        owner = token_at(self.tokens, start, end)
        text = replacement if isinstance(replacement, str) else str(replacement)
        if owner is None:
            return text
        return self.structure.escape(owner, text)


def structure_still_valid(
    structure: LineStructure, line: str, before: list[FieldRegion], max_depth: int
) -> bool:
    """After rewriting, the line must parse into at least as many regions and tokens."""
    after = structure.parse(line, max_depth)
    return len(after) >= len(before) and len(region_tokens(after)) >= len(region_tokens(before))
