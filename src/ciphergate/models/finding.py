"""Detection results. A ``Finding`` never carries the matched value, only where and why."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ciphergate.constants import confidence_band


@dataclass(frozen=True, slots=True)
class Location:
    """Structural locator. ``span`` is a character offset range inside the scanned value/line."""

    record_index: int
    line: int | None
    field_path: str
    column_index: int | None = None
    span: tuple[int, int] | None = None
    in_key: bool = False

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"record": self.record_index, "line": self.line}
        if self.field_path:
            data["field_path"] = self.field_path
        if self.column_index is not None:
            data["column"] = self.column_index
        if self.span is not None:
            data["span"] = [self.span[0], self.span[1]]
        if self.in_key:
            data["in_key"] = True
        return data


@dataclass(frozen=True, slots=True)
class Finding:
    category: str
    detector: str
    confidence: float
    evidence: tuple[str, ...]
    location: Location
    field_name: str | None
    value_type: str

    @property
    def band(self) -> str:
        return confidence_band(self.confidence)

    @property
    def whole_value(self) -> bool:
        return self.location.span is None


def value_type_name(value: Any) -> str:
    """Basic JSON-ish type name. Never the value itself."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "other"


@dataclass(frozen=True, slots=True)
class ScanItem:
    """One scalar value (or JSON key) handed to detectors. Held in memory only during a scan."""

    record_index: int
    line: int | None
    field_path: str
    field_name: str | None
    value: Any
    column_index: int | None = None
    in_key: bool = False

    @property
    def text(self) -> str | None:
        """Text form used by content detectors. Booleans and nulls carry no scannable content."""
        if self.value is None or isinstance(self.value, bool):
            return None
        if isinstance(self.value, str):
            return self.value
        if isinstance(self.value, int | float):
            return repr(self.value) if isinstance(self.value, float) else str(self.value)
        return None

    @property
    def is_empty(self) -> bool:
        return self.value is None or self.value == ""

    def location(self, span: tuple[int, int] | None = None) -> Location:
        return Location(
            record_index=self.record_index,
            line=self.line,
            field_path=self.field_path,
            column_index=self.column_index,
            span=span,
            in_key=self.in_key,
        )
