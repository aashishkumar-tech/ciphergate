"""Operational runtime limits. Data-handling decisions live in the policy, never here."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal

PathDisplay = Literal["basename", "redacted", "full"]

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    """Resource limits and presentation options (units: bytes unless stated).

    Every limit fails the run when exceeded; input is never silently truncated.
    """

    max_input_bytes: int = 100 * MIB
    max_json_document_bytes: int = 32 * MIB
    max_record_bytes: int = 1 * MIB
    max_json_depth: int = 64
    max_findings: int = 200_000
    max_report_items: int = 1_000
    encoding: str = "utf-8"
    csv_delimiter: str = ","
    path_display: PathDisplay = "basename"
    # Stored for completeness of the run report; never changes decisions.
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_json_document_bytes",
            "max_record_bytes",
            "max_json_depth",
            "max_findings",
            "max_report_items",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if len(self.csv_delimiter) != 1 or self.csv_delimiter in '\r\n"':
            raise ValueError("csv_delimiter must be a single character other than quote or newline")

    def with_overrides(self, **changes: object) -> RuntimeSettings:
        clean = {k: v for k, v in changes.items() if v is not None}
        return replace(self, **clean)  # type: ignore[arg-type]
