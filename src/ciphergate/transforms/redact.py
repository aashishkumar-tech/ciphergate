"""Constant-marker redaction. The marker names the category at most; never any source data."""

from __future__ import annotations

from ciphergate.models.policy import RedactParams


def redact(params: RedactParams, category: str) -> str:
    return params.marker.replace("{category}", category)
