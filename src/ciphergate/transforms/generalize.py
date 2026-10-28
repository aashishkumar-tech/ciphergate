"""Precision-reducing generalization strategies.

* ``year`` / ``year_month``: ISO date or datetime (``YYYY-MM-DD[...]``) or ``YYYY/MM/DD``.
* ``age_band``: non-negative number -> ``"30-39"`` (band_size 10); ``>= max_age`` -> ``"120+"``.
* ``round_coordinates``: number within [-180, 180] rounded to ``decimals`` (type preserved).
* ``numeric_bin``: number -> ``"<a"``, ``"[a, b)"`` or ``">=z"`` using the configured edges.

Values that do not fit the strategy raise ``TransformError`` (fail closed; no partial guessing).
"""

from __future__ import annotations

import datetime as dt
import itertools
import math
import re
from typing import Any

from ciphergate.errors import TransformError
from ciphergate.models.policy import GeneralizeParams

_DATE_PREFIX = re.compile(r"^(\d{4})[-/](\d{2})[-/](\d{2})(?:$|[T ])")
YEAR_RE = re.compile(r"^\d{4}$")
YEAR_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
AGE_BAND_RE = re.compile(r"^\d+-\d+$|^\d+\+$")


def _fail(strategy: str) -> TransformError:
    return TransformError(
        f"generalize ({strategy}) cannot be applied to a value of this shape",
        code="generalize_unsupported_value",
    )


def _number(value: Any, strategy: str) -> float:
    if isinstance(value, bool):
        raise _fail(strategy)
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            raise _fail(strategy) from None
    else:
        raise _fail(strategy)
    if not math.isfinite(number):
        raise _fail(strategy)
    return number


def _fmt(number: float) -> str:
    return f"{number:g}"


def generalize(value: Any, params: GeneralizeParams) -> Any:
    strategy = params.strategy
    if strategy in ("year", "year_month"):
        if not isinstance(value, str):
            raise _fail(strategy)
        m = _DATE_PREFIX.match(value.strip())
        if not m:
            raise _fail(strategy)
        try:
            dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            raise _fail(strategy) from None
        return m.group(1) if strategy == "year" else f"{m.group(1)}-{m.group(2)}"
    if strategy == "age_band":
        age = _number(value, strategy)
        if age < 0:
            raise _fail(strategy)
        if age >= params.max_age:
            return f"{params.max_age}+"
        low = int(age // params.band_size) * params.band_size
        return f"{low}-{min(low + params.band_size - 1, params.max_age - 1)}"
    if strategy == "round_coordinates":
        coordinate = _number(value, strategy)
        if abs(coordinate) > 180:
            raise _fail(strategy)
        rounded = round(coordinate, params.decimals)
        if isinstance(value, str):
            return f"{rounded:.{params.decimals}f}"
        return rounded
    if strategy == "numeric_bin":
        number = _number(value, strategy)
        edges = params.bins or []
        if number < edges[0]:
            return f"<{_fmt(edges[0])}"
        for lo, hi in itertools.pairwise(edges):
            if lo <= number < hi:
                return f"[{_fmt(lo)}, {_fmt(hi)})"
        return f">={_fmt(edges[-1])}"
    raise TransformError("unsupported generalize strategy", code="unsupported_transform")


def matches_generalized_shape(text: str, params: GeneralizeParams) -> bool:
    """Used by rescan: does this text already look like this strategy's output?"""
    if params.strategy == "year":
        return bool(YEAR_RE.match(text))
    if params.strategy == "year_month":
        return bool(YEAR_MONTH_RE.match(text))
    if params.strategy == "age_band":
        return bool(AGE_BAND_RE.match(text))
    if params.strategy == "numeric_bin":
        return text.startswith(("<", "[", ">="))
    return False
