"""Heuristic checks for user-supplied regular expressions.

Python's ``re`` engine backtracks, so a pathological pattern can take exponential time. These checks
reject common risky constructs (nested quantifiers, backreferences, empty matches,
excessive length).
They are heuristics, NOT a proof of regex safety; inputs are additionally bounded by record limits.
"""

from __future__ import annotations

import re

MAX_PATTERN_LENGTH = 512

_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[*+}](?:[^()\\]|\\.)*\)\s*(?:[*+]|\{\d*,)")
_BACKREFERENCE = re.compile(r"\\[1-9]|\(\?P=")
_UNBOUNDED_WILDCARD_RUN = re.compile(r"(?:\.\*|\.\+)(?:[^()]*)(?:\.\*|\.\+)")


def regex_problems(pattern: str, *, strict: bool = True) -> list[str]:
    """Return a list of safe problem descriptions (never echoes the pattern)."""
    problems: list[str] = []
    if len(pattern) > MAX_PATTERN_LENGTH:
        problems.append(f"pattern longer than {MAX_PATTERN_LENGTH} characters")
        return problems
    try:
        compiled = re.compile(pattern)
    except re.error:
        problems.append("pattern does not compile")
        return problems
    if compiled.search("") is not None:
        problems.append("pattern can match the empty string")
    if strict:
        if _NESTED_QUANTIFIER.search(pattern):
            problems.append("nested quantifier (risk of catastrophic backtracking)")
        if _BACKREFERENCE.search(pattern):
            problems.append("backreferences are not allowed")
        if _UNBOUNDED_WILDCARD_RUN.search(pattern):
            problems.append("multiple unbounded wildcards (risk of excessive backtracking)")
    return problems
