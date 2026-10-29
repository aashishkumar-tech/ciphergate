"""Exception hierarchy with stable error codes and safe messages.

Messages are always authored by CipherGate and must never contain input values, matched text,
key material, or third-party parser excerpts. Callers chain the original exception with
``raise ... from exc`` only when it is needed for debugging; the CLI never renders chained messages.
"""

from __future__ import annotations

from dataclasses import dataclass

from ciphergate.constants import ExitCode


class CipherGateError(Exception):
    """Base class. ``code`` is a stable identifier; ``message`` is safe to display."""

    default_code = "ciphergate_error"
    exit_code: ExitCode = ExitCode.INTERNAL

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or self.default_code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class UsageError(CipherGateError):
    default_code = "usage_error"
    exit_code = ExitCode.USAGE


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single policy validation problem: a location in the policy plus a safe message."""

    location: str
    message: str
    code: str = "invalid_value"

    def render(self) -> str:
        return f"{self.location}: {self.message} [{self.code}]"


class PolicyValidationError(CipherGateError):
    default_code = "policy_invalid"
    exit_code = ExitCode.POLICY_INVALID

    def __init__(
        self, message: str, *, issues: list[ValidationIssue] | None = None, code: str | None = None
    ) -> None:
        super().__init__(message, code=code)
        self.issues = list(issues or [])


class ContextError(CipherGateError):
    """Required context is missing, unsupported, or conflicts with a policy-pinned value."""

    default_code = "context_error"
    exit_code = ExitCode.BLOCKED


class InputFormatError(CipherGateError):
    default_code = "input_format_error"
    exit_code = ExitCode.INPUT_ERROR


class InputLimitError(CipherGateError):
    default_code = "size_limit_exceeded"
    exit_code = ExitCode.INPUT_ERROR


class DetectionError(CipherGateError):
    default_code = "detection_error"
    exit_code = ExitCode.INPUT_ERROR


class DetectorUnavailableError(CipherGateError):
    """An optional detector is enabled by the policy but cannot be used (never skipped)."""

    default_code = "detector_unavailable"
    exit_code = ExitCode.KEY_OR_TRANSFORM_CONFIG


class UnsafePathError(CipherGateError):
    default_code = "unsafe_path"
    exit_code = ExitCode.OUTPUT_ERROR


class OutputWriteError(CipherGateError):
    default_code = "output_write_error"
    exit_code = ExitCode.OUTPUT_ERROR


class MissingKeyError(CipherGateError):
    default_code = "key_missing"
    exit_code = ExitCode.KEY_OR_TRANSFORM_CONFIG


class TransformError(CipherGateError):
    default_code = "transform_error"
    exit_code = ExitCode.KEY_OR_TRANSFORM_CONFIG


class PolicyBlockedError(CipherGateError):
    default_code = "policy_blocked"
    exit_code = ExitCode.BLOCKED


class RescanFailedError(CipherGateError):
    default_code = "rescan_failed"
    exit_code = ExitCode.RESCAN_FAILED


class InternalError(CipherGateError):
    default_code = "internal_error"
    exit_code = ExitCode.INTERNAL
