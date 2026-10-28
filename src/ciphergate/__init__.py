"""CipherGate: local-first, environment- and destination-aware data inspection and sanitization.

Supported public API (everything else is internal and may change without notice)::

    load_policy(path) -> Policy
    validate_policy(path_or_policy) -> ValidationResult
    inspect_file(path, policy, context=None) -> RunReport
    plan_file(path, policy, context=None) -> RunReport
    sanitize_file(input_path, output_path, policy, context=None, options=None) -> RunReport
    rescan_file(path, policy, context=None, strict=None) -> RunReport
"""

__version__ = "0.1.0a1"

from ciphergate.config import RuntimeSettings
from ciphergate.constants import (
    Destination,
    DomainProfile,
    Environment,
    InputFormat,
    TargetEnvironment,
    UseCase,
)
from ciphergate.models.context import ContextInput
from ciphergate.models.report import RunReport, RunStatus
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.policy.validator import (
    Policy,
    ValidationResult,
    load_policy,
    validate_policy,
)

__all__ = [
    "ContextInput",
    "Destination",
    "DomainProfile",
    "Environment",
    "InputFormat",
    "Policy",
    "RunReport",
    "RunStatus",
    "RuntimeSettings",
    "SanitizeOptions",
    "TargetEnvironment",
    "UseCase",
    "ValidationResult",
    "__version__",
    "inspect_file",
    "load_policy",
    "plan_file",
    "rescan_file",
    "sanitize_file",
    "validate_policy",
]
