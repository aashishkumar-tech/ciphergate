"""CipherGate: local-first, environment- and destination-aware data inspection and sanitization.

Supported public API (everything else is internal and may change without notice)::

    load_policy(path) -> Policy
    load_template(name) -> Policy        # a packaged template; review it before relying on it
    template_names() -> list[str]
    validate_policy(path_or_policy) -> ValidationResult
    inspect_file(path, policy, context=None) -> RunReport
    plan_file(path, policy, context=None) -> RunReport
    sanitize_file(input_path, output_path, policy, context=None, options=None) -> RunReport
    rescan_file(path, policy, context=None, strict=None) -> RunReport

    # binary streams (format required; output written only after a successful run)
    inspect_stream(stream, policy, context=None, *, fmt) -> RunReport
    plan_stream(stream, policy, context=None, *, fmt) -> RunReport
    sanitize_stream(stream, output, policy, context=None, options=None) -> RunReport
    rescan_stream(stream, policy, context=None, *, fmt, strict=None) -> RunReport

    # directories (links never followed; sanitize publishes a new directory all-or-nothing)
    inspect_directory(root, policy, context=None, *, recursive=False) -> BatchReport
    plan_directory(root, policy, context=None, *, recursive=False) -> BatchReport
    sanitize_directory(root, output_dir, policy, context=None, options=None, *, recursive=False)
    rescan_directory(root, policy, context=None, *, recursive=False, strict=None) -> BatchReport
"""

__version__ = "0.8.0"

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
from ciphergate.pipeline.batch import (
    BatchReport,
    inspect_directory,
    plan_directory,
    rescan_directory,
    sanitize_directory,
)
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.pipeline.streams import (
    inspect_stream,
    plan_stream,
    rescan_stream,
    sanitize_stream,
)
from ciphergate.policy.templates import load_template, template_names
from ciphergate.policy.validator import (
    Policy,
    ValidationResult,
    load_policy,
    validate_policy,
)

__all__ = [
    "BatchReport",
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
    "inspect_directory",
    "inspect_file",
    "inspect_stream",
    "load_policy",
    "load_template",
    "plan_directory",
    "plan_file",
    "plan_stream",
    "rescan_directory",
    "rescan_file",
    "rescan_stream",
    "sanitize_directory",
    "sanitize_file",
    "sanitize_stream",
    "template_names",
    "validate_policy",
]
