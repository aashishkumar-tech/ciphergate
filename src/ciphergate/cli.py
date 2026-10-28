"""``ciphergate`` command-line interface.

Output contract: human summaries go to stdout (suppressed by ``--quiet``); when ``--report-format
json`` is used without ``--report``, stdout carries only the JSON report. Errors go to stderr as
``error[<code>]: <safe message>``. Exit codes are documented in README.md and ``ExitCode``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import signal
import sys
import traceback
from collections.abc import Callable
from enum import StrEnum
from importlib import resources
from pathlib import Path
from types import FrameType
from typing import Annotated, Any

import typer

from ciphergate import __version__
from ciphergate.config import RuntimeSettings
from ciphergate.constants import (
    Destination,
    DomainProfile,
    Environment,
    ExitCode,
    InputFormat,
    TargetEnvironment,
    UseCase,
)
from ciphergate.errors import (
    CipherGateError,
    OutputWriteError,
    PolicyValidationError,
    UsageError,
)
from ciphergate.models.context import ContextInput
from ciphergate.models.finding import Finding, Location
from ciphergate.models.report import RunReport
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.pipeline.paths import validate_output_path
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.policy.context import evaluate_gates, resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.validator import load_policy, validate_policy
from ciphergate.reporting.safe_text import escape_control
from ciphergate.reporting.serializer import report_to_json, write_report_file
from ciphergate.reporting.terminal import render_summary

logger = logging.getLogger("ciphergate")

app = typer.Typer(
    name="ciphergate",
    help="Inspect and sanitize logs and test datasets before they leave their environment.\n\n"
    "Workflow: validate-policy -> inspect -> plan -> sanitize --apply -> rescan. "
    "A passing run is not proof that no sensitive data remains.",
    add_completion=False,
    no_args_is_help=True,
    # Rich tracebacks can print local variables (i.e. data). Never enable them.
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


class ReportFormat(StrEnum):
    JSON = "json"
    TEXT = "text"


class PathDisplayChoice(StrEnum):
    BASENAME = "basename"
    REDACTED = "redacted"
    FULL = "full"


# --------------------------------------------------------------------------- shared options

PolicyOpt = Annotated[Path, typer.Option("--policy", "-p", help="Policy YAML file.")]
FormatOpt = Annotated[
    InputFormat | None, typer.Option("--format", help="Input format (default: from extension).")
]
ReportOpt = Annotated[
    Path | None, typer.Option("--report", help="Write the privacy-safe report to this file.")
]
ReportFormatOpt = Annotated[
    ReportFormat | None,
    typer.Option("--report-format", help="Report format: json or text (default json for files)."),
]
EnvOpt = Annotated[
    Environment | None,
    typer.Option(
        "--environment",
        "--source-environment",
        help="Where the source data came from (dev|stg|prd|unknown). Declared, not verified.",
    ),
]
TargetOpt = Annotated[
    TargetEnvironment | None,
    typer.Option("--target-environment", help="Environment receiving the output."),
]
DestOpt = Annotated[
    Destination | None,
    typer.Option("--destination", help="Recipient/channel of the output (distinct from env)."),
]
UseCaseOpt = Annotated[UseCase | None, typer.Option("--use-case", help="Purpose of the output.")]
ProfileOpt = Annotated[
    DomainProfile | None, typer.Option("--profile", help="Domain profile of the data.")
]
MaxBytesOpt = Annotated[
    int | None, typer.Option("--max-bytes", min=1, help="Maximum input size in bytes.")
]
EncodingOpt = Annotated[
    str | None, typer.Option("--encoding", help="Input encoding (ASCII-compatible; default utf-8).")
]
PathDisplayOpt = Annotated[
    PathDisplayChoice | None,
    typer.Option("--path-display", help="How file paths appear in reports (default basename)."),
]
QuietOpt = Annotated[bool, typer.Option("--quiet", "-q", help="No summary on stdout.")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="List every reported item.")]
NoColorOpt = Annotated[bool, typer.Option("--no-color", help="Accepted for CI; output is plain.")]
DebugOpt = Annotated[
    bool, typer.Option("--debug", help="On internal errors show frames (never values/messages).")
]
ForceOpt = Annotated[bool, typer.Option("--force", help="Replace an existing output/report file.")]


def _context(
    environment: Environment | None,
    target: TargetEnvironment | None,
    destination: Destination | None,
    use_case: UseCase | None,
    profile: DomainProfile | None,
) -> ContextInput:
    return ContextInput(
        environment=environment,
        target_environment=target,
        destination=destination,
        domain_profile=profile,
        use_case=use_case,
    )


def _runtime(
    max_bytes: int | None, encoding: str | None, path_display: PathDisplayChoice | None
) -> RuntimeSettings:
    try:
        return RuntimeSettings().with_overrides(
            max_input_bytes=max_bytes,
            encoding=encoding,
            path_display=str(path_display) if path_display else None,
        )
    except ValueError as exc:
        raise UsageError(str(exc), code="invalid_runtime_setting") from None


def _err(message: str) -> None:
    sys.stderr.write(escape_control(message)[:2000] + "\n")


def _safe_traceback(exc: BaseException) -> str:
    frames = traceback.extract_tb(exc.__traceback__)
    lines = [f"  {Path(f.filename).name}:{f.lineno} in {f.name}" for f in frames]
    return f"{type(exc).__name__} (message suppressed)\n" + "\n".join(lines)


def _guard(debug: bool, body: Callable[[], int]) -> None:
    try:
        code = body()
    except PolicyValidationError as exc:
        _err(f"error[{exc.code}]: {exc.message}")
        for issue in exc.issues:
            _err(f"  - {issue.render()}")
        raise typer.Exit(int(exc.exit_code)) from None
    except CipherGateError as exc:
        _err(f"error[{exc.code}]: {exc.message}")
        raise typer.Exit(int(exc.exit_code)) from None
    except KeyboardInterrupt:
        _err("error[interrupted]: operation interrupted; no output was published")
        raise typer.Exit(int(ExitCode.INTERRUPTED)) from None
    except (typer.Exit, typer.Abort):
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort safe rendering
        _err("error[internal_error]: unexpected internal error (no data was published)")
        if debug:
            _err(_safe_traceback(exc))
        raise typer.Exit(int(ExitCode.INTERNAL)) from None
    raise typer.Exit(code)


def _emit(
    report: RunReport,
    *,
    report_path: Path | None,
    report_format: ReportFormat | None,
    quiet: bool,
    verbose: bool,
    force: bool,
) -> int:
    if report_path is not None:
        write_report_file(report, report_path, str(report_format or ReportFormat.JSON), force=force)
        if not quiet:
            sys.stdout.write(render_summary(report, verbose=verbose))
    elif report_format == ReportFormat.JSON:
        sys.stdout.write(report_to_json(report))
    elif not quiet:
        sys.stdout.write(render_summary(report, verbose=verbose))
    return report.exit_code


def _check_report_path(report: Path | None, protected: list[Path], force: bool) -> None:
    if report is not None:
        validate_output_path(report, protected=protected, force=force, label="report")


def _configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level, format="ciphergate: %(levelname)s: %(message)s", stream=sys.stderr
    )


# --------------------------------------------------------------------------- commands


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(f"ciphergate {__version__}\n")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """CipherGate CLI."""


@app.command("init")
def init_command(
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write the policy.")
    ] = Path("ciphergate-policy.yml"),
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Write a starter policy template (it MUST be reviewed before real use)."""

    def body() -> int:
        validate_output_path(output, protected=[], force=force, label="policy")
        text = (
            resources.files("ciphergate")
            .joinpath("templates/starter_policy.yml")
            .read_text(encoding="utf-8")
        )
        with AtomicOutput(output, force=force) as out:
            out.stream.write(text)
            out.publish()
        if not quiet:
            sys.stdout.write(
                f"wrote starter policy to {escape_control(output.name)}\n"
                "WARNING: this is a template. Review every rule, context value and destination "
                "for your data before relying on it. It is not legal or compliance advice.\n"
            )
        return 0

    _guard(debug, body)


@app.command("validate-policy")
def validate_policy_command(
    policy: Annotated[Path, typer.Argument(help="Policy YAML file.")],
    report_format: ReportFormatOpt = None,
    quiet: QuietOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Validate a policy's schema and semantics. Never reads any dataset."""

    def body() -> int:
        result = validate_policy(policy)
        if report_format == ReportFormat.JSON:
            payload: dict[str, Any] = {
                "valid": result.valid,
                "policy": result.policy.name if result.policy else None,
                "digest": result.policy.digest if result.policy else None,
                "errors": [
                    {"location": i.location, "message": i.message, "code": i.code}
                    for i in result.errors
                ],
                "warnings": list(result.warnings),
            }
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        elif result.valid and result.policy is not None:
            if not quiet:
                sys.stdout.write(
                    f"policy '{escape_control(result.policy.name)}' is valid "
                    f"({result.policy.digest[:19]}...)\n"
                )
                for warning in result.warnings:
                    sys.stdout.write(f"  warning: {escape_control(warning)}\n")
        else:
            _err("error[policy_invalid]: policy failed validation")
            for issue in result.errors:
                _err(f"  - {issue.render()}")
        return 0 if result.valid else int(ExitCode.POLICY_INVALID)

    _guard(debug, body)


def _run_analysis_command(
    command: str,
    input_path: Path,
    policy: Path,
    fmt: InputFormat | None,
    report: Path | None,
    report_format: ReportFormat | None,
    ctx: ContextInput,
    runtime: RuntimeSettings,
    quiet: bool,
    verbose: bool,
    force: bool,
    strict: bool | None = None,
) -> int:
    _check_report_path(report, [input_path], force)
    loaded = load_policy(policy)
    if command == "inspect":
        result = inspect_file(input_path, loaded, ctx, runtime=runtime, fmt=fmt)
    elif command == "plan":
        result = plan_file(input_path, loaded, ctx, runtime=runtime, fmt=fmt)
    else:
        result = rescan_file(input_path, loaded, ctx, strict=strict, runtime=runtime, fmt=fmt)
    return _emit(
        result,
        report_path=report,
        report_format=report_format,
        quiet=quiet,
        verbose=verbose,
        force=force,
    )


@app.command("inspect")
def inspect_command(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="File to inspect.")],
    policy: PolicyOpt,
    fmt: FormatOpt = None,
    report: ReportOpt = None,
    report_format: ReportFormatOpt = None,
    environment: EnvOpt = None,
    target_environment: TargetOpt = None,
    destination: DestOpt = None,
    use_case: UseCaseOpt = None,
    profile: ProfileOpt = None,
    max_bytes: MaxBytesOpt = None,
    encoding: EncodingOpt = None,
    path_display: PathDisplayOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Detect and report findings. Never modifies the input or writes sanitized data."""
    _configure_logging(verbose, debug)
    _guard(
        debug,
        lambda: _run_analysis_command(
            "inspect",
            input_path,
            policy,
            fmt,
            report,
            report_format,
            _context(environment, target_environment, destination, use_case, profile),
            _runtime(max_bytes, encoding, path_display),
            quiet,
            verbose,
            force,
        ),
    )


@app.command("plan")
def plan_command(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="File to plan for.")],
    policy: PolicyOpt,
    fmt: FormatOpt = None,
    report: ReportOpt = None,
    report_format: ReportFormatOpt = None,
    environment: EnvOpt = None,
    target_environment: TargetOpt = None,
    destination: DestOpt = None,
    use_case: UseCaseOpt = None,
    profile: ProfileOpt = None,
    max_bytes: MaxBytesOpt = None,
    encoding: EncodingOpt = None,
    path_display: PathDisplayOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Preview the decisions sanitize --apply would make. Writes no data file."""
    _configure_logging(verbose, debug)
    _guard(
        debug,
        lambda: _run_analysis_command(
            "plan",
            input_path,
            policy,
            fmt,
            report,
            report_format,
            _context(environment, target_environment, destination, use_case, profile),
            _runtime(max_bytes, encoding, path_display),
            quiet,
            verbose,
            force,
        ),
    )


@app.command("sanitize")
def sanitize_command(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="File to sanitize.")],
    policy: PolicyOpt,
    output: Annotated[Path, typer.Option("--output", "-o", help="Sanitized output file.")],
    apply: Annotated[
        bool, typer.Option("--apply", help="Actually write output (else plan).")
    ] = False,
    fmt: FormatOpt = None,
    report: ReportOpt = None,
    report_format: ReportFormatOpt = None,
    environment: EnvOpt = None,
    target_environment: TargetOpt = None,
    destination: DestOpt = None,
    use_case: UseCaseOpt = None,
    profile: ProfileOpt = None,
    max_bytes: MaxBytesOpt = None,
    encoding: EncodingOpt = None,
    path_display: PathDisplayOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Apply the policy and atomically write OUTPUT. Requires --apply; refuses to overwrite."""
    _configure_logging(verbose, debug)

    def body() -> int:
        _check_report_path(report, [input_path, output], force)
        loaded = load_policy(policy)
        options = SanitizeOptions(
            apply=apply,
            force=force,
            format=fmt,
            runtime=_runtime(max_bytes, encoding, path_display),
        )
        result = sanitize_file(
            input_path,
            output,
            loaded,
            _context(environment, target_environment, destination, use_case, profile),
            options,
        )
        try:
            code = _emit(
                result,
                report_path=report,
                report_format=report_format,
                quiet=quiet,
                verbose=verbose,
                force=force,
            )
        except OutputWriteError as exc:
            if result.output.get("written"):
                # The report is written after publication; never let this look like no output.
                raise OutputWriteError(
                    "the sanitized output WAS published, but the report could not be written: "
                    + exc.message,
                    code=exc.code,
                ) from None
            raise
        if not apply and not quiet and report_format != ReportFormat.JSON:
            sys.stdout.write("  (dry run: pass --apply to write the sanitized output)\n")
        return code

    _guard(debug, body)


@app.command("rescan")
def rescan_command(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Sanitized file to rescan.")],
    policy: PolicyOpt,
    strict: Annotated[
        bool | None,
        typer.Option(
            "--strict/--no-strict",
            help="Fail (exit 7) on gating residuals (default: policy settings.strict).",
        ),
    ] = None,
    fmt: FormatOpt = None,
    report: ReportOpt = None,
    report_format: ReportFormatOpt = None,
    environment: EnvOpt = None,
    target_environment: TargetOpt = None,
    destination: DestOpt = None,
    use_case: UseCaseOpt = None,
    profile: ProfileOpt = None,
    max_bytes: MaxBytesOpt = None,
    encoding: EncodingOpt = None,
    path_display: PathDisplayOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Report residual findings in an existing output. Read-only; never alters the file."""
    _configure_logging(verbose, debug)
    _guard(
        debug,
        lambda: _run_analysis_command(
            "rescan",
            input_path,
            policy,
            fmt,
            report,
            report_format,
            _context(environment, target_environment, destination, use_case, profile),
            _runtime(max_bytes, encoding, path_display),
            quiet,
            verbose,
            force,
            strict,
        ),
    )


@app.command("explain")
def explain_command(
    policy: PolicyOpt,
    category: Annotated[str, typer.Option("--category", help="Category ID, e.g. pii.email.")],
    field: Annotated[str, typer.Option("--field", help="Field path, e.g. /user/email.")] = "",
    confidence: Annotated[float, typer.Option("--confidence", min=0.0, max=1.0)] = 0.9,
    detector: Annotated[str, typer.Option("--detector")] = "field_name",
    fmt: Annotated[InputFormat, typer.Option("--format")] = InputFormat.JSON,
    environment: EnvOpt = None,
    target_environment: TargetOpt = None,
    destination: DestOpt = None,
    use_case: UseCaseOpt = None,
    profile: ProfileOpt = None,
    debug: DebugOpt = False,
) -> None:
    """Explain the decision for a hypothetical finding (no data needed)."""

    def body() -> int:
        loaded = load_policy(policy)
        if category not in loaded.categories:
            raise UsageError("unknown category for this policy", code="unknown_category")
        ctx = resolve_context(
            loaded, _context(environment, target_environment, destination, use_case, profile)
        )
        field_name = field.rstrip("/").rsplit("/", 1)[-1] if field else None
        finding = Finding(
            category=category,
            detector=detector,
            confidence=confidence,
            evidence=("hypothetical",),
            field_name=field_name or None,
            value_type="string",
            location=Location(record_index=0, line=None, field_path=field),
        )
        decision = PolicyEngine(loaded).decide(finding, ctx, fmt)
        gates, approvals = evaluate_gates(loaded, ctx)
        payload = {
            "policy": loaded.name,
            "context": ctx.to_report(),
            "finding": {
                "category": category,
                "field_path": field,
                "confidence": confidence,
                "detector": detector,
                "format": str(fmt),
            },
            "decision": decision.to_dict(),
            "run_gates": [g.to_dict() for g in gates],
            "transfer_approvals": approvals,
        }
        # json.dumps escapes every control character (ensure_ascii), so this is terminal-safe.
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    _guard(debug, body)


def _sigterm_handler(signum: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    with contextlib.suppress(ValueError, OSError, AttributeError):
        signal.signal(signal.SIGTERM, _sigterm_handler)
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
