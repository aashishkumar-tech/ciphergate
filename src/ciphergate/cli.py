"""``ciphergate`` command-line interface.

Output contract: human summaries go to stdout (suppressed by ``--quiet``); when ``--report-format
json`` is used without ``--report``, stdout carries only the JSON report. Errors go to stderr as
``error[<code>]: <safe message>``. Exit codes are documented in README.md and ``ExitCode``.

``-`` as INPUT reads stdin (``--format`` required); ``sanitize --output -`` writes the sanitized
data to stdout only after the run succeeded, and the summary then goes to stderr so stdout
carries data only. See ``ciphergate.pipeline.stdio``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import sys
import traceback
from collections.abc import Callable
from enum import StrEnum
from importlib import resources
from pathlib import Path
from types import FrameType
from typing import Annotated, Any, TextIO

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
    UnsafePathError,
    UsageError,
)
from ciphergate.models.context import ContextInput
from ciphergate.models.finding import Finding, Location
from ciphergate.models.report import RunReport
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.pipeline.batch import (
    BatchReport,
    analyze_directory,
    is_inside,
    sanitize_directory,
)
from ciphergate.pipeline.paths import validate_output_path
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.pipeline.stdio import (
    STDIN_DISPLAY,
    STDOUT_DISPLAY,
    StdioWorkspace,
    copy_to_stdout,
    is_stdio,
    require_stdin_format,
    silence_stdout,
)
from ciphergate.policy.context import evaluate_gates, resolve_context
from ciphergate.policy.engine import PolicyEngine
from ciphergate.policy.templates import read_template, template_names
from ciphergate.policy.validator import load_policy, validate_policy
from ciphergate.reporting.safe_text import escape_control
from ciphergate.reporting.serializer import (
    batch_report_to_json,
    report_to_json,
    write_batch_report_file,
    write_report_file,
)
from ciphergate.reporting.terminal import render_batch_summary, render_summary

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
RecursiveOpt = Annotated[
    bool,
    typer.Option("--recursive", "-r", help="With a directory INPUT, also process subdirectories."),
]
MaxFilesOpt = Annotated[
    int | None,
    typer.Option("--max-files", min=1, help="Maximum files in a directory run (default 1000)."),
]


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
    max_bytes: int | None,
    encoding: str | None,
    path_display: PathDisplayChoice | None,
    max_files: int | None = None,
) -> RuntimeSettings:
    try:
        return RuntimeSettings().with_overrides(
            max_input_bytes=max_bytes,
            encoding=encoding,
            path_display=str(path_display) if path_display else None,
            max_batch_files=max_files,
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
    except BrokenPipeError:
        silence_stdout()
        _err("error[stdout_broken_pipe]: stdout was closed before all output was written")
        raise typer.Exit(int(ExitCode.OUTPUT_ERROR)) from None
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
    summary_stream: TextIO | None = None,
) -> int:
    summary = summary_stream or sys.stdout
    if report_path is not None:
        write_report_file(report, report_path, str(report_format or ReportFormat.JSON), force=force)
        if not quiet:
            summary.write(render_summary(report, verbose=verbose))
    elif report_format == ReportFormat.JSON:
        sys.stdout.write(report_to_json(report))
    elif not quiet:
        summary.write(render_summary(report, verbose=verbose))
    return report.exit_code


def _emit_batch(
    report: BatchReport,
    *,
    report_path: Path | None,
    report_format: ReportFormat | None,
    quiet: bool,
    verbose: bool,
    force: bool,
) -> int:
    if report_path is not None:
        write_batch_report_file(
            report, report_path, str(report_format or ReportFormat.JSON), force=force
        )
        if not quiet:
            sys.stdout.write(render_batch_summary(report, verbose=verbose))
    elif report_format == ReportFormat.JSON:
        sys.stdout.write(batch_report_to_json(report))
    elif not quiet:
        sys.stdout.write(render_batch_summary(report, verbose=verbose))
    return report.exit_code


def _is_directory_input(path: Path) -> bool:
    return not is_stdio(path) and os.path.isdir(path)


def _check_batch_report_path(report: Path | None, directories: list[Path], force: bool) -> None:
    _check_report_path(report, [], force)
    if report is not None and any(is_inside(report, d) for d in directories):
        raise UnsafePathError(
            "--report must not be inside the input or output directory",
            code="report_inside_batch_directory",
        )


def _no_recursive(recursive: bool) -> None:
    if recursive:
        raise UsageError("--recursive needs a directory INPUT", code="recursive_needs_directory")


def _check_report_path(report: Path | None, protected: list[Path], force: bool) -> None:
    if report is None:
        return
    if is_stdio(report):
        raise UsageError(
            "--report - is not supported; omit --report and pass --report-format json "
            "to print the JSON report on stdout",
            code="report_stdout_unsupported",
        )
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
    template: Annotated[
        str | None,
        typer.Option("--template", "-t", help="Named template (see --list-templates)."),
    ] = None,
    list_templates: Annotated[
        bool, typer.Option("--list-templates", help="List named templates and exit.")
    ] = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Write a starter policy template (it MUST be reviewed before real use)."""

    def body() -> int:
        if list_templates:
            sys.stdout.write("".join(f"{name}\n" for name in template_names()))
            return 0
        text = (
            read_template(template)
            if template is not None
            else resources.files("ciphergate")
            .joinpath("templates/starter_policy.yml")
            .read_text(encoding="utf-8")
        )
        validate_output_path(output, protected=[], force=force, label="policy")
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
    recursive: bool = False,
) -> int:
    if _is_directory_input(input_path):
        _check_batch_report_path(report, [input_path], force)
        batch = analyze_directory(
            command,
            input_path,
            load_policy(policy),
            ctx,
            recursive=recursive,
            runtime=runtime,
            fmt=fmt,
            strict=strict,
        )
        return _emit_batch(
            batch,
            report_path=report,
            report_format=report_format,
            quiet=quiet,
            verbose=verbose,
            force=force,
        )
    _no_recursive(recursive)
    stdin = is_stdio(input_path)
    if stdin:
        fmt = require_stdin_format(fmt, sys.stdin.buffer)
    _check_report_path(report, [] if stdin else [input_path], force)
    loaded = load_policy(policy)
    with StdioWorkspace() if stdin else contextlib.nullcontext() as ws:
        path = input_path
        if ws is not None and fmt is not None:
            path = ws.spool_input(sys.stdin.buffer, fmt, runtime.max_input_bytes)
        if command == "inspect":
            result = inspect_file(path, loaded, ctx, runtime=runtime, fmt=fmt)
        elif command == "plan":
            result = plan_file(path, loaded, ctx, runtime=runtime, fmt=fmt)
        else:
            result = rescan_file(path, loaded, ctx, strict=strict, runtime=runtime, fmt=fmt)
    if stdin:
        result.input["path"] = STDIN_DISPLAY
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
    input_path: Annotated[
        Path, typer.Argument(metavar="INPUT", help="File to inspect, a directory, or - for stdin.")
    ],
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
    recursive: RecursiveOpt = False,
    max_files: MaxFilesOpt = None,
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
            _runtime(max_bytes, encoding, path_display, max_files),
            quiet,
            verbose,
            force,
            recursive=recursive,
        ),
    )


@app.command("plan")
def plan_command(
    input_path: Annotated[
        Path, typer.Argument(metavar="INPUT", help="File to plan for, a directory, or - for stdin.")
    ],
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
    recursive: RecursiveOpt = False,
    max_files: MaxFilesOpt = None,
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
            _runtime(max_bytes, encoding, path_display, max_files),
            quiet,
            verbose,
            force,
            recursive=recursive,
        ),
    )


@app.command("sanitize")
def sanitize_command(
    input_path: Annotated[
        Path, typer.Argument(metavar="INPUT", help="File or directory to sanitize, or - for stdin.")
    ],
    policy: PolicyOpt,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output file (a new directory for a directory INPUT), or - for stdout.",
        ),
    ],
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
    recursive: RecursiveOpt = False,
    max_files: MaxFilesOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Apply the policy and atomically write OUTPUT. Requires --apply; refuses to overwrite."""
    _configure_logging(verbose, debug)

    def body() -> int:
        if _is_directory_input(input_path):
            return sanitize_batch()
        _no_recursive(recursive)
        stdin, to_stdout = is_stdio(input_path), is_stdio(output)
        selected_fmt = require_stdin_format(fmt, sys.stdin.buffer) if stdin else fmt
        if to_stdout and report is None and report_format == ReportFormat.JSON:
            raise UsageError(
                "--output - uses stdout for data; write the JSON report with --report PATH",
                code="stdout_conflict",
            )
        runtime = _runtime(max_bytes, encoding, path_display)
        _check_report_path(report, [p for p in (input_path, output) if not is_stdio(p)], force)
        loaded = load_policy(policy)
        options = SanitizeOptions(apply=apply, force=force, format=selected_fmt, runtime=runtime)
        with StdioWorkspace() if stdin or to_stdout else contextlib.nullcontext() as ws:
            in_path, out_path = input_path, output
            if ws is not None and stdin and selected_fmt is not None:
                in_path = ws.spool_input(sys.stdin.buffer, selected_fmt, runtime.max_input_bytes)
            if ws is not None and to_stdout:
                out_path = ws.output_path()
            result = sanitize_file(
                in_path,
                out_path,
                loaded,
                _context(environment, target_environment, destination, use_case, profile),
                options,
            )
            if stdin:
                result.input["path"] = STDIN_DISPLAY
            if to_stdout:
                result.output["path"] = STDOUT_DISPLAY
                if result.output.get("written"):
                    copy_to_stdout(out_path, sys.stdout.buffer)
        try:
            code = _emit(
                result,
                report_path=report,
                report_format=report_format,
                quiet=quiet,
                verbose=verbose,
                force=force,
                summary_stream=sys.stderr if to_stdout else None,
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
            (sys.stderr if to_stdout else sys.stdout).write(
                "  (dry run: pass --apply to write the sanitized output)\n"
            )
        return code

    def sanitize_batch() -> int:
        if is_stdio(output):
            raise UsageError(
                "a directory INPUT needs --output DIR, not stdout", code="stdout_unsupported"
            )
        runtime = _runtime(max_bytes, encoding, path_display, max_files)
        _check_batch_report_path(report, [input_path, output], force)
        batch = sanitize_directory(
            input_path,
            output,
            load_policy(policy),
            _context(environment, target_environment, destination, use_case, profile),
            SanitizeOptions(apply=apply, force=force, format=fmt, runtime=runtime),
            recursive=recursive,
        )
        code = _emit_batch(
            batch,
            report_path=report,
            report_format=report_format,
            quiet=quiet,
            verbose=verbose,
            force=force,
        )
        if not apply and not quiet and report_format != ReportFormat.JSON:
            sys.stdout.write("  (dry run: pass --apply to write the sanitized output)\n")
        return code

    _guard(debug, body)


@app.command("rescan")
def rescan_command(
    input_path: Annotated[
        Path,
        typer.Argument(
            metavar="INPUT", help="Sanitized file to rescan, a directory, or - for stdin."
        ),
    ],
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
    recursive: RecursiveOpt = False,
    max_files: MaxFilesOpt = None,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verbose: VerboseOpt = False,
    no_color: NoColorOpt = False,
    debug: DebugOpt = False,
) -> None:
    """Report residual findings in an existing output. Read-only; never alters the file.

    No gating findings does not mean the output is safe: rescan only sees what detectors match.
    """
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
            _runtime(max_bytes, encoding, path_display, max_files),
            quiet,
            verbose,
            force,
            strict,
            recursive=recursive,
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
