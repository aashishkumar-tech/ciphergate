"""Directory (batch) processing: one run over every supported file below a directory.

Safety contract:

* Discovery never follows symlinks, junctions or other reparse points, and never reads special
  files (devices, FIFOs, sockets); each skipped entry is reported with a reason. Subdirectories
  are entered only with ``recursive``; nesting is bounded by ``MAX_BATCH_DEPTH`` and the number
  of files by ``RuntimeSettings.max_batch_files`` (exceeding either fails the whole run).
* Files are processed in sorted relative-path order, each exactly as the single-file command
  would process it. A failing file does not stop the others, so the report is complete.
* ``sanitize`` builds the whole output tree in a private staging directory next to the output
  directory and publishes it with one rename only when **every** file was sanitized. Otherwise
  the staging tree is deleted and no output directory appears. The output directory must not
  exist yet and must not be inside the input directory.
* The batch exit code is that of the first failing file in processing order (0 if none).
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ciphergate import __version__
from ciphergate.config import RuntimeSettings
from ciphergate.constants import DISCLAIMER, ExitCode, InputFormat
from ciphergate.errors import (
    CipherGateError,
    InputFormatError,
    InputLimitError,
    OutputWriteError,
    UnsafePathError,
    UsageError,
)
from ciphergate.models.context import ContextInput
from ciphergate.models.report import RunReport
from ciphergate.pipeline.sanitizer import (
    SanitizeOptions,
    inspect_file,
    plan_file,
    rescan_file,
    sanitize_file,
)
from ciphergate.policy.validator import Policy
from ciphergate.readers import EXTENSION_FORMATS
from ciphergate.reporting.audit import new_run_id, utc_now

logger = logging.getLogger("ciphergate")

BATCH_REPORT_SCHEMA = "ciphergate.batch-report/v1"
MAX_BATCH_DEPTH = 32
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT (symlinks, junctions, mount points)


@dataclass(frozen=True)
class Discovery:
    root: Path
    files: list[Path]  # relative to root, sorted
    skipped: list[tuple[Path, str]]  # (relative path, reason code)


@dataclass
class FileResult:
    relative: Path
    display: str
    exit_code: int
    report: RunReport | None = None
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"path": self.display, "exit_code": self.exit_code}
        if self.report is not None:
            entry["status"] = str(self.report.status)
            entry["report"] = self.report.to_dict()
        else:
            entry["status"] = "error"
            entry["error"] = {"code": self.error_code, "message": self.error_message}
        return entry


@dataclass
class BatchReport:
    command: str
    input_display: str
    recursive: bool
    files: list[FileResult]
    skipped: list[dict[str, str]]
    output: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    run_id: str = field(default_factory=new_run_id)
    timestamp: str = field(default_factory=utc_now)

    @property
    def exit_code(self) -> int:
        for result in self.files:
            if result.exit_code != 0:
                return result.exit_code
        return 0

    @property
    def status(self) -> str:
        return "completed" if self.exit_code == 0 else "failed"

    def summary(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        findings = blocked = review = 0
        for result in self.files:
            key = str(result.report.status) if result.report is not None else "error"
            by_status[key] = by_status.get(key, 0) + 1
            if result.report is not None:
                findings += int(result.report.summary.get("findings_total", 0))
                blocked += int(result.report.summary.get("blocked", 0))
                review += int(result.report.summary.get("review_required", 0))
        return {
            "files_total": len(self.files),
            "files_ok": sum(1 for r in self.files if r.exit_code == 0),
            "files_failed": sum(1 for r in self.files if r.exit_code != 0),
            "files_skipped": len(self.skipped),
            "by_status": dict(sorted(by_status.items())),
            "findings_total": findings,
            "blocked": blocked,
            "review_required": review,
        }

    def to_dict(self) -> dict[str, Any]:
        first = next((r.report for r in self.files if r.report is not None), None)
        return {
            "schema": BATCH_REPORT_SCHEMA,
            "command": self.command,
            "status": self.status,
            "exit_code": self.exit_code,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "ciphergate_version": __version__,
            "input": {"path": self.input_display, "recursive": self.recursive},
            "policy": first.policy if first is not None else None,
            "context": first.context if first is not None else None,
            "summary": self.summary(),
            "files": [r.to_dict() for r in self.files],
            "skipped": self.skipped,
            "output": self.output,
            "warnings": self.warnings,
            "disclaimer": DISCLAIMER,
        }


# --------------------------------------------------------------------------- discovery


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    is_junction = getattr(entry, "is_junction", None)
    if is_junction is not None and is_junction():
        return True
    if sys.platform == "win32":
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & _REPARSE_POINT)
    return False


def discover(root: Path, *, recursive: bool, fmt: InputFormat | None, max_files: int) -> Discovery:
    """List the files a batch run will process. Raises on limits; never follows links."""
    try:
        st = os.lstat(root)
    except OSError:
        raise UnsafePathError(
            "input directory cannot be accessed", code="input_unreadable"
        ) from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(
            "batch input must be a real directory, not a symlink", code="input_not_directory"
        )
    files: list[Path] = []
    skipped: list[tuple[Path, str]] = []

    def walk(rel_dir: Path, depth: int) -> None:
        try:
            with os.scandir(root / rel_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            skipped.append((rel_dir, "directory_unreadable"))
            return
        for entry in entries:
            rel = rel_dir / entry.name
            try:
                if _is_link(entry):
                    skipped.append((rel, "symlink_not_followed"))
                elif entry.is_dir(follow_symlinks=False):
                    if not recursive:
                        skipped.append((rel, "directory_not_recursed"))
                    elif depth >= MAX_BATCH_DEPTH:
                        raise InputLimitError(
                            f"directory nesting exceeds {MAX_BATCH_DEPTH} levels",
                            code="batch_depth_exceeded",
                        )
                    else:
                        walk(rel, depth + 1)
                elif not entry.is_file(follow_symlinks=False):
                    skipped.append((rel, "not_regular_file"))
                elif fmt is None and rel.suffix.lower() not in EXTENSION_FORMATS:
                    skipped.append((rel, "unsupported_extension"))
                else:
                    files.append(rel)
                    if len(files) > max_files:
                        raise InputLimitError(
                            f"directory has more than max_batch_files ({max_files}) files",
                            code="batch_file_limit_exceeded",
                        )
            except OSError:
                skipped.append((rel, "entry_unreadable"))

    walk(Path(), 0)
    return Discovery(root, sorted(files, key=lambda p: p.as_posix()), skipped)


def display_relative(rel: Path, index: int, root: Path, mode: str) -> str:
    if mode == "redacted":
        return f"<redacted:{index:04d}>{rel.suffix}"
    if mode == "full":
        return str(root / rel)
    return rel.as_posix()


def _skipped(discovery: Discovery, mode: str) -> list[dict[str, str]]:
    return [
        {"path": display_relative(rel, i, discovery.root, mode), "reason": reason}
        for i, (rel, reason) in enumerate(discovery.skipped, start=1)
    ]


def _still_regular(path: Path) -> bool:
    """Re-check just before use: the entry must still be a regular file, not a link."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not getattr(st, "st_file_attributes", 0) & _REPARSE_POINT


def _run_each(
    discovery: Discovery,
    mode: str,
    run: Callable[[Path, Path], RunReport],
) -> list[FileResult]:
    results: list[FileResult] = []
    for index, rel in enumerate(discovery.files, start=1):
        shown = display_relative(rel, index, discovery.root, mode)
        path = discovery.root / rel
        if not _still_regular(path):
            results.append(
                FileResult(
                    rel,
                    shown,
                    int(ExitCode.OUTPUT_ERROR),
                    error_code="input_changed_type",
                    error_message="entry is no longer a regular file; not processed",
                )
            )
            continue
        try:
            report = run(path, rel)
        except CipherGateError as exc:
            results.append(FileResult(rel, shown, int(exc.exit_code), None, exc.code, exc.message))
            continue
        report.input["path"] = shown
        results.append(FileResult(rel, shown, report.exit_code, report))
    return results


def _require_files(discovery: Discovery) -> None:
    if not discovery.files:
        raise InputFormatError(
            "no supported input files found in the directory (see --format, --recursive)",
            code="batch_empty",
        )


# --------------------------------------------------------------------------- operations


def analyze_directory(
    command: str,
    root: str | Path,
    policy: Policy,
    context: ContextInput | None,
    *,
    recursive: bool,
    runtime: RuntimeSettings,
    fmt: InputFormat | None = None,
    strict: bool | None = None,
) -> BatchReport:
    """Batch ``inspect`` / ``plan`` / ``rescan``. Read-only, like the single-file commands."""
    root = Path(root)
    discovery = discover(root, recursive=recursive, fmt=fmt, max_files=runtime.max_batch_files)
    _require_files(discovery)

    def run(path: Path, rel: Path) -> RunReport:
        if command == "inspect":
            return inspect_file(path, policy, context, runtime=runtime, fmt=fmt)
        if command == "plan":
            return plan_file(path, policy, context, runtime=runtime, fmt=fmt)
        return rescan_file(path, policy, context, strict=strict, runtime=runtime, fmt=fmt)

    mode = runtime.path_display
    return BatchReport(
        command=command,
        input_display=display_relative(Path(root.name), 0, root.parent, mode)
        if mode != "redacted"
        else "<redacted>",
        recursive=recursive,
        files=_run_each(discovery, mode, run),
        skipped=_skipped(discovery, mode),
    )


def inspect_directory(
    root: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    recursive: bool = False,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
) -> BatchReport:
    """Inspect every supported file below ``root``. Never writes any data file."""
    return analyze_directory(
        "inspect", root, policy, context, recursive=recursive,
        runtime=runtime or RuntimeSettings(), fmt=fmt,
    )  # fmt: skip


def plan_directory(
    root: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    recursive: bool = False,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
) -> BatchReport:
    """Preview sanitize decisions for every supported file below ``root``."""
    return analyze_directory(
        "plan", root, policy, context, recursive=recursive,
        runtime=runtime or RuntimeSettings(), fmt=fmt,
    )  # fmt: skip


def rescan_directory(
    root: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    *,
    recursive: bool = False,
    strict: bool | None = None,
    runtime: RuntimeSettings | None = None,
    fmt: InputFormat | None = None,
) -> BatchReport:
    """Report residual findings in every supported file below ``root``. Read-only."""
    return analyze_directory(
        "rescan", root, policy, context, recursive=recursive,
        runtime=runtime or RuntimeSettings(), fmt=fmt, strict=strict,
    )  # fmt: skip


def is_inside(path: Path, directory: Path) -> bool:
    """True if ``path`` resolves to ``directory`` or somewhere below it.

    Compares file identity, not just spelling: on case-insensitive filesystems (macOS APFS,
    Windows) ``IN/out`` is inside ``in`` even though ``normcase`` is a no-op on POSIX.
    """
    real_dir = os.path.normcase(os.path.realpath(directory))
    real = os.path.normcase(os.path.realpath(path))
    if real == real_dir or real.startswith(real_dir.rstrip(os.sep) + os.sep):
        return True
    try:
        dir_stat = os.stat(directory)
    except OSError:
        return False
    current = Path(os.path.realpath(path))
    for candidate in (current, *current.parents):
        try:
            if os.path.samestat(os.stat(candidate), dir_stat):
                return True
        except OSError:
            continue  # not created yet
    return False


def validate_output_directory(root: Path, output: Path) -> None:
    if os.path.lexists(output):
        raise OutputWriteError(
            "output directory already exists; choose a new path (--force does not replace "
            "directories)",
            code="output_exists",
        )
    if is_inside(output, root):
        raise UnsafePathError(
            "output directory must not be inside the input directory",
            code="output_inside_input",
        )
    parent = output.parent if str(output.parent) else Path(".")
    if parent.exists() and not parent.is_dir():
        raise UnsafePathError("output parent is not a directory", code="output_parent_invalid")


def sanitize_directory(
    root: str | Path,
    output: str | Path,
    policy: Policy,
    context: ContextInput | None = None,
    options: SanitizeOptions | None = None,
    *,
    recursive: bool = False,
) -> BatchReport:
    """Sanitize every file into a new OUTPUT directory, published only if all files pass."""
    root, output = Path(root), Path(output)
    options = options or SanitizeOptions()
    if options.force:
        raise UsageError(
            "force cannot replace an output directory; remove it or choose a new path",
            code="force_unsupported_for_directory",
        )
    runtime = options.runtime or RuntimeSettings()
    validate_output_directory(root, output)
    discovery = discover(
        root, recursive=recursive, fmt=options.format, max_files=runtime.max_batch_files
    )
    _require_files(discovery)
    mode = runtime.path_display
    shown_root = (
        "<redacted>"
        if mode == "redacted"
        else display_relative(Path(root.name), 0, root.parent, mode)
    )
    shown_out = (
        "<redacted>"
        if mode == "redacted"
        else display_relative(Path(output.name), 0, output.parent, mode)
    )
    file_options = SanitizeOptions(
        apply=options.apply,
        force=False,
        keys=options.keys,
        format=options.format,
        runtime=runtime,
    )

    if not options.apply:
        # Dry run: plan every file; the output paths are never created.
        results = _run_each(
            discovery,
            mode,
            lambda path, rel: sanitize_file(path, output / rel, policy, context, file_options),
        )
        for result in results:
            if result.report is not None:
                result.report.output["path"] = f"{shown_out}/{result.display}"
        return BatchReport(
            "sanitize",
            shown_root,
            recursive,
            results,
            _skipped(discovery, mode),
            output={"written": False, "path": shown_out, "withheld_reason": "apply_not_set"},
        )

    parent = output.parent if str(output.parent) else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(prefix=".ciphergate-batch-", dir=parent))
    except OSError:
        raise OutputWriteError(
            "cannot create a staging directory next to the output", code="output_temp_failed"
        ) from None
    published = False
    try:
        with contextlib.suppress(OSError):
            os.chmod(staging, 0o700)
        results = _run_each(
            discovery,
            mode,
            lambda path, rel: sanitize_file(path, staging / rel, policy, context, file_options),
        )
        report = BatchReport("sanitize", shown_root, recursive, results, _skipped(discovery, mode))
        for result in results:
            if result.report is not None:
                result.report.output["path"] = f"{shown_out}/{result.display}"
                if result.report.output.get("written"):
                    result.report.output["written"] = False
                    result.report.output["staged"] = True
        if report.exit_code != 0:
            report.output = {
                "written": False,
                "path": shown_out,
                "withheld_reason": "file_failed",
            }
            return report
        if os.path.lexists(output):
            raise OutputWriteError(
                "output directory appeared during processing; nothing was published",
                code="output_exists",
            )
        try:
            os.rename(staging, output)
        except OSError:
            raise OutputWriteError(
                "cannot publish the output directory", code="output_publish_failed"
            ) from None
        published = True
        for result in results:
            if result.report is not None:
                result.report.output.pop("staged", None)
                result.report.output["written"] = True
        report.output = {"written": True, "path": shown_out}
        return report
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
            if staging.exists():
                logger.warning(
                    "could not remove the staging directory %s; delete it manually",
                    staging.name,
                )
