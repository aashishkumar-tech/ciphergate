"""Input/output path safety checks.

* Input must be an existing regular file (symlinks are resolved; devices, FIFOs, sockets and
  directories are rejected) within ``max_input_bytes``.
* Output must not resolve to the input or any other protected path (realpath + ``samefile``,
  case-normalised on Windows), must not be a symlink or directory, and must not already exist
  unless ``force`` is given.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from ciphergate.errors import InputLimitError, OutputWriteError, UnsafePathError


def validate_input_path(path: Path, max_bytes: int) -> Path:
    try:
        st = os.stat(path)  # follows symlinks: we check what will actually be read
    except FileNotFoundError:
        raise UnsafePathError("input file does not exist", code="input_not_found") from None
    except OSError:
        raise UnsafePathError("input file cannot be accessed", code="input_unreadable") from None
    if stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(
            "input is a directory; use a *_directory function", code="input_is_directory"
        )
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(
            "input is not a regular file (devices/FIFOs are refused)", code="input_not_regular"
        )
    if st.st_size > max_bytes:
        raise InputLimitError(
            f"input exceeds max_input_bytes ({max_bytes})", code="size_limit_exceeded"
        )
    return Path(os.path.realpath(path))


def _same(a: Path, b: Path) -> bool:
    ra = os.path.normcase(os.path.realpath(a))
    rb = os.path.normcase(os.path.realpath(b))
    if ra == rb:
        return True
    try:
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


def validate_output_path(
    path: Path, *, protected: list[Path], force: bool, label: str = "output"
) -> Path:
    for other in protected:
        if _same(path, other):
            raise UnsafePathError(
                f"{label} path refers to the input or another protected file",
                code=f"{label}_aliases_input",
            )
    if path.is_symlink():
        raise UnsafePathError(
            f"{label} path is a symlink; refusing to write through it", code=f"{label}_is_symlink"
        )
    if path.exists():
        if path.is_dir():
            raise UnsafePathError(f"{label} path is a directory", code=f"{label}_is_directory")
        if not stat.S_ISREG(path.stat().st_mode):
            raise UnsafePathError(
                f"{label} path is not a regular file", code=f"{label}_not_regular"
            )
        if not force:
            raise OutputWriteError(
                f"{label} file already exists; use --force to replace it", code=f"{label}_exists"
            )
    parent = path.parent if str(path.parent) else Path(".")
    if parent.exists() and not parent.is_dir():
        raise UnsafePathError(f"{label} parent is not a directory", code=f"{label}_parent_invalid")
    return path


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def display_path(path: Path | None, mode: str) -> str | None:
    if path is None:
        return None
    if mode == "redacted":
        return "<redacted>" + (path.suffix if path.suffix else "")
    if mode == "full":
        return str(path)
    return path.name
