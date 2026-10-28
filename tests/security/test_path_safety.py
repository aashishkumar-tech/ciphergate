"""Path safety: aliasing, symlinks, special files, directories."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import sanitize_file
from ciphergate.errors import UnsafePathError
from ciphergate.pipeline.paths import display_path, validate_input_path, validate_output_path
from ciphergate.policy.validator import Policy
from tests.conftest import EXAMPLES, MINIMAL_POLICY


def _symlink(target: Path, link: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")


def test_output_equal_to_input_rejected(
    tmp_path: Path, policy_text: Callable[[str], Policy]
) -> None:
    src = tmp_path / "in.csv"
    shutil.copy(EXAMPLES / "sample.csv", src)
    before = src.read_bytes()
    for alias in (src, tmp_path / "." / "in.csv", tmp_path / "sub" / ".." / "in.csv"):
        (tmp_path / "sub").mkdir(exist_ok=True)
        with pytest.raises(UnsafePathError):
            sanitize_file(src, alias, policy_text(MINIMAL_POLICY))
    assert src.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="case-insensitive filesystem alias")
def test_case_alias_rejected_on_windows(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    src.write_text("a\n", encoding="utf-8")
    with pytest.raises(UnsafePathError):
        validate_output_path(tmp_path / "IN.CSV", protected=[src], force=True)


def test_symlink_alias_rejected(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    src.write_text("a\n", encoding="utf-8")
    link = tmp_path / "link.csv"
    _symlink(src, link)
    with pytest.raises(UnsafePathError):
        validate_output_path(link, protected=[src], force=True)


def test_symlink_output_rejected(tmp_path: Path) -> None:
    other = tmp_path / "other.txt"
    other.write_text("keep", encoding="utf-8")
    link = tmp_path / "out.txt"
    _symlink(other, link)
    with pytest.raises(UnsafePathError):
        validate_output_path(link, protected=[], force=True)


def test_hardlink_alias_rejected(tmp_path: Path) -> None:
    src = tmp_path / "in.csv"
    src.write_text("a\n", encoding="utf-8")
    hard = tmp_path / "hard.csv"
    try:
        os.link(src, hard)
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(UnsafePathError):
        validate_output_path(hard, protected=[src], force=True)


def test_input_must_be_regular_file(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError) as info:
        validate_input_path(tmp_path, 10**6)
    assert info.value.code == "input_is_directory"
    with pytest.raises(UnsafePathError):
        validate_input_path(tmp_path / "missing.csv", 10**6)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_fifo_rejected(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(UnsafePathError) as info:
        validate_input_path(fifo, 10**6)
    assert info.value.code == "input_not_regular"


def test_output_directory_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        validate_output_path(tmp_path, protected=[], force=True)


def test_display_modes() -> None:
    p = Path("/secret/customer-acme/export.csv")
    assert display_path(p, "basename") == "export.csv"
    assert display_path(p, "redacted") == "<redacted>.csv"
