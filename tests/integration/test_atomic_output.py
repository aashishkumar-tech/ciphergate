"""Atomic publish contract: temp files, no partial outputs, interruption and write failures."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate import SanitizeOptions, sanitize_file
from ciphergate.errors import OutputWriteError
from ciphergate.pipeline import sanitizer
from ciphergate.pipeline.atomic_output import AtomicOutput
from ciphergate.policy.validator import Policy
from tests.conftest import MINIMAL_POLICY


def temps(directory: Path) -> list[Path]:
    return list(directory.glob(".ciphergate-*.tmp"))


def test_publish_and_no_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    with AtomicOutput(target, force=False) as out:
        out.stream.write("one")
        assert out.temp_path is not None and out.temp_path.parent == tmp_path
        assert not target.exists()
        out.publish()
    assert target.read_text(encoding="utf-8") == "one" and not temps(tmp_path)
    with pytest.raises(OutputWriteError), AtomicOutput(target, force=False) as out:
        out.stream.write("two")
        out.publish()
    assert target.read_text(encoding="utf-8") == "one" and not temps(tmp_path)


def test_force_replaces_atomically(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    target.write_text("old", encoding="utf-8")
    with AtomicOutput(target, force=True) as out:
        out.stream.write("new")
        assert target.read_text(encoding="utf-8") == "old"  # untouched until publish
        out.publish()
    assert target.read_text(encoding="utf-8") == "new"


def test_exception_and_interrupt_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    for exc in (RuntimeError, KeyboardInterrupt):
        with pytest.raises(exc), AtomicOutput(target, force=False) as out:
            out.stream.write("partial")
            raise exc
        assert not target.exists() and not temps(tmp_path)


def test_exit_without_publish_discards(tmp_path: Path) -> None:
    with AtomicOutput(tmp_path / "o.txt", force=False) as out:
        out.stream.write("x")
    assert not (tmp_path / "o.txt").exists() and not temps(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_temp_permissions_owner_only(tmp_path: Path) -> None:
    with AtomicOutput(tmp_path / "o.txt", force=False) as out:
        assert out.temp_path is not None
        assert (out.temp_path.stat().st_mode & 0o777) == 0o600


def test_encoding_failure_is_output_error(tmp_path: Path) -> None:
    with (
        pytest.raises(OutputWriteError),
        AtomicOutput(tmp_path / "o.txt", force=False, encoding="ascii") as out,
    ):
        out.stream.write("café")
        out.publish()
    assert not (tmp_path / "o.txt").exists() and not temps(tmp_path)


def test_interrupt_mid_sanitize_leaves_nothing(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = write("in.txt", "a@example.com\n" * 50)
    real = sanitizer._transform_record
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 10:
            raise KeyboardInterrupt
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(sanitizer, "_transform_record", flaky)
    out = tmp_path / "o.txt"
    with pytest.raises(KeyboardInterrupt):
        sanitize_file(src, out, policy_text(MINIMAL_POLICY), options=SanitizeOptions())
    assert not out.exists() and not temps(tmp_path)


def test_publish_failure_reported_and_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with (
        pytest.raises(OutputWriteError) as info,
        AtomicOutput(tmp_path / "o.txt", force=True) as out,
    ):
        out.stream.write("x")
        out.publish()
    assert "disk full" not in str(info.value)
    assert not temps(tmp_path)


def test_input_change_detected(
    tmp_path: Path,
    write: Callable[[str, str | bytes], Path],
    policy_text: Callable[[str], Policy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ciphergate.errors import InputFormatError

    src = write("in.txt", "a@example.com\n")
    real = sanitizer._write_transformed

    def mutate(*args: object, **kwargs: object) -> object:
        result = real(*args, **kwargs)  # type: ignore[arg-type]
        src.write_text("changed\n", encoding="utf-8")
        return result

    monkeypatch.setattr(sanitizer, "_write_transformed", mutate)
    out = tmp_path / "o.txt"
    with pytest.raises(InputFormatError) as info:
        sanitize_file(src, out, policy_text(MINIMAL_POLICY))
    assert info.value.code == "input_changed" and not out.exists() and not temps(tmp_path)


def test_temp_creation_failure(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(OutputWriteError) as info, AtomicOutput(blocker / "o.txt", force=False):
        pass
    assert info.value.code == "output_temp_failed"


def test_stream_after_close_and_double_finish(tmp_path: Path) -> None:
    with AtomicOutput(tmp_path / "o.txt", force=False) as out:
        out.finish_writing()
        out.finish_writing()  # idempotent
        with pytest.raises(OutputWriteError):
            _ = out.stream
        out.publish()
    assert (tmp_path / "o.txt").read_text(encoding="utf-8") == ""


def test_publish_without_open(tmp_path: Path) -> None:
    out = AtomicOutput(tmp_path / "o.txt", force=False)
    with pytest.raises(OutputWriteError):
        out.publish()


def test_flush_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: int) -> None:
        raise OSError("io")

    monkeypatch.setattr(os, "fsync", boom)
    with (
        pytest.raises(OutputWriteError) as info,
        AtomicOutput(tmp_path / "o.txt", force=False) as out,
    ):
        out.stream.write("x")
        out.finish_writing()
    assert info.value.code == "output_flush_failed" and not temps(tmp_path)


def test_cleanup_failure_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = AtomicOutput(tmp_path / "o.txt", force=False)
    out.__enter__()
    out.finish_writing()

    def boom(self: Path, missing_ok: bool = False) -> None:
        raise OSError("locked")

    monkeypatch.setattr(Path, "unlink", boom)
    out.abort()
    assert out.cleanup_failed_path is not None
    monkeypatch.undo()
    out.cleanup_failed_path.unlink()
