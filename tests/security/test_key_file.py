"""Key files via ``<key_env>_FILE`` (#10): permission checks, fail-closed, never leaked."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from ciphergate.errors import MissingKeyError
from ciphergate.transforms.keys import MAX_KEY_FILE_BYTES, KeyProvider, KeyStatus
from tests.conftest import EXAMPLES, POLICIES

NAME = "CIPHERGATE_HMAC_KEY"
POSIX = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


def _key_file(tmp_path: Path, content: str | bytes, mode: int = 0o600) -> Path:
    path = tmp_path / "hmac.key"
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    os.chmod(path, mode)
    return path


def test_file_key_equals_env_key(tmp_path: Path) -> None:
    raw = "hex:" + secrets.token_hex(32)
    path = _key_file(tmp_path, raw + "\n")  # one trailing newline is stripped
    from_file = KeyProvider({NAME + "_FILE": str(path)})
    from_env = KeyProvider({NAME: raw})
    assert from_file.status(NAME) == KeyStatus.AVAILABLE and from_file.source(NAME) == "file"
    assert from_file.get(NAME) == from_env.get(NAME) and from_env.source(NAME) == "env"


def test_both_sources_is_ambiguous(tmp_path: Path) -> None:
    raw = "hex:" + secrets.token_hex(32)
    keys = KeyProvider({NAME: raw, NAME + "_FILE": str(_key_file(tmp_path, raw))})
    assert keys.status(NAME) == KeyStatus.AMBIGUOUS_SOURCE
    with pytest.raises(MissingKeyError) as exc:
        keys.get(NAME)
    assert exc.value.code == "key_file_invalid" and raw[4:] not in exc.value.message


@pytest.mark.parametrize(
    ("make", "status"),
    [
        (lambda p: str(p / "missing.key"), KeyStatus.FILE_UNREADABLE),
        (str, KeyStatus.FILE_NOT_REGULAR),  # a directory
        (
            lambda p: str(_key_file(p, "x" * (MAX_KEY_FILE_BYTES + 1))),
            KeyStatus.FILE_TOO_LARGE,
        ),
        (lambda p: str(_key_file(p, b"\xff\xfe" * 20)), KeyStatus.INVALID_ENCODING),
        (lambda p: str(_key_file(p, "short")), KeyStatus.TOO_SHORT),
        (lambda p: str(_key_file(p, "")), KeyStatus.MISSING),
    ],
)
def test_bad_key_files_fail_closed(tmp_path: Path, make, status: KeyStatus) -> None:  # type: ignore[no-untyped-def]
    keys = KeyProvider({NAME + "_FILE": make(tmp_path)})
    assert keys.status(NAME) == status
    with pytest.raises(MissingKeyError):
        keys.get(NAME)


@POSIX
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o606])
def test_group_or_other_access_rejected(tmp_path: Path, mode: int) -> None:
    path = _key_file(tmp_path, "hex:" + secrets.token_hex(32), mode)
    keys = KeyProvider({NAME + "_FILE": str(path)})
    assert keys.status(NAME) == KeyStatus.FILE_INSECURE
    with pytest.raises(MissingKeyError) as exc:
        keys.get(NAME)
    assert exc.value.code == "key_file_invalid" and str(path) not in exc.value.message


@POSIX
def test_symlink_target_is_checked(tmp_path: Path) -> None:
    target = _key_file(tmp_path, "hex:" + secrets.token_hex(32), 0o400)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    assert KeyProvider({NAME + "_FILE": str(link)}).status(NAME) == KeyStatus.AVAILABLE
    os.chmod(target, 0o644)
    assert KeyProvider({NAME + "_FILE": str(link)}).status(NAME) == KeyStatus.FILE_INSECURE


def test_key_file_read_once(tmp_path: Path) -> None:
    path = _key_file(tmp_path, "hex:" + secrets.token_hex(32))
    keys = KeyProvider({NAME + "_FILE": str(path)})
    first = keys.get(NAME)
    path.write_text("hex:" + secrets.token_hex(32), encoding="utf-8")
    assert keys.status(NAME) == KeyStatus.AVAILABLE and keys.get(NAME) == first


def test_cli_with_key_file_never_leaks(tmp_path: Path) -> None:
    raw_hex = secrets.token_hex(32)
    path = _key_file(tmp_path, f"hex:{raw_hex}\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(NAME)}
    env |= {"PYTHONIOENCODING": "utf-8", NAME + "_FILE": str(path)}
    out = tmp_path / "out.csv"
    report = tmp_path / "r.json"
    args = [
        sys.executable, "-m", "ciphergate", "sanitize", str(EXAMPLES / "sample.csv"),
        "--policy", str(POLICIES / "prd_external_ai.yml"), "--environment", "prd",
        "--target-environment", "external", "--destination", "external_ai",
        "--output", str(out), "--report", str(report), "--apply",
    ]  # fmt: skip
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, env=env, check=False)
    assert r.returncode == 0, r.stderr
    text = report.read_text(encoding="utf-8")
    assert '"source": "file"' in text
    for blob in (r.stdout, r.stderr, text, out.read_text(encoding="utf-8")):
        assert raw_hex not in blob and str(path) not in blob
    if sys.platform == "win32":
        assert "not verified on Windows" in r.stderr
    # Ambiguous configuration: refused, nothing published.
    out2 = tmp_path / "out2.csv"
    env[NAME] = f"hex:{raw_hex}"
    args[args.index(str(out))] = str(out2)
    args[args.index(str(report))] = str(tmp_path / "r2.json")
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, env=env, check=False)
    assert r.returncode == 6 and not out2.exists() and raw_hex not in r.stdout + r.stderr
