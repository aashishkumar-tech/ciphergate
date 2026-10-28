"""The core pipeline must make no network calls: socket creation/connection/DNS fail the test."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ciphergate import SanitizeOptions, inspect_file, plan_file, rescan_file, sanitize_file
from ciphergate.cli import app
from ciphergate.policy.validator import Policy
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import EXAMPLES, POLICIES


class NetworkUsed(AssertionError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(*_: object, **__: object) -> None:
        raise NetworkUsed("network access attempted")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "gethostbyname", deny)


def test_api_pipeline_offline(
    no_network: None, tmp_path: Path, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    p = policy_file("prd_external_ai.yml")
    for name in ("sample.csv", "sample.json", "sample.jsonl", "sample.log"):
        inspect_file(EXAMPLES / name, p, keys=keys)
        plan_file(EXAMPLES / name, p, keys=keys)
    out = tmp_path / "o.csv"
    sanitize_file(EXAMPLES / "sample.csv", out, p, options=SanitizeOptions(keys=keys))
    rescan_file(out, p)


def test_cli_offline(no_network: None, tmp_path: Path, key_env: str) -> None:
    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "sanitize",
            str(EXAMPLES / "sample.csv"),
            "--policy",
            str(POLICIES / "prd_external_ai.yml"),
            "--output",
            str(tmp_path / "o.csv"),
            "--apply",
        ],
    )
    assert r.exit_code == 0, r.output


def test_core_modules_do_not_import_network_libraries() -> None:
    import ast

    src = Path(__file__).resolve().parents[2] / "src" / "ciphergate"
    banned = {"socket", "http", "urllib", "requests", "httpx", "aiohttp", "ftplib", "smtplib"}
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in banned, (path.name, name)
