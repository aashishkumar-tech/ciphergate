"""Shared fixtures. All data is synthetic; keys are generated per test and never written to disk."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from ciphergate.constants import Destination, Environment, TargetEnvironment
from ciphergate.models.context import ContextInput
from ciphergate.policy.validator import Policy, load_policy, load_policy_text
from ciphergate.transforms.keys import KeyProvider

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "policies"
EXAMPLES = ROOT / "examples"

# Synthetic sensitive-looking values used across tests to check they never leak.
SYNTHETIC_SECRETS = [
    "TEST_ONLY_NOT_A_CREDENTIAL",
    "TEST_ONLY_NOT_A_REAL_TOKEN_123",
    "AKIATESTONLYNOTREAL1",
    "alice.test@example.com",
    "4111 1111 1111 1111",
]


@pytest.fixture
def hmac_key() -> str:
    return "hex:" + secrets.token_hex(32)


@pytest.fixture
def keys(hmac_key: str) -> KeyProvider:
    return KeyProvider({"CIPHERGATE_HMAC_KEY": hmac_key})


@pytest.fixture
def key_env(monkeypatch: pytest.MonkeyPatch, hmac_key: str) -> Iterator[str]:
    monkeypatch.setenv("CIPHERGATE_HMAC_KEY", hmac_key)
    yield hmac_key


@pytest.fixture
def no_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CIPHERGATE_HMAC_KEY", raising=False)


@pytest.fixture
def policy_file() -> Callable[[str], Policy]:
    def load(name: str) -> Policy:
        return load_policy(POLICIES / name)

    return load


@pytest.fixture
def policy_text() -> Callable[[str], Policy]:
    def load(text: str) -> Policy:
        return load_policy_text(text, source_name="inline.yml")

    return load


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str | bytes], Path]:
    def _write(name: str, content: str | bytes) -> Path:
        path = tmp_path / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_bytes(content.encode("utf-8"))
        return path

    return _write


def ctx(env: str | None = None, target: str | None = None, dest: str | None = None) -> ContextInput:
    return ContextInput(
        environment=Environment(env) if env else None,
        target_environment=TargetEnvironment(target) if target else None,
        destination=Destination(dest) if dest else None,
    )


MINIMAL_POLICY = """
policy_version: 1
name: minimal
# A trusted local destination: a missing destination is treated as untrusted.
context: {destination: local_dev}
requirements: {environment: false, destination: false}
settings: {strict: false}
rules:
  - id: redact-all-pii
    priority: 100
    match: {categories: ["pii.*", network.telemetry]}
    action: redact
  - id: redact-credentials
    priority: 100
    match: {categories: [credential.secret]}
    action: redact
defaults:
  date.generic: {action: allow}
"""
