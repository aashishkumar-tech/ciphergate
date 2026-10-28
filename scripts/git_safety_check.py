"""Pre-commit / CI repository safety check. Local only; never prints file contents or matches.

Checks (each failure is reported as ``path[:line]: <check> [<code>]``):

* ``--require-feature-branch``: refuse to commit directly on ``main``/``master``;
* forbidden paths: env files, private keys/certificates, ``data/``, real-data and CipherGate
  output/report files, machine-local Claude Code settings;
* files larger than ``--max-bytes`` (default 1 MiB);
* secret-like content found by CipherGate's own ``SecretDetector``. A flagged line passes only if
  it carries an explicit synthetic marker (``TEST_ONLY``, ``NOT_A_REAL``, ``example.invalid``, ...),
  so synthetic fixtures stay allowed while real-looking credentials fail. Reviewed false
  positives (keyword mentions in docs, detector test vectors) are listed in
  ``.github/git-safety-allowlist.txt`` as ``<path> <sha256 of the stripped line>``: no content is
  stored, and editing an allowlisted line makes it fail again until it is re-reviewed.
  ``--suggest-allowlist`` prints entries for the current findings (path and hash only).

Modes: ``--staged`` (default; staged files, as pre-commit runs it) or ``--all`` (every tracked
file, as CI runs it). Like any pattern scanner it has false negatives: passing is not proof that
the repository is secret-free.

Exit codes: 0 clean, 1 findings, 2 usage/environment error.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import subprocess
import sys
from pathlib import Path

try:
    from ciphergate.detectors.secrets import SecretDetector
    from ciphergate.models.finding import ScanItem
except ImportError:  # pragma: no cover - exercised only without the dev install
    print("git-safety: ciphergate is not installed (pip install -e '.[dev]'); NOT verified")
    sys.exit(2)

PROTECTED_BRANCHES = frozenset({"main", "master"})
FORBIDDEN_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "id_rsa*",
    "id_ed25519*",
    "*.sanitized.*",
    "*.report.json",
    "ciphergate-policy.yml",
)
FORBIDDEN_DIRS = ("data/", "real_data/", "secrets/")
FORBIDDEN_EXACT = frozenset({".claude/settings.local.json"})
ALLOWED_EXACT = frozenset({".env.example"})
SYNTHETIC_MARKERS = (
    "TEST_ONLY",
    "TESTONLY",
    "NOT_A_REAL",
    "NOT_A_CREDENTIAL",
    "NOTREAL",
    "example.invalid",
    "example.com",
    "example.org",
    "<set-a-",
    "<redacted",
)
BINARY_SNIFF = 8192
ALLOWLIST = Path(".github/git-safety-allowlist.txt")


def git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], capture_output=True, text=True, check=True, encoding="utf-8"
        )
    except (OSError, subprocess.CalledProcessError):
        print(f"git-safety: 'git {args[0]}' failed; NOT verified")
        sys.exit(2)
    return result.stdout


def forbidden_reason(path: str) -> str | None:
    if path in ALLOWED_EXACT:
        return None
    if path in FORBIDDEN_EXACT:
        return "machine-local settings"
    if any(path.startswith(d) or f"/{d}" in f"/{path}" for d in FORBIDDEN_DIRS):
        return "data/secrets directory"
    name = path.rsplit("/", 1)[-1]
    if any(fnmatch.fnmatch(name, pattern) for pattern in FORBIDDEN_PATTERNS):
        return "secret, key or output file type"
    return None


def line_digest(line: str) -> str:
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def load_allowlist() -> frozenset[tuple[str, str]]:
    if not ALLOWLIST.is_file():
        return frozenset()
    entries: set[tuple[str, str]] = set()
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            path, digest = line.split()
            entries.add((path, digest))
    return frozenset(entries)


def scan_secrets(
    path: str, data: bytes, allowlist: frozenset[tuple[str, str]]
) -> list[tuple[int, str]]:
    """Return (line number, line digest) for flagged lines that are neither marked nor allowed."""
    if b"\0" in data[:BINARY_SNIFF]:
        return []
    text = data.decode("utf-8", errors="replace")
    detector = SecretDetector()
    flagged: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not detector.detect(ScanItem(0, number, path, None, line)):
            continue
        if any(marker in line for marker in SYNTHETIC_MARKERS):
            continue
        digest = line_digest(line)
        if (path, digest) not in allowlist:
            flagged.append((number, digest))
    return flagged


def staged_blob(path: str) -> bytes:
    try:
        return subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        print("git-safety: cannot read staged content of a file; NOT verified")
        sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="check staged files (default)")
    mode.add_argument("--all", action="store_true", help="check every tracked file")
    parser.add_argument("--require-feature-branch", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024)
    parser.add_argument(
        "--suggest-allowlist",
        action="store_true",
        help="print allowlist entries (path + hash) for findings; review each before adding",
    )
    args = parser.parse_args(argv)
    allowlist = load_allowlist()
    suggestions: list[str] = []

    problems: list[str] = []
    if args.require_feature_branch:
        branch = git("symbolic-ref", "--short", "HEAD").strip()  # works before the first commit
        if branch in PROTECTED_BRANCHES:
            problems.append(f"{branch}: direct commits to a protected branch [protected_branch]")

    if args.all:
        paths = [p for p in git("ls-files", "-z").split("\0") if p]
    else:
        paths = [
            p
            for p in git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
            if p
        ]

    for path in paths:
        reason = forbidden_reason(path)
        if reason:
            problems.append(f"{path}: forbidden path ({reason}) [forbidden_path]")
            continue
        data = Path(path).read_bytes() if args.all else staged_blob(path)
        if len(data) > args.max_bytes:
            problems.append(f"{path}: larger than {args.max_bytes} bytes [file_too_large]")
            continue
        for line, digest in scan_secrets(path, data, allowlist):
            problems.append(
                f"{path}:{line}: secret-like content without a synthetic marker [secret_pattern]"
            )
            suggestions.append(f"{path} {digest}  # line {line}: <reason reviewed by a human>")

    if problems:
        print(f"git-safety: {len(problems)} problem(s) (contents are never printed):")
        for problem in problems:
            print(f"  - {problem}")
        if args.suggest_allowlist and suggestions:
            print("candidate allowlist entries (add ONLY after confirming each is not a secret):")
            for suggestion in suggestions:
                print(f"  {suggestion}")
        return 1
    print(f"git-safety: {len(paths)} file(s) checked, no problems found (not proof of absence)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
