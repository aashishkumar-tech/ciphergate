"""Compare CipherGate with other local tools on a generated, labelled, synthetic log corpus.

Every value is random and format-shaped; none is real. A positive case counts as caught only if
the tool's finding overlaps the planted value (CipherGate: the value is gone from the output). A
negative case counts as a false alarm on any finding. Dates are excluded for every tool, because
the CipherGate benchmark policy allows them.

The corpus is written by the same people who wrote the detectors, so results guide engineering
work and are not evidence for a public comparison. See README.md in this directory.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import logging
import random
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
POLICY = HERE / "policy.yml"
DEFAULT_SEED = 20261030
PER_CLASS = 25
NEGATIVE_FACTOR = 10
AN = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
FIRST = [
    "Maria",
    "Liam",
    "Priya",
    "Chen",
    "Omar",
    "Sofia",
    "Noah",
    "Aisha",
    "Lucas",
    "Hannah",
    "Diego",
    "Yuki",
]
LAST = [
    "Fernandez",
    "Walker",
    "Sharma",
    "Nguyen",
    "Haddad",
    "Rossi",
    "Becker",
    "Okafor",
    "Silva",
    "Lindgren",
]
STREET = ["Maple", "Cedar", "Willow", "Harbor", "Sunset", "Lakeview", "Birch", "Orchard"]

# The placeholder carries the repository's synthetic marker: these lines are templates, not values.
TEMPLATES = {
    "aws_key_id": [
        "aws credentials loaded access_key={TEST_ONLY}",
        "boto3 client created with {TEST_ONLY}",
    ],
    "github_pat": ["git clone failed using token {TEST_ONLY}", "export GH_TOKEN={TEST_ONLY}"],
    "slack_bot": ["slack notify failed token={TEST_ONLY}", "posting with {TEST_ONLY}"],
    "stripe_key": ["charge failed for key {TEST_ONLY}", "STRIPE_SECRET={TEST_ONLY}"],
    "jwt": ["rejected session {TEST_ONLY}", "auth cookie value={TEST_ONLY}"],
    "bearer_header": [
        "upstream call Authorization: Bearer {TEST_ONLY}",
        'headers={{"Authorization": "Bearer {TEST_ONLY}"}}',
    ],
    "password_line": [
        "connect failed password={TEST_ONLY}",
        'config {{"password": "{TEST_ONLY}"}}',
        "PGPASSWORD={TEST_ONLY} psql",
    ],
    "api_key_line": [
        "request api_key={TEST_ONLY} rejected",
        'config {{"api_key": "{TEST_ONLY}"}}',
    ],
    "db_password_in_url": ["connecting postgres://app:{TEST_ONLY}@db.internal.example:5432/orders"],
    "unlabeled_high_entropy": ["retrying upstream with {TEST_ONLY}", "cache miss for {TEST_ONLY}"],
    "base64_wrapped": [
        "basic header Authorization: Basic {TEST_ONLY}",
        "decoded nothing from {TEST_ONLY}",
    ],
    "email": [
        "password reset sent to {TEST_ONLY}",
        "user {TEST_ONLY} not found",
        'payload {{"contact": "{TEST_ONLY}"}}',
    ],
    "url_encoded_email": [
        "GET /users?mail={TEST_ONLY} 404",
        "redirect to /verify?address={TEST_ONLY}",
    ],
    "phone_us": ["sms failed for {TEST_ONLY}", "callback number {TEST_ONLY} invalid"],
    "phone_intl": ["sms failed for {TEST_ONLY}", "callback number {TEST_ONLY} invalid"],
    "ipv4_public": ["connection reset by {TEST_ONLY}", "login from {TEST_ONLY} denied"],
    "ipv6": ["connection reset by {TEST_ONLY}", "login from {TEST_ONLY} denied"],
    "payment_card": ["charge declined for card {TEST_ONLY}", "payment retry pan={TEST_ONLY}"],
    "ssn": ["identity check failed ssn={TEST_ONLY}", "kyc mismatch for {TEST_ONLY}"],
    "iban": ["payout failed to {TEST_ONLY}", "beneficiary account {TEST_ONLY} closed"],
    "mac_address": ["dhcp lease for {TEST_ONLY}", "device {TEST_ONLY} offline"],
    "person_name": [
        "ticket opened by {TEST_ONLY} yesterday",
        "invoice sent to {TEST_ONLY} on request",
        'customer_name="{TEST_ONLY}"',
    ],
    "street_address": ["delivery failed at {TEST_ONLY}", "shipping to {TEST_ONLY} delayed"],
    "date_of_birth": [
        "signup rejected dob={TEST_ONLY}",
        'profile {{"date_of_birth": "{TEST_ONLY}"}}',
    ],
}


class Corpus:
    """Seeded generator, so a run can be repeated exactly."""

    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)
        self.generators: dict[str, Callable[[], str]] = {
            "aws_key_id": lambda: "AKIA" + self.rs(16, string.ascii_uppercase + "234567"),
            "github_pat": lambda: "ghp_" + self.rs(36),
            "slack_bot": lambda: "-".join(
                ("xoxb", self.rs(11, string.digits), self.rs(12, string.digits), self.rs(24))
            ),
            "stripe_key": lambda: "sk_live_" + self.rs(24),
            "jwt": self.jwt,
            "bearer_header": lambda: self.rs(40),
            "password_line": lambda: self.rs(14),
            "api_key_line": lambda: self.rs(32, HEX),
            "db_password_in_url": lambda: self.rs(14),
            "unlabeled_high_entropy": lambda: self.rs(40),
            "base64_wrapped": lambda: base64.b64encode(f"svc:{self.rs(16)}".encode()).decode(),
            "email": self.email,
            "url_encoded_email": lambda: urllib.parse.quote(self.email(), safe=""),
            "phone_us": lambda: f"(202) 555-0{self.r.randint(100, 199)}",
            "phone_intl": lambda: f"+44 20 7946 0{self.r.randint(100, 999)}",
            "ipv4_public": lambda: f"203.0.113.{self.r.randint(1, 254)}",
            "ipv6": lambda: f"2001:db8::{self.rs(4, HEX)}",
            "payment_card": lambda: self.luhn(self.r.choice(["4", "51", "37"])),
            "ssn": lambda: "-".join(
                str(self.r.randint(*bounds)) for bounds in ((100, 665), (10, 99), (1000, 9999))
            ),
            "iban": self.iban,
            "mac_address": lambda: ":".join(self.rs(2, HEX) for _ in range(6)),
            "person_name": lambda: f"{self.r.choice(FIRST)} {self.r.choice(LAST)}",
            "street_address": lambda: f"{self.r.randint(10, 9999)} {self.r.choice(STREET)} Street",
            "date_of_birth": lambda: (
                f"19{self.r.randint(50, 99)}-0{self.r.randint(1, 9)}-1{self.r.randint(0, 9)}"
            ),
        }
        self.negatives: list[Callable[[], str]] = [
            lambda: f"request completed in {self.r.randint(1, 900)}ms status=200",
            lambda: f"worker-{self.r.randint(1, 40)} processed {self.r.randint(1, 9000)} messages",
            lambda: f"GET /api/v{self.r.randint(1, 3)}/orders?page={self.r.randint(1, 50)} 200",
            lambda: "build " + ".".join(str(self.r.randint(0, 30)) for _ in range(3)) + " deployed",
            lambda: f"commit {self.rs(40, HEX)} merged",
            lambda: f"object sha256 {self.rs(64, HEX)} cached",
            lambda: "order " + "-".join(self.rs(n, HEX) for n in (8, 4, 4, 4, 12)) + " shipped",
            lambda: f"token_count={self.r.randint(1, 8000)} prompt tokens used",
            lambda: "password_reset_enabled=true feature flag loaded",
            lambda: "key_name=primary rotation not due",
            lambda: f"invoice total {self.rs(16, string.digits)} units",
            lambda: f"batch id {self.rs(16, string.digits)} queued",
            lambda: f"memory usage {self.r.randint(10, 99)}% heap {self.r.randint(100, 4000)}MB",
            lambda: "Apache Kafka consumer rebalanced on Spring Boot service",
            lambda: "Redis cluster failover finished after Kubernetes restart",
            lambda: "NullPointerException in OrderService.processPayment",
            lambda: f"retry attempt {self.r.randint(1, 5)} of 5 scheduled",
            lambda: "connection pool exhausted, waiting for free slot",
            lambda: f"timeout after {self.r.randint(1, 60)}s calling inventory service",
            lambda: f"cache hit ratio 0.{self.r.randint(10, 99)} over last window",
        ]

    def rs(self, n: int, alphabet: str = AN) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def email(self) -> str:
        return (
            f"{self.rs(6, string.ascii_lowercase)}.{self.rs(4, string.ascii_lowercase)}@example.com"
        )

    def luhn(self, prefix: str, length: int = 16) -> str:
        body = prefix + self.rs(length - len(prefix) - 1, string.digits)
        total = 0
        for i, ch in enumerate(reversed(body)):
            d = int(ch) * (2 if i % 2 == 0 else 1)
            total += d - 9 if d > 9 else d
        return body + str((10 - total % 10) % 10)

    def iban(self) -> str:
        bban = "WEST" + self.rs(14, string.digits)
        check = 98 - int("".join(str(int(c, 36)) for c in bban + "GB00")) % 97
        return f"GB{check:02d}{bban}"

    def jwt(self) -> str:
        def b64u(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64u(json.dumps({"sub": self.rs(8)}).encode())
        return f"{head}.{body}.{b64u(self.r.randbytes(32))}"

    def build(self, per_class: int = PER_CLASS) -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        for cls, generate in self.generators.items():
            templates = TEMPLATES[cls]
            for i in range(per_class):
                value = generate()
                body = templates[i % len(templates)].format(TEST_ONLY=value)
                text = f"2026-10-30T07:12:{i % 60:02d}Z ERROR app: {body}\n"
                cases.append({"cls": cls, "text": text, "value": value})
        for _ in range(per_class):
            body = "\n".join(self.rs(64) for _ in range(6))
            block = "\n".join(
                ("-----BEGIN RSA PRIVATE" + " KEY-----", body, "-----END RSA PRIVATE" + " KEY-----")
            )
            cases.append({"cls": "private_key_pem", "text": f"dump:\n{block}\n", "value": body})
        for i in range(per_class * NEGATIVE_FACTOR):
            body = self.negatives[i % len(self.negatives)]()
            text = f"2026-10-30T07:13:{i % 60:02d}Z INFO app: {body}\n"
            cases.append({"cls": "NEGATIVE", "text": text, "value": None})
        return cases


def overlaps(span: tuple[int, int], case: dict[str, Any]) -> bool:
    if case["value"] is None:
        return True
    start = case["text"].find(case["value"])
    return span[0] < start + len(case["value"]) and start < span[1]


def run_ciphergate(cases: list[dict[str, Any]], tmp: Path) -> tuple[list[bool], dict[str, int]]:
    from ciphergate import ContextInput, SanitizeOptions, load_policy, sanitize_file

    policy = load_policy(POLICY)
    withheld: dict[str, int] = defaultdict(int)
    hits = []
    for i, case in enumerate(cases):
        source, output = tmp / f"cg_{i}.log", tmp / f"cg_{i}.out"
        source.write_text(case["text"], encoding="utf-8", newline="")
        report = sanitize_file(source, output, policy, ContextInput(), SanitizeOptions(apply=True))
        if not report.ok or not output.exists():
            withheld[case["cls"]] += 1  # nothing was published, so the value did not get through
            hits.append(True)
            continue
        text = output.read_text(encoding="utf-8")
        hits.append(text != case["text"] if case["value"] is None else case["value"] not in text)
    return hits, dict(withheld)


def run_presidio(cases: list[dict[str, Any]], threshold: float, model: str) -> list[bool]:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }
    )
    engine = AnalyzerEngine(nlp_engine=provider.create_engine())
    hits = []
    for case in cases:
        found = engine.analyze(text=case["text"], language="en", score_threshold=threshold)
        spans = [(r.start, r.end) for r in found if r.entity_type != "DATE_TIME"]
        hits.append(any(overlaps(s, case) for s in spans))
    return hits


def run_scrubadub(cases: list[dict[str, Any]]) -> list[bool]:
    import scrubadub

    scrubber = scrubadub.Scrubber()
    hits = []
    for case in cases:
        filth = scrubber.iter_filth(case["text"])
        spans = [(f.beg, f.end) for f in filth if "date" not in f.type]
        hits.append(any(overlaps(s, case) for s in spans))
    return hits


def run_detect_secrets(cases: list[dict[str, Any]], tmp: Path) -> list[bool]:
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings

    hits = []
    with default_settings():
        for i, case in enumerate(cases):
            path = tmp / f"ds_{i}.log"
            path.write_text(case["text"], encoding="utf-8", newline="")
            collection = SecretsCollection()
            collection.scan_file(str(path))
            found = [secret for _, secret in collection]
            # PEM findings report the header, so any finding on those cases counts.
            if case["value"] is None or case["cls"] == "private_key_pem":
                hits.append(bool(found))
                continue
            value = case["value"]
            hits.append(
                any(
                    s.secret_value and (s.secret_value in value or value in s.secret_value)
                    for s in found
                )
            )
    return hits


def run_gitleaks(cases: list[dict[str, Any]], tmp: Path, binary: str) -> list[bool]:
    folder = tmp / "gitleaks"
    folder.mkdir()
    for i, case in enumerate(cases):
        (folder / f"case_{i}.log").write_text(case["text"], encoding="utf-8", newline="")
    report = tmp / "gitleaks.json"
    subprocess.run(  # the user names the binary with --gitleaks
        [binary, "dir", str(folder), "--report-format", "json", "--report-path", str(report),
         "--no-banner", "--exit-code", "0", "--log-level", "error"],
        check=True, capture_output=True,
    )  # fmt: skip
    hits = [False] * len(cases)
    for finding in json.loads(report.read_text(encoding="utf-8")):
        i = int(Path(finding["File"]).stem.split("_")[1])
        value, match = cases[i]["value"], finding.get("Secret", "")
        if (
            value is None
            or cases[i]["cls"] == "private_key_pem"
            or match in value
            or value in match
        ):
            hits[i] = True
    return hits


def is_inside_repo(path: Path) -> bool:
    resolved, repo = path.resolve(), REPO.resolve()
    return resolved == repo or repo in resolved.parents


def table(
    cases: list[dict[str, Any]], tools: dict[str, list[bool]]
) -> dict[str, dict[str, list[int]]]:
    rows: dict[str, dict[str, list[int]]] = {}
    for tool, hits in tools.items():
        for case, hit in zip(cases, hits, strict=True):
            cell = rows.setdefault(case["cls"], {}).setdefault(tool, [0, 0])
            cell[0] += int(hit)
            cell[1] += 1
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="Directory outside the repository.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--per-class", type=int, default=PER_CLASS)
    parser.add_argument("--gitleaks", help="Path to a gitleaks binary you installed yourself.")
    parser.add_argument("--spacy-model", default="en_core_web_sm")
    args = parser.parse_args(argv)
    if is_inside_repo(args.out):
        print("--out must be outside the repository: the corpus holds fake credentials")
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    logging.disable(logging.WARNING)
    cases = Corpus(args.seed).build(args.per_class)
    (args.out / "corpus.jsonl").write_text(
        "".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8"
    )
    tools: dict[str, list[bool]] = {}
    seconds: dict[str, float] = {}
    withheld: dict[str, int] = {}
    skipped: list[str] = []

    def timed(name: str, run: Callable[[], list[bool]]) -> None:
        start = time.perf_counter()
        tools[name] = run()
        seconds[name] = round(time.perf_counter() - start, 1)

    def ciphergate(tmp: Path) -> list[bool]:
        hits, seen = run_ciphergate(cases, tmp)
        withheld.update(seen)
        return hits

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        timed("ciphergate", lambda: ciphergate(tmp))
        if importlib.util.find_spec("presidio_analyzer"):
            timed("presidio", lambda: run_presidio(cases, 0.0, args.spacy_model))
            timed("presidio@0.5", lambda: run_presidio(cases, 0.5, args.spacy_model))
        else:
            skipped.append("presidio")
        if importlib.util.find_spec("scrubadub"):
            timed("scrubadub", lambda: run_scrubadub(cases))
        else:
            skipped.append("scrubadub")
        if importlib.util.find_spec("detect_secrets"):
            timed("detect-secrets", lambda: run_detect_secrets(cases, tmp))
        else:
            skipped.append("detect-secrets")
        if args.gitleaks:
            timed("gitleaks", lambda: run_gitleaks(cases, tmp, args.gitleaks))
        else:
            skipped.append("gitleaks")

    rows = table(cases, tools)
    print("class".ljust(26) + "".join(name.rjust(16) for name in tools))
    for cls, row in rows.items():
        print(cls.ljust(26) + "".join(f"{row[n][0]}/{row[n][1]}".rjust(16) for n in tools))
    print("seconds".ljust(26) + "".join(str(seconds[n]).rjust(16) for n in tools))
    print(f"ciphergate withheld output: {withheld or 'none'}")
    print(f"not run: {', '.join(skipped) or 'none'}")
    (args.out / f"results_{args.seed}.json").write_text(
        json.dumps({"seed": args.seed, "rows": rows, "seconds": seconds, "skipped": skipped}),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
