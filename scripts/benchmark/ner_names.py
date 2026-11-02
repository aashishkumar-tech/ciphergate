"""Measure the optional NER detector (``presidio_ner``) on generated, labelled log lines.

An engineering aid, not a public claim: the corpus is synthetic and written by the people who
wrote CipherGate, and NER results depend on the spaCy model and its version. It never contacts a
service. It needs ``presidio-analyzer`` and an installed spaCy model (CipherGate never downloads
one) and prints only counts and generated example text, never real data.

    python scripts/benchmark/ner_names.py --model en_core_web_sm --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import defaultdict

from ciphergate.detectors.presidio_ner import PresidioDetector
from ciphergate.models.finding import ScanItem
from ciphergate.models.policy import PresidioSettings

# Common given and family names by region. Combinations are generated, not real people.
NAMES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "english": (
        ("James", "Emily", "Oliver", "Sarah", "Daniel", "Grace", "Thomas", "Hannah"),
        ("Smith", "Johnson", "Brown", "Taylor", "Walker", "Wright", "Hughes", "Turner"),
    ),
    "spanish": (
        ("Carlos", "Lucia", "Javier", "Sofia", "Miguel", "Elena", "Diego", "Carmen"),
        ("Garcia", "Martinez", "Lopez", "Sanchez", "Ramirez", "Torres", "Flores", "Vargas"),
    ),
    "indian": (
        ("Priya", "Rahul", "Ananya", "Vikram", "Aarav", "Kavya", "Arjun", "Meera"),
        ("Sharma", "Patel", "Iyer", "Reddy", "Nair", "Gupta", "Kumar", "Desai"),
    ),
    "chinese": (
        ("Wei", "Mei", "Jun", "Li", "Hao", "Xiu", "Chen", "Lan"),
        ("Wang", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao", "Wu"),
    ),
    "arabic": (
        ("Omar", "Fatima", "Yusuf", "Layla", "Khalid", "Aisha", "Hassan", "Noor"),
        ("Haddad", "Mansour", "Khalil", "Nasser", "Saleh", "Aziz", "Farouk", "Hamdan"),
    ),
    "west_african": (
        ("Chinedu", "Amara", "Kwame", "Ngozi", "Tunde", "Ama", "Emeka", "Adaeze"),
        ("Okafor", "Mensah", "Adeyemi", "Boateng", "Okonkwo", "Owusu", "Eze", "Asante"),
    ),
    "german": (
        ("Lukas", "Anna", "Felix", "Lena", "Jonas", "Marie", "Paul", "Clara"),
        ("Mueller", "Schmidt", "Fischer", "Weber", "Wagner", "Becker", "Hoffmann", "Koch"),
    ),
    "japanese": (
        ("Haruto", "Yui", "Sota", "Hina", "Ren", "Aoi", "Yuto", "Sakura"),
        ("Sato", "Suzuki", "Takahashi", "Tanaka", "Watanabe", "Ito", "Yamamoto", "Kato"),
    ),
}

TEMPLATES = (
    "ticket opened by {name} after the export failed",
    "user {name} logged in from the mobile app",
    "Assigned to {name} (support tier 2)",
    "{name} reset the password for the staging account",
    "ERROR processing refund requested by {name}: timeout",
    "approved by {name} on behalf of the finance team",
    "INFO 2026-03-04 12:00:01 checkout completed for customer {name}",
    "escalation: please call back {name} regarding invoice 4471",
)

# How the name is written. Logs rarely use clean "First Last".
STYLES = {
    "first_last": lambda f, s: f"{f} {s}",
    "last_comma_first": lambda f, s: f"{s}, {f}",
    "lowercase": lambda f, s: f"{f.lower()} {s.lower()}",
    "first_only": lambda f, s: f,
    "upper": lambda f, s: f"{f.upper()} {s.upper()}",
}

NEGATIVES = (
    "Connection to PostgreSQL timed out after 30 seconds",
    "Spring Boot application started in 3.2 seconds",
    "Kafka consumer group rebalanced across 4 partitions",
    "NullPointerException in OrderService.process line 88",
    "Deployed version 2.3.1 to the Frankfurt region",
    "Redis cache miss for key session index",
    "Retrying request to PaymentGateway in 5 seconds",
    "Scheduled job DailyReport finished with status OK",
    "Kubernetes pod web-7f9c restarted by the liveness probe",
    "User clicked Save on the Account Settings page",
    "Jenkins pipeline Build And Test passed on main",
    "Amazon S3 upload completed for bucket reports",
    "Elasticsearch cluster health changed from yellow to green",
    "Stripe webhook invoice.paid received",
    "Grafana alert High Latency resolved",
    "Django migration 0042_auto applied",
)


def item(text: str) -> ScanItem:
    return ScanItem(record_index=0, line=1, field_path="", field_name=None, value=text)


def overlaps(span: tuple[int, int], start: int, end: int) -> bool:
    return span[0] < end and start < span[1]


def run(model: str, min_score: float, seed: int, per_cell: int) -> int:
    rng = random.Random(seed)
    detector = PresidioDetector(PresidioSettings(enabled=True, model=model, min_score=min_score))
    by_region: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_style: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    full_cover = 0
    total = 0
    for region, (given, family) in NAMES.items():
        for style, render in STYLES.items():
            for _ in range(per_cell):
                name = render(rng.choice(given), rng.choice(family))
                text = rng.choice(TEMPLATES).format(name=name)
                start = text.index(name)
                end = start + len(name)
                spans = [
                    f.location.span
                    for f in detector.detect(item(text))
                    if f.category == "pii.person_name" and f.location.span
                ]
                hit = any(overlaps(s, start, end) for s in spans)
                covered = any(s[0] <= start and end <= s[1] for s in spans)
                total += 1
                full_cover += covered
                for bucket in (by_region[region], by_style[style]):
                    bucket[0] += hit
                    bucket[1] += 1
    false_alarms = 0
    for text in NEGATIVES:
        if any(f.category == "pii.person_name" for f in detector.detect(item(text))):
            false_alarms += 1

    caught = sum(v[0] for v in by_region.values())
    print(f"model={model} min_score={min_score} seed={seed} lines={total}")
    print(f"names caught (any overlap): {caught}/{total} = {caught / total:.0%}")
    print(f"names fully covered:        {full_cover}/{total} = {full_cover / total:.0%}")
    print(f"false alarms on name-free lines: {false_alarms}/{len(NEGATIVES)}")
    print("by style:")
    for style, (hit, n) in by_style.items():
        print(f"  {style:18} {hit:3}/{n}")
    print("by region:")
    for region, (hit, n) in by_region.items():
        print(f"  {region:18} {hit:3}/{n}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", default="en_core_web_sm")
    parser.add_argument("--min-score", type=float, default=0.6)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--per-cell", type=int, default=8, help="lines per region and style")
    args = parser.parse_args(argv)
    return run(args.model, args.min_score, args.seed, args.per_cell)


if __name__ == "__main__":
    sys.exit(main())
