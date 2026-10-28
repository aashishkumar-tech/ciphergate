"""Healthcare / financial / test-dataset templates behave as their headers describe."""

from __future__ import annotations

import csv
import datetime as dt
from collections.abc import Callable
from pathlib import Path

from ciphergate import RunStatus, SanitizeOptions, sanitize_file
from ciphergate.policy.validator import Policy
from ciphergate.transforms.keys import KeyProvider
from tests.conftest import ctx

Write = Callable[[str, str | bytes], Path]

PATIENTS = (
    "patient_id,admission_date,discharge_date,dob,zip_code\n"
    "PT_TEST_001,2026-01-01,2026-01-11,1980-05-05,00000\n"
    "PT_TEST_001,2026-02-01,2026-02-03,1980-05-05,00000\n"
    "PT_TEST_002,2026-01-01,2026-01-02,1975-07-07,00000\n"
)


def rows(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(path.open(encoding="utf-8", newline="")))


def test_healthcare_pseudonyms_and_per_patient_date_shift(
    tmp_path: Path, write: Write, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    out = tmp_path / "o.csv"
    r = sanitize_file(
        write("p.csv", PATIENTS),
        out,
        policy_file("healthcare_template.yml"),
        ctx("stg", dest="approved_internal"),
        SanitizeOptions(keys=keys),
    )
    assert r.status == RunStatus.SANITIZED, r.summary
    got = rows(out)
    assert got[0]["patient_id"] == got[1]["patient_id"] != got[2]["patient_id"]
    assert got[0]["patient_id"].startswith("pt_pz1_")
    assert got[0]["dob"] == "1980" and got[0]["zip_code"] == "[REDACTED:pii.address]"
    assert got[0]["admission_date"] != "2026-01-01"  # shifted (offset is never zero)
    los = [
        (
            dt.date.fromisoformat(x["discharge_date"]) - dt.date.fromisoformat(x["admission_date"])
        ).days
        for x in got
    ]
    assert los == [10, 2, 1]  # intervals preserved per patient


def test_healthcare_clinical_values_review_or_block(
    tmp_path: Path, write: Write, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    src = write("c.csv", "patient_id,diagnosis\nPT_TEST_001,TEST_CONDITION_A\n")
    p = policy_file("healthcare_template.yml")
    internal = sanitize_file(
        src, tmp_path / "a.csv", p, ctx("dev", dest="approved_internal"), SanitizeOptions(keys=keys)
    )
    assert internal.status == RunStatus.REVIEW_REQUIRED
    external = sanitize_file(
        src,
        tmp_path / "b.csv",
        p,
        ctx("prd", "external", "external_ai"),
        SanitizeOptions(keys=keys),
    )
    assert external.status == RunStatus.BLOCKED
    assert not (tmp_path / "a.csv").exists() and not (tmp_path / "b.csv").exists()


def test_financial_template(
    tmp_path: Path, write: Write, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    src = write(
        "f.csv",
        "account_id,amount,card_number,iban\nACC_TEST_1,42.50,4111111111111111,TEST_IBAN_0000\n",
    )
    p = policy_file("financial_template.yml")
    out = tmp_path / "o.csv"
    r = sanitize_file(src, out, p, ctx("dev", dest="approved_internal"), SanitizeOptions(keys=keys))
    assert r.status == RunStatus.SANITIZED
    row = rows(out)[0]
    assert row["account_id"].startswith("acct_pz1_") and row["amount"] == "[10, 100)"
    assert row["card_number"] == "[REDACTED:pii.payment_card]"
    assert row["iban"] == "[REDACTED:pii.bank_account]"
    blocked = sanitize_file(
        src, tmp_path / "x.csv", p, ctx("dev", dest="external_vendor"), SanitizeOptions(keys=keys)
    )
    assert blocked.status == RunStatus.BLOCKED


def test_test_dataset_entity_joins(
    tmp_path: Path, write: Write, policy_file: Callable[[str], Policy], keys: KeyProvider
) -> None:
    src = write(
        "t.csv",
        "customer_id,email,full_name\n"
        "alice.test@example.com,Alice.Test@example.com,Alice Example\n",
    )
    out = tmp_path / "o.csv"
    r = sanitize_file(
        src,
        out,
        policy_file("test_dataset.yml"),
        ctx("dev", dest="local_dev"),
        SanitizeOptions(keys=keys),
    )
    assert r.status == RunStatus.SANITIZED
    row = rows(out)[0]
    # Entity scope + casefold: same person links across the two columns.
    assert row["customer_id"] == row["email"] and row["full_name"] == "Test Person"
