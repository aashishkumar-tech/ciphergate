"""The detection benchmark: repeatable corpus, valid labels, results kept out of the repository."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ciphergate import load_policy
from ciphergate.detectors.iban import iban_valid
from ciphergate.detectors.payment_card import luhn_valid
from tests.conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts" / "benchmark"))

import compare_tools


def test_corpus_is_repeatable_for_a_seed() -> None:
    assert compare_tools.Corpus(1).build(3) == compare_tools.Corpus(1).build(3)
    assert compare_tools.Corpus(1).build(3) != compare_tools.Corpus(2).build(3)


def test_every_class_has_templates_and_labels_are_present_in_the_text() -> None:
    corpus = compare_tools.Corpus(1)
    assert set(corpus.generators) == set(compare_tools.TEMPLATES)
    for case in corpus.build(4):
        assert case["value"] is None or case["value"] in case["text"]


def test_negatives_carry_no_label() -> None:
    negatives = [c for c in compare_tools.Corpus(1).build(2) if c["cls"] == "NEGATIVE"]
    assert len(negatives) == 2 * compare_tools.NEGATIVE_FACTOR
    assert all(c["value"] is None for c in negatives)


def test_generated_values_pass_their_own_checks() -> None:
    corpus = compare_tools.Corpus(1)
    for _ in range(50):
        assert iban_valid(corpus.iban())
        assert luhn_valid(corpus.luhn("4"))


def test_benchmark_policy_is_valid() -> None:
    assert load_policy(compare_tools.POLICY).name == "benchmark-redact-everything"


def test_ciphergate_scoring_on_a_small_corpus(tmp_path: Path) -> None:
    cases = compare_tools.Corpus(1).build(1)
    hits, _ = compare_tools.run_ciphergate(cases, tmp_path)
    scored = {c["cls"]: hit for c, hit in zip(cases, hits, strict=True) if c["value"]}
    assert scored["email"] and scored["iban"] and scored["private_key_pem"]
    assert not scored["person_name"]  # a known gap without NER; the score must be able to say so


@pytest.mark.parametrize("inside", [ROOT, ROOT / "build" / "bench"])
def test_refuses_to_write_inside_the_repository(inside: Path) -> None:
    assert compare_tools.is_inside_repo(inside)
    assert compare_tools.main(["--out", str(inside), "--per-class", "1"]) == 2


def test_output_outside_the_repository_is_allowed(tmp_path: Path) -> None:
    assert not compare_tools.is_inside_repo(tmp_path)


def test_results_are_not_tracked() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "scripts/benchmark"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert not [f for f in tracked if f.endswith((".jsonl", ".json"))]
