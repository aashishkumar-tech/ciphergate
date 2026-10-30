# Detection benchmark

Measures what CipherGate catches and flags wrongly on generated, labelled log lines, next to other
local tools. It is an engineering aid for finding gaps. It is not part of the package, CI or the
test suite, and it never contacts a service.

## Do not use the results as a public claim

- The corpus is written by the people who wrote the detectors, so it leans toward CipherGate.
- The data is synthetic. Real logs behave differently.
- Other tools run on default settings, and their results depend on versions and models.
- A high score here does not show that sensitive data is gone from any file.

## Run it

Use a separate virtual environment, because these tools are not project dependencies:

```bash
python -m venv /path/outside/repo/venv
# Activate it, then:
python -m pip install . detect-secrets scrubadub presidio-analyzer
python -m pip install en_core_web_sm  # see the spaCy docs for the model install command
python scripts/benchmark/compare_tools.py --out /path/outside/repo/results
```

Only CipherGate is required. Any other tool that is not installed is skipped and listed under
`not run`. To include gitleaks, install it yourself and pass `--gitleaks PATH`.

`--out` must be outside the repository, because `corpus.jsonl` holds format-shaped fake
credentials that must not be committed. The tool refuses a path inside the repository. Results
are repeatable for the same `--seed` and tool versions.

## Reading the output

Each row is a data class, and each cell is caught/total. A positive counts only if the finding
overlaps the planted value; for CipherGate, the value must be gone from the output. `NEGATIVE`
counts false alarms on clean lines. `presidio@0.5` is Presidio with a 0.5 score threshold.

Random 16-digit IDs pass the card checksum about 10% of the time, so `NEGATIVE` varies by seed.
