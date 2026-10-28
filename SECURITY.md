# Security policy

## Reporting a vulnerability

> **Maintainer action required before public release:** no security contact has been
> configured. Replace this notice with a monitored private channel (for example, GitHub private
> vulnerability reporting on the hosting repository, or a dedicated security mailbox).

Until then, do not file public issues containing exploit details or real data. Report privately
to the repository owner through the hosting platform's private reporting feature.

Please include: affected version, a description of the issue, and reproduction steps using
**synthetic data only**. Never send real datasets, credentials or keys.

## What to expect

This is a small project without a dedicated security team. Best effort: acknowledgement within
7 days, an initial assessment within 30 days, and coordinated disclosure once a fix is available.
No bug bounty is offered.

## Scope

In scope: raw-value or key leakage through output/reports/logs/errors, fail-open policy paths,
unsafe file handling, parser resource exhaustion, network access from the core.
Out of scope: detector false negatives on their own (see docs/limitations.md) — but reports of
missed common patterns are welcome as normal issues with synthetic examples.

If a credential was exposed before sanitization, rotate it; CipherGate cannot un-share data.

## Supported versions

Only the latest release (currently 0.1.0a1, alpha pre-release) receives fixes.
