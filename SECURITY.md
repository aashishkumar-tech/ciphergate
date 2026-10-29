# Security policy

## Reporting a vulnerability

Use either private channel:

- **Preferred: GitHub private vulnerability reporting.** Open the
  [Report a vulnerability](https://github.com/aashishkumar-tech/ciphergate/security/advisories/new)
  form (Security tab, then "Report a vulnerability"). The report is visible only to you and the
  maintainers, and the fix can be coordinated in a private advisory.
- **Email: [aashishkumar.tech@gmail.com](mailto:aashishkumar.tech@gmail.com)**, with the
  subject starting `[ciphergate security]`.

Report privately. Do **not** open a public issue, pull request or discussion for a
vulnerability, and do not include exploit details anywhere public before a fix is released.

Examples of what to report:

- raw input values, matched text or HMAC keys leaking through output, reports, logs, errors or
  tracebacks;
- fail-open paths, where a missing rule, key, context or configuration lets content through;
- bypasses of the credential hard constraint, the context gates or the residual rescan gate;
- unsafe file handling (path aliasing, symlinks, overwrite, partial output on failure);
- parser or regex resource exhaustion;
- any network access from the core.

Please include:

- the affected version (`ciphergate --version`) and your OS / Python version;
- a description of the issue and its impact;
- reproduction steps, a policy snippet and input that use **synthetic data only**
  (`example.invalid`, `TEST_ONLY_*`).

**Never send real datasets, production logs, credentials or keys**, even redacted ones. Email is
not encrypted and no PGP key is offered.

## What to expect

This is a small project without a dedicated security team. Target response times (best effort,
not a contractual SLA):

| Step | Target |
|---|---|
| Acknowledge your report | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix or mitigation for critical issues | within 30 days of assessment |

You will be kept informed. Disclosure is coordinated: details are published (as a GitHub
security advisory or release note) once a fix is available, with credit if you want it. No bug
bounty is offered.

## Scope

In scope: the examples listed above, in the `ciphergate` package, CLI and shipped policy
templates. Out of scope: detector false negatives on their own (see `docs/limitations.md`).
Reports of missed common patterns are welcome as normal issues with synthetic examples.

If a credential was exposed before sanitization, rotate it: CipherGate cannot un-share data.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest pre-release / release) | yes |
| anything older | no |

Only the latest release receives fixes.
