# CipherGate — Implementation Specification for Claude Code

> **Purpose of this file:** This is the implementation contract for building CipherGate. Treat it as the project’s primary specification. Inspect the existing repository before changing anything, then implement a working, tested application—not merely a plan, scaffold, or collection of TODOs.
>
> **Important limitation:** No detector can guarantee that every sensitive value will be found in arbitrary data. CipherGate must make this limitation explicit, use conservative policies for uncertainty, provide dry-run and review workflows, and never claim that using it alone guarantees GDPR, HIPAA, PCI DSS, or any other compliance outcome.

---

## 0. Instructions to Claude Code

### 0.1 Required working behavior

1. Begin by inspecting the current working directory, repository status, files, Python version, existing conventions, and tests. Do not overwrite or delete existing user work without understanding it.
2. If the repository is empty, create the layout defined below. If it already has useful code, preserve compatible work and adapt the design rather than blindly replacing files.
3. Convert this specification into executable code in small milestones. After each milestone, run the relevant tests and fix failures before continuing.
4. Do not stop after writing a plan. Implement the application, policies, tests, documentation, packaging, and CI described here.
5. Do not leave security-sensitive functionality as a TODO, stub, `pass`, unimplemented command, silent fallback, or mocked success. If an item is outside the MVP, reject it explicitly in validation and document it as deferred.
6. Do not claim a feature works unless a test or direct verification supports that claim. In the final report, distinguish implemented, tested, partially supported, and deferred features.
7. Prefer straightforward, typed, readable Python over overengineering. Avoid unnecessary frameworks, background services, cloud dependencies, or paid APIs.
8. Do not send input data, file contents, matched values, secrets, or reports to remote services. The MVP must operate locally and must not make network requests at runtime.
9. Make safe behavior the default. If policy evaluation is ambiguous for a potentially sensitive value or destination, do not silently allow it. Require an explicit policy decision or block the operation.
10. Do not use real customer, healthcare, financial, employee, or production data in tests or examples. Use synthetic fixtures only.
11. Run formatting/linting, type checks, tests, package installation, CLI smoke tests, and any security checks that the repository supports. Fix failures rather than hiding or weakening tests to make the suite green.
12. Keep documentation aligned with actual behavior. Do not document unsupported features as implemented.
13. If a design choice is not specified, choose the option with the lower privacy/security risk, document the choice, and continue. Ask the user only if a truly blocking choice cannot be resolved safely.
14. Do not print secrets or sample raw sensitive values in terminal logs, exception messages, test failure summaries, debug output, audit reports, or telemetry. The project should not ship telemetry.
15. Avoid destructive commands. Do not change global Git configuration, install system packages, modify files outside the repository except normal test/build artifacts, or commit/push unless explicitly asked.

### 0.2 Definition of a complete first release

The first release is complete only when:

- The package installs in an isolated environment and exposes a working `ciphergate` CLI.
- CSV, JSON, JSONL, and plain text/log input are supported within documented size/encoding constraints.
- Environment-aware policies work for DEV, STG, and PRD; environment and destination are distinct, validated, reported context values.
- Included DEV/STG/PRD policy templates validate, and tests cover cross-environment data-transfer decisions.
- Inspection is non-mutating and produces a privacy-safe report.
- Policy files are schema-validated, have deterministic precedence, and cannot enable unsafe behavior by accident.
- Sanitization changes output according to policy, writes atomically, refuses accidental overwrite, and does not modify the source.
- A no-network test proves the core pipeline makes no outbound calls.
- Built-in detectors and transforms have unit, integration, adversarial, regression, and CLI tests.
- Logs and reports are tested to ensure raw matched values and secrets do not leak.
- Unknown/high-risk content is not silently passed to an untrusted destination by default.
- The README, examples, threat model, security policy, contribution guide, and release notes accurately describe the software and its limits.

### 0.3 Claude Code project tooling: skills, subagents, hooks, and integrations

Treat Claude Code tooling as part of the developer experience when it provides repeatable value. **Evaluate and implement the smallest useful setup; do not create skills, agents, hooks, MCP servers, or plugins merely to make the repository look sophisticated.** The CipherGate runtime must remain a normal Python CLI/library and must never depend on Claude Code being installed.

Before designing this setup:

1. Check the installed Claude Code version and the current official documentation for Skills, subagents, hooks, settings, and permissions. Verify the supported configuration schema instead of relying on memory or copying examples for an older version.
2. Inspect existing `.claude/` configuration before modifying it. Preserve user settings, merge changes carefully, and do not overwrite local configuration.
3. Separate project-shared configuration from machine-specific configuration. Check in only configuration that is safe and useful for all contributors. Never commit credentials, local absolute paths, personal permissions, or machine-specific settings.
4. Explain briefly in the implementation notes which capabilities were created, which were intentionally omitted, and why.

#### Skills (repeatable workflows)

Use project-level skills under `.claude/skills/<skill-name>/SKILL.md` when the workflow is repeatable and more detailed than belongs in this main file. The skill should have a clear name, short description, trigger/use guidance, and actionable steps. Keep instructions focused and maintain them with the codebase.

Assess and create these skills when they add value:

- `policy-review`: review or author CipherGate YAML policies, especially DEV/STG/PRD, source environment versus destination, rule precedence, secret handling, and fail-closed behavior. It must recommend tests for policy changes.
- `security-review`: review changes for raw-data leakage, key handling, unsafe defaults, path and atomic-write safety, false assurance, dependency/network behavior, and policy bypasses. It must report findings by severity and cite the affected files/lines; it must not claim a clean security audit without evidence.
- `test-and-verify`: run the project's relevant unit, integration, security, lint, type-check, packaging, and CLI checks; summarize exact commands and failures. It must not hide failures or weaken/remove tests to make the suite pass.
- `release-readiness`: check documented limitations, version/changelog consistency, policy validation, examples, package installation, security tests, CI status, and release checklist before a release.

Create only the skills that are useful after inspecting the repository. Do not duplicate the entire `CLAUDE.md` inside every skill. Prefer the built-in Claude Code skills/commands where they already meet the need. Skills must not need access to real production data or send project content to external services.

#### Subagents (focused independent work)

Use project subagents in `.claude/agents/` for repeatable, separable work where an independent context or constrained tool access improves results. Assess these candidates:

- `security-reviewer`: read-only review of code/config/tests for security and privacy failures; use read-only tools where supported and return prioritized findings with file/line evidence.
- `policy-engine-reviewer`: review environment/destination context, rule precedence, missing-context behavior, and DEV → STG → PRD / external destination cases; do not silently edit policies.
- `test-reviewer`: inspect coverage gaps and propose/run bounded tests without deleting or weakening existing tests.

Create only agents that solve a distinct recurring task. Use built-in Explore/Plan/code-review capabilities where sufficient. Delegate parallel, independent analysis; do not spawn agents for trivial edits or let multiple agents concurrently modify the same files. The main agent remains responsible for integrating findings, making code changes, running the full suite, and verifying results. Limit subagent tools/permissions to what each role needs; read-only reviewers should not have write or shell capabilities unless there is a documented need.

#### Hooks (deterministic guardrails and quality checks)

Hooks may be configured using the current supported Claude Code project settings format (usually under `.claude/settings.json`) and checked-in scripts under a clearly named directory such as `scripts/claude_hooks/`. Add hooks only when they are reliable, fast, deterministic, and demonstrably helpful.

Potential useful hook behavior:

- After a Python source edit/write, run a bounded local lint or syntax check against the changed file, if the installed tool and event schema can be detected safely. Report a concise status; never print source contents or values.
- On session start, optionally show a short local reminder of the project verification commands and policy/security constraints. Do not print environment variables, keys, file contents, or sensitive paths.
- Before particularly risky tool actions, consider a narrowly scoped guard only if the current hook API can identify the action reliably. Do not build a brittle generic shell-command parser or claim that a hook is a complete security boundary.

Hook requirements:

- Validate every hook's schema and behavior against the installed/current official Claude Code documentation.
- Keep hooks local-only: no network calls, telemetry, remote scripts, package downloads, or external API usage.
- Do not print or inspect secrets, raw datasets, or whole source files. Pass only the minimum event metadata required.
- Avoid destructive commands and avoid automatically running the full test suite on every file edit.
- Use bounded timeouts and predictable exit behavior. Handle missing optional tools gracefully without falsely reporting that checks passed; required CI checks remain enforced by CI.
- Document how to inspect, test, disable, and remove hooks. Never hide failures or bypass permission prompts.
- Do not use hooks as a substitute for application-level security controls, tests, or CI.

#### MCP servers, plugins, and external integrations

CipherGate's MVP is local-first and must not require MCP servers, plugins, a hosted service, or external integrations. Do not configure an MCP server just because the feature exists. Add one only for a concrete, explicitly scoped development need, document its trust boundary and permissions, avoid credentials where possible, and never send customer datasets or secrets to it. Do not use an MCP integration to turn the CipherGate runtime into a network-dependent product.

#### Recommended shared layout

Add only the files actually created and tested, for example:

```text
.claude/
├── skills/
│   ├── policy-review/SKILL.md
│   ├── security-review/SKILL.md
│   ├── test-and-verify/SKILL.md
│   └── release-readiness/SKILL.md
├── agents/
│   ├── security-reviewer.md
│   ├── policy-engine-reviewer.md
│   └── test-reviewer.md
└── settings.json               # only safe, shared project hooks/settings
scripts/
└── claude_hooks/               # only if project hooks are implemented
```

This is a candidate layout, not a requirement to create empty files. Do not commit `.claude/settings.local.json` or other local-only settings. Keep user-specific settings outside the repository. If a skill, agent, hook, MCP server, or plugin is not justified or cannot be tested safely, omit it and state why.

#### Validation and acceptance criteria for Claude Code tooling

- Any created skills have valid `SKILL.md` frontmatter and are discoverable/invocable in the installed Claude Code version where feasible.
- Any created agents have valid frontmatter, clear triggering descriptions, least-privilege tool access, and distinct responsibilities.
- Any hooks use valid current event/configuration schemas, run only local allowlisted checks, and are tested with representative event inputs.
- A hook failure never causes CipherGate itself to report data as sanitized or safe. CI and application tests remain authoritative for product correctness.
- No hook prints source values, keys, environment variable contents, or sensitive report payloads.
- The repository documents how to use the useful skills (for example `/policy-review`, `/security-review`, `/test-and-verify`, `/release-readiness`), how/when subagents are delegated to, and how to inspect/disable hooks.
- If this tooling cannot be tested because Claude Code is unavailable in the current environment, validate files structurally, document the limitation, and provide exact manual verification steps. Do not claim live Claude Code validation was performed.
- The final report lists the created artifacts, exact checks performed, and any omitted capability with a reason.

---

## 1. Product definition

### 1.1 Project name and mission

**Name:** CipherGate  
**Category:** Local-first, environment-aware, destination-aware data inspection and sanitization for developer workflows.  
**Mission:** Help developers protect logs and datasets before they move between DEV, STG, and PRD workflows or are shared with external AI tools, vendors, support teams, or other destinations.

CipherGate should feel like a dependable developer CLI and CI/CD pipeline gate: predictable, explainable, composable, scriptable, and safe to run locally. It must show why a rule was applied instead of hiding decisions behind an opaque AI model.

**Core product promise:** CipherGate checks the data, applies the policy for the source environment and intended destination, preserves useful debugging context where policy allows it, rescans the result, and blocks a release when required safeguards fail. The core tool is a data-handling gate; it does not deploy applications or change cloud infrastructure.


### 1.2 The problem it solves

Teams often create ad-hoc scripts to remove emails, credentials, identifiers, healthcare-related fields, or customer data from logs and datasets. Such scripts tend to be inconsistent, difficult to audit, domain-blind, and easy to bypass when field names, data formats, or application behavior change. CipherGate should provide:

- Detection signals from field names, value patterns, structure, and optional local detectors.
- A separate policy engine that decides what to do based on data sensitivity, confidence, field path, domain, use case, and intended destination.
- Deterministic transformations when repeatability or referential integrity is needed.
- Reports that explain decisions without disclosing the protected values.
- A conservative inspect/plan/apply workflow suitable for local use and CI pipelines.

### 1.3 Product principles

1. **Local-first:** No network calls, accounts, hosted service, telemetry, or external API is required by the core program.
2. **Policy before transformation:** Detectors identify candidates and evidence; policies decide the action; transformers execute the action. Keep these concerns separate.
3. **Explainable:** Every nontrivial action should have a stable reason code and the rule/policy that caused it.
4. **Safe by default:** No policy, invalid policy, missing key, conflicting rules, ambiguous sensitive decision, or output error must not silently fall back to allow.
5. **Data minimization:** Reports contain counts, field paths, action outcomes, confidence bands, and reason codes—not raw values.
6. **Deterministic where requested:** Keyed pseudonyms should be stable for the same value and key/scope, but not generated with plain unkeyed hashes.
7. **Useful to developers:** CLI-first, readable output, exit codes, machine-readable JSON report, simple YAML policies, and pipe/CI compatibility.
8. **Honest boundaries:** Detection is probabilistic/incomplete in some domains; a passing scan is not proof that data is safe or legally de-identified.
9. **No security by obscurity:** Document threats, assumptions, and failure behavior.
10. **Small dependable core:** Optional advanced detectors must not be necessary for core CLI use.

### 1.4 Intended users

- Software engineers preparing application logs for debugging or support.
- AI/ML engineers preparing text/data files for local experimentation or external LLM workflows.
- Data engineers sanitizing samples used in development and test environments.
- Small teams that need an auditable, code-first sanitization step in CI.

**Initial ideal customer:** A small SaaS/software engineering team that uses cloud AI assistants to debug application errors and currently relies on manual redaction, custom scripts, or developer judgment before sharing logs. The daily user is a developer; likely technical buyers are engineering/platform leads, with a CTO or founder as a potential buyer for team-level capabilities later.

**The first use case:** A developer wants help diagnosing an error and needs to prepare a log file without exposing customer identifiers, credentials, private infrastructure details, or other information prohibited by the team's policy.

**Three intended differentiators (hypotheses to validate, not claims of uniqueness):**

1. **Environment + destination-aware rules:** The same data can receive different treatment depending on whether it came from DEV, STG, or PRD and whether it is going to an approved internal tool, a staging environment, an external vendor, an external AI service, or a public repository.
2. **Useful debugging context stays useful:** Protect or transform sensitive values without needlessly deleting the error message, trace context, structure, and other information developers need—only when the selected policy permits retaining it.
3. **A data release checkpoint:** Provide a repeatable inspect → plan → sanitize → rescan workflow that can fail a CI/CD job if required checks fail. A successful scan is not proof that every risk has been found.

Do not claim these features are unique versus all competitors. Implement them well, measure false positives/false negatives and workflow usability, and validate the differentiation with real prospective users before making market claims.

### 1.5 MVP scope

Build a production-minded local CLI and Python library that can:

- Inspect local files without changing them.
- Read CSV, JSON, JSONL, and plain text/log files.
- Detect common identifiers and secret-like content using deterministic local detectors.
- Apply a versioned YAML policy to choose actions.
- Apply rules using source environment (`dev`, `stg`, `prd`, or `unknown`), optional target environment (`dev`, `stg`, `prd`, `external`, or `unknown`), domain profile, use case, and intended destination.
- Treat environment and destination as separate context dimensions. A source environment describes where the data originated; a destination describes who/what is meant to receive it.
- Redact, replace, pseudonymize, generalize, shift dates, drop fields/records, or block processing based on explicit rules.
- Provide starter environment/destination policy examples for DEV, STG, and PRD, with conservative cross-environment transfer behavior.
- Support a non-zero CI exit status when a policy blocks the release, unresolved review remains, required context is missing, or a strict rescan fails.
- Emit privacy-safe inspection/action reports.
- Rescan sanitized output for configured detector categories.
- Validate policies before use.
- Run in noninteractive CI mode with clear exit statuses.
- Use optional local detectors only when installed/configured; never download models automatically.

### 1.6 Explicit non-goals for the MVP

Do **not** build these unless the user later requests a separate scope:

- A hosted SaaS platform, user accounts, billing, analytics, or a web dashboard.
- Remote LLM-based classification or external AI APIs.
- A database-backed reversible token vault.
- Claims of legal compliance, certification, guaranteed anonymization, or guaranteed absence of sensitive data.
- Automatic production deployment or alteration of cloud resources.
- Full OCR of scanned PDFs/images, office-document processing, database connectors, message-bus integrations, or binary-file parsing.
- Enterprise secrets management, KMS integration, distributed processing, or multi-tenant services.
- Automatic mutation of input files.
- A promise to detect every name, health condition, source-code secret, proprietary fact, or indirect identifier.
- A “magic” AI confidence score that conceals uncertainty.

If the repository includes any of these already, do not remove them thoughtlessly; assess their relevance, isolate them from the core, and document the actual support level.

---

## 2. Threat model and trust boundaries

### 2.1 Assets to protect

- Raw input values and complete source files.
- Credentials, access tokens, private keys, connection strings, and passwords.
- Direct identifiers (names, emails, phone numbers, government identifiers, account numbers).
- Sensitive or regulated fields (health, financial, employment, precise location, demographics, and other domain-specific fields).
- Proprietary data and source code that may be confidential even if it is not personal data.
- Pseudonymization keys and any future mapping material.
- File paths, metadata, and reports that could themselves reveal confidential context.
- Referential relationships across records that pseudonymization is intended to preserve.

### 2.2 Adversaries and failure sources

Consider both malicious and accidental exposure:

- A developer accidentally shares an unmasked log or dataset.
- A malformed or malicious file attempts path traversal, symlink exploitation, parser abuse, resource exhaustion, or terminal/log injection.
- A detector misses a sensitive value, or a harmless value is falsely flagged.
- A user creates an overly permissive rule or misunderstands an action.
- A policy conflict or missing policy accidentally resolves to “allow.”
- An exception or debug statement prints input data.
- A report includes raw values, unique samples, or filenames that reveal sensitive data.
- A pseudonymization key is absent, weak, exposed, or changed unexpectedly.
- A file write fails partway through and leaves a partial or ambiguous output.
- A deterministic pseudonym allows linkage across contexts that should not be linked.
- A local optional detector downloads a model or calls a hosted service without the user understanding it.

### 2.3 Security objectives

- Do not modify the input file.
- Do not send data over the network.
- Do not log raw values by default—ever in normal operation.
- Fail safely on invalid configuration, missing required secrets, unresolved policy, and output integrity errors.
- Preserve record structure and value types when required by the transform contract.
- Make overwrites explicit.
- Restrict temporary data exposure and clean temporary artifacts on success/failure/cancellation where possible.
- Use keyed, domain-separated pseudonymization instead of raw hashes for stable tokens.
- Ensure any report is safe to store or share under the stated report policy.

### 2.4 Assumptions and limitations

- The tool runs with the current user's operating-system permissions; it cannot protect raw data from a fully compromised host or a malicious administrator.
- The local machine, Python runtime, and installed dependencies are trusted.
- Environment variables can be visible to sufficiently privileged local processes and diagnostic tooling; key handling must be documented accordingly.
- Text matching cannot infer every semantic meaning or indirect identifier.
- A field may be sensitive despite a benign-looking field name, and a field name may look sensitive when values are harmless.
- Safe output depends on policy quality, detector coverage, transformation correctness, intended destination, and review of the result.
- “Pseudonymized” data may remain personal data and may be linkable. Redaction/generalization does not automatically equal anonymization.

### 2.5 Fail-safe behaviors

The following must never silently degrade into an allow action:

- Invalid or unsupported policy version.
- Missing mandatory policy file when the command requires it.
- Invalid policy syntax/schema.
- Rule conflict with no valid precedence resolution.
- Keyed pseudonymization requested but key missing/empty/too short according to the documented minimum.
- Unsupported transform/action.
- Source environment, target environment, or destination required by policy but not provided.
- A source/target environment value is unsupported or conflicts with a pinned policy context.
- Parser errors in strict mode.
- Input truncation, size-limit exceeded, or record corruption that would invalidate the promised scan.
- Output write/flush/rename failure.
- A high-risk/secret detection that has no applicable rule for the destination.
- An attempt to use a reversible token action without a supported vault implementation.

On failure, exit nonzero, avoid writing a “successful” output, and provide a concise safe diagnostic with a stable error code. Do not print the raw offending value.

---

## 3. Data taxonomy and detection model

### 3.1 Separation of detection from policy

Implement three distinct phases:

1. **Detection:** Produces candidate findings, evidence, confidence, and locations. It must not decide whether the value is allowed.
2. **Policy evaluation:** Combines findings with context and returns an action, rule ID, reason code, and any required parameters.
3. **Transformation:** Applies the approved action and returns transformed data plus non-sensitive execution metadata.

Keep these interfaces small and typed. Do not embed policy decisions in regexes or detector implementations.

### 3.2 Sensitivity categories

Use stable, extensible category identifiers. The initial built-in taxonomy should include at least:

| Category ID | Meaning / examples | Notes |
|---|---|---|
| `credential.secret` | API keys, access tokens, passwords, bearer tokens, private keys, connection strings | Highest priority; never allow by default for external destinations. |
| `pii.email` | Email addresses | Can be direct identifier. |
| `pii.phone` | Telephone/mobile numbers | Locale ambiguity is high; configurable region/context. |
| `pii.person_name` | Person names | Reliable detection often needs optional local NER or field context. |
| `pii.government_id` | National/tax/social identity identifiers | Country-specific patterns only when enabled. |
| `pii.payment_card` | Payment-card-like number passing checksum/context checks | Do not treat every long digit string as a card. |
| `pii.bank_account` | Bank account / routing identifiers | Country-specific; avoid generic overclaiming. |
| `pii.address` | Postal/street address | Incomplete without context/NER; policy should reflect uncertainty. |
| `pii.date_of_birth` | Date explicitly labeled or contextually detected as DOB | Do not infer DOB merely from every date. |
| `pii.precise_location` | Exact coordinates, precise address, location trail | Coarse location may have a different policy. |
| `pii.ip_address` | IPv4/IPv6 address | Context can determine whether public, private, or sensitive. |
| `pii.device_identifier` | Device ID, advertising ID, MAC, serial, persistent device token | Configurable patterns/field names. |
| `pii.customer_identifier` | Customer/member/patient/user identifiers that can link to people | Treat as high-risk if external or cross-dataset linkability matters. |
| `health.phi` | Patient/clinical/health-related values and identifiers | Generic text detection is incomplete; profile and field context matter. |
| `financial.sensitive` | Account, transaction, tax, salary, balance, or credit-related data | Domain policy determines appropriate transformation. |
| `employment.sensitive` | Employee IDs, salary, performance, HR case data | Domain policy determines handling. |
| `network.telemetry` | Internal hostnames, URLs, internal IPs, trace IDs, request IDs | May be safe in one context and revealing in another. |
| `proprietary.source` | Private source code, internal architecture, business rules, proprietary strings | Not all source-code/IP can be reliably detected by a generic scanner. |
| `security.internal` | Internal endpoints, topology details, security findings | Context-based classification. |
| `location.coarse` | City/region/approximate location | Often safer than precise location but still context-dependent. |
| `identifier.generic` | Unknown/custom identifiers that may link records | User-defined category supported. |
| `unknown.sensitive_candidate` | A candidate requiring policy/review because classification is uncertain | Do not treat as a finding-free allow. |

Categories must be extensible through policy configuration and, where appropriate, a detector plugin interface.

### 3.3 Detection evidence and confidence

A detection finding should include, where applicable:

- `category`: stable taxonomy ID.
- `source`: detector ID, such as `field_name`, `email_regex`, `luhn_card`, `secret_pattern`, or optional plugin ID.
- `confidence`: normalized numeric value in `[0.0, 1.0]` plus a named band (`low`, `medium`, `high`).
- `location`: safe structural locator (CSV column name/index and row number; JSON pointer; JSONL line; text line/character span where useful).
- `evidence_codes`: safe metadata such as `field_name_match`, `pattern_match`, `checksum_valid`, `context_keyword`, never a copy of the matched value.
- `field_path`: canonical path string.
- `value_type`: original basic data type, not the value itself.
- `sensitivity`: derived policy label if applicable.

Never put a raw matched value in a `Finding`, exception, log, audit record, or default CLI output. Internal transform code necessarily handles source values in memory but should not retain them longer than needed.

Use confidence to explain evidence and resolve explicit policy thresholds; do not present a numeric score as a calibrated probability unless calibration has been demonstrated. Detector confidence values are engineering estimates, not statistical guarantees.

### 3.4 Field-name and structural heuristics

Build configurable field-name heuristics for common names and variations, e.g.:

- Email: `email`, `e_mail`, `email_address`, `contact_email`.
- Phone: `phone`, `mobile`, `telephone`, `contact_number`.
- Person name: `name`, `first_name`, `last_name`, `full_name`, `patient_name`, `employee_name`.
- DOB: `dob`, `date_of_birth`, `birth_date`, `birthdate`.
- Credentials: `password`, `passwd`, `secret`, `api_key`, `access_token`, `refresh_token`, `authorization`, `private_key`, `client_secret`.
- Payment: `card_number`, `pan`, `cvv`, `bank_account`, `routing_number`.
- Health: `patient`, `diagnosis`, `condition`, `medication`, `medical_record`, `mrn`, `claim`, `member_id`.
- Location: `lat`, `latitude`, `lon`, `lng`, `longitude`, `gps`, `address`, `street`, `postal_code`, `zip`.
- Identifiers: `user_id`, `customer_id`, `account_id`, `member_id`, `employee_id`, `device_id`, `session_id`, `request_id`, `trace_id`.

These are examples, not an exhaustive universal dictionary. Avoid treating every `id`, `name`, `key`, `value`, or `token` field as automatically the same sensitivity in every domain. Support exact, case-insensitive, normalized, glob, and regex-based field/path matching in policy. Normalization can remove punctuation and compare snake_case/camelCase variants, but retain the original field path in output.

### 3.5 Built-in deterministic detectors

Implement deterministic local detectors for at least:

- Email-like addresses.
- Phone-like numbers with configurable locale/context and conservative confidence.
- IPv4 and IPv6 addresses using standard library validation rather than regex alone.
- Payment-card-like sequences with Luhn validation and contextual clues; avoid reporting arbitrary long digit strings as high confidence.
- Common secret formats / high-risk keywords plus pattern families: bearer credentials, common cloud/API token formats where feasible, private-key PEM headers, connection-string/password patterns, and assignment-style `password=...` / `api_key: ...` values. Never include the match in output.
- Dates in supported formats, but classify as DOB only with explicit field/context evidence; otherwise use a broader `date`/`unknown` signal.
- IPv4/IPv6, URL and hostname-like values where enabled.
- User-configured custom regex detectors with validation and safety controls.

Avoid dangerous catastrophic-backtracking regexes. Prefer bounded patterns and document the limits. If custom regex support uses Python `re`, reject or warn on obviously risky constructs where feasible; impose file/record size limits and allow a strict configuration that rejects unsafe regex forms. Do not claim full regex safety based on a heuristic validator.

Optional local NER / Microsoft Presidio integration may be offered as an extra, but:

- It must not be required for base installation.
- It must never download models or contact a service automatically.
- It must detect availability and fail with a clear, safe message if explicitly enabled but missing.
- It must disclose that local models can still be incomplete and can consume significant resources.
- Tests for the core package must run without optional detectors installed.
- No optional detector may override an explicit deny/block rule or bypass policy evaluation.

### 3.6 Free text and structured data

- Scan text values in structured formats as well as field names.
- For JSON, recursively visit object properties and array items; use stable JSON Pointer paths with proper escaping (`~` to `~0`, `/` to `~1`).
- For JSONL, process one JSON document per non-empty line, report line-numbered parse errors, and never silently drop malformed lines.
- For CSV, preserve column order and header names; handle quoted separators, embedded newlines, escaped quotes, empty cells, BOM, and configurable delimiter/encoding. Do not split CSV by naïve commas.
- For logs/text, support line-by-line scanning, with configurable multiline secret/private-key detection if implemented. If multiline state is unsupported, document this clearly and ensure sensitive key headers trigger conservative handling.
- Empty strings, null, booleans, zero, numeric identifiers, and repeated values must not be confused with missing data.

### 3.7 Domains and policies: not one rule for all data

CipherGate must not assume that “PII found” implies “replace everything with `[REDACTED]`”. Policy should express the purpose, destination, domain profile, sensitivity, confidence, and desired utility. Examples:

- A request ID may be useful for debugging within an approved internal environment but unsuitable for external sharing if it links back to a user.
- An IP address may be needed for incident analysis but could disclose internal network topology.
- An email might be replaced by a stable pseudonym to preserve joins, while the original domain might need to be generalized or removed.
- A date of birth may be generalized to a year or age band rather than shifted exactly.
- A clinical diagnosis is materially different from a patient identifier; both may need protection but for different reasons.
- A credential should generally be removed or block the release, not merely masked partially, because leaving a prefix/suffix can still leak context.
- Source code or internal business logic may require an explicit review process rather than simplistic regex redaction.

Provide starter profiles as templates and state clearly that the user must review them for their environment. Profiles are not legal advice, certification, or guaranteed-safe defaults for every workflow.

---

## 4. Policy engine specification

### 4.1 Core requirement

The policy engine is the most important component. It must be deterministic, independently testable, and separate from detection and transformation code. Policies describe what action to take, not how a detector works.

### 4.2 Context passed to the policy engine

Policy evaluation must consider all of these dimensions independently:

- `environment`: the environment the input data originated from; allowed values are `dev`, `stg`, `prd`, or `unknown`.
- `target_environment`: the environment that will receive the output, if it is an internal environment; allowed values are `dev`, `stg`, `prd`, `external`, or `unknown`.
- `destination`: the actual intended recipient/channel, e.g. `local_dev`, `approved_internal`, `staging_test`, `production_monitoring`, `external_vendor`, `external_ai`, `public_repository`, or `unknown`.
- `domain_profile` (e.g. `developer_logs`, `test_dataset`, `healthcare`, `financial`, `general`).
- `use_case` (e.g. `debugging`, `analytics`, `training`, `external_llm`, `support_bundle`, `test_fixture`).
- Sensitivity category and confidence band/threshold.
- Field name/path, format, value type, and detection evidence.
- Rule priority and explicit allow/deny scope.
- Run mode (`dry_run` vs `apply`) without changing what decision a policy would choose.

#### 4.2.1 Environment semantics (mandatory)

- `environment` means **where the source data came from**, not where CipherGate is installed and not the destination. In the CLI, `--environment` is the friendly flag; `--source-environment` may be provided as an explicit alias. Both represent the same source context.
- `target_environment` means where the output dataset will be used when that destination is another application environment. Use `external` for an external service/vendor/AI destination when the profile needs the distinction. It is separate from `destination`.
- `destination` states the actual recipient/channel and must not be guessed from the source environment. `environment=prd` does not automatically mean a file is approved for production monitoring; `environment=dev` does not make the content safe.
- Context may be supplied by a policy or by explicit CLI flags. If a policy pins a context field and a CLI-supplied value conflicts with it, fail with a safe context-conflict error unless that policy explicitly permits an override. Never silently change the effective environment. Record effective context and any permitted override in the report.
- A strict/environment-aware sanitization run must receive enough context to choose a policy. Missing `environment`, required `target_environment`, or required `destination` must fail closed or require review; never silently assume DEV or a trusted destination.
- Environment is policy context only. CipherGate does not inspect cloud-account identity, verify which infrastructure is truly DEV/STG/PRD, control deployment approvals, or prevent a user from lying about a CLI argument. CI/CD integration should source context from controlled pipeline configuration where possible and document this trust boundary.

#### 4.2.2 Required baseline posture by environment

These are baseline product defaults and starter-policy requirements. Teams may create stricter rules. Relaxing them must require explicit policy edits and a clear validation warning.

- **DEV:** Optimize for developer feedback and debugging, but do not assume data is fake. Protect credentials in all environments. Use synthetic data where practical. Real customer data, production-derived logs, and secrets in a developer's local workspace remain subject to policy. DEV may be more permissive only for explicitly approved destinations and categories; it must never allow secrets to external destinations by default.
- **STG:** Treat staging data as potentially production-derived. Prefer synthetic or appropriately masked datasets. Do not treat STG as safe merely because it is non-production. Copying raw PRD data into STG must block or require explicit reviewed policy approval after required transformations and rescan. Staging credentials are still secrets and should not be exposed externally.
- **PRD:** Apply the strictest defaults to data leaving production. Credentials/secrets must be blocked from external release unless transformed into a safe non-secret representation; they must never pass through by default. Direct/indirect identifiers and sensitive business fields require explicit policy decisions. External AI, vendor, public-repository, or unknown destinations require strict sanitization and a residual-finding gate. Approved internal production monitoring may retain selected fields only under explicit destination- and field-specific rules.
- **UNKNOWN:** No implicit allow. For strict/enforcement workflows, block or require review until source environment and destination context are supplied.

#### 4.2.3 Cross-environment transfer rules

- `dev -> stg`: allow only according to the test/staging policy; secrets remain blocked and identifying/customer data must follow explicit rules.
- `prd -> stg`: treat raw production-derived data as blocked by default. It may proceed only if a reviewed policy explicitly permits the intended transformed dataset, all required checks succeed, and the residual scan passes. A passing scan is a useful gate, not a guarantee of safety.
- `prd -> external` / `external_ai` / `external_vendor` / `public_repository`: use the strict external-release posture. Block credentials; transform or block customer identifiers, internal infrastructure details, and sensitive fields as required; fail on unresolved high-risk findings.
- `prd -> approved internal monitoring`: apply an explicit allowlist of the fields/categories needed for the monitoring purpose; never assume every field is safe because the recipient is internal.
- `dev -> prd`: CipherGate is not a deployment system. If it is used to gate a data file headed into production, apply the target-production policy and fail closed on secrets or unresolved prohibited data. Do not interpret this as permission to deploy code or production configuration.
- Any transfer involving `unknown`, an unrecognized environment, or an unrecognized destination must not resolve to an implicit allow.

#### 4.2.4 Rule selectors

Rules must be able to match one or more environment and destination dimensions, using validated selectors such as:

- `environments: [dev, stg, prd]` for source environment.
- `target_environments: [dev, stg, prd, external]` where target context matters.
- `destinations: [external_ai, external_vendor]` for named destination channels.
- Existing selectors for categories, field names/paths, domain profile, use case, and confidence.

Reject invalid environment values and misspelled selectors during policy validation. Use a documented `unknown` value rather than treating absence as `dev`. Selector matching must be deterministic and fully covered by tests.

Do not infer that a destination is trusted just because it is omitted. If a policy requires a destination and none is provided, validation/evaluation should fail closed.

### 4.3 Actions

Implement these actions in the MVP where technically applicable:

- `allow`: retain value. Must be explicit when the default policy would otherwise mask/block it. Rules allowing high-risk categories for an external destination should require deliberate explicit acknowledgement in policy validation and report a prominent warning; by default, reject or block clearly dangerous secret/credential allowances.
- `redact`: replace a text value with a constant marker such as `[REDACTED:pii.email]`; marker should be configurable and safely escaped for structured formats.
- `replace`: replace with a configured safe constant (e.g. `example.invalid`, `0000000000`, a synthetic category-specific value). Validate replacement compatibility and avoid accidentally making fake values real-world identifiers.
- `pseudonymize`: produce a deterministic pseudonym via HMAC-SHA-256 using a required secret key and domain separation. Never use plain SHA-256 of values as a privacy-preserving pseudonym. Support scope choices such as category-wide or field-scoped; default to the narrowest appropriate scope to avoid unnecessary cross-context linkage. Make the scope explicit in policy.
- `generalize`: reduce precision based on a supported strategy (e.g. date to year or month/year, age to bands, coordinate rounding/geographic grid) and reject unsupported strategies.
- `date_shift`: shift dates using a configured policy. For per-entity consistent shifting, derive a deterministic offset from a keyed pseudonym scheme or provide an explicit documented strategy. Do not shift unrelated dates independently if the requirement is to preserve temporal relationships. Support bounds and leap-day behavior tests.
- `drop_field`: remove a JSON property / CSV column only when configured to do so. For CSV, row-level field deletion has a schema consequence; implement column dropping at file/schema level and clearly report it. For text/log lines, field deletion is not supported unless a structured parser has identified a field.
- `drop_record`: remove an entire record/line/row. This must be explicit; show record counts and reason codes, not row contents.
- `block`: stop release/application because this class of content is not permitted. Do not write a successful output; partial output must not remain at the final destination.
- `review`: indicate that a human decision is needed. In the default apply mode, a review-required finding must prevent the output from being treated as successfully sanitized unless a policy clearly defines a safe replacement/action. A report-only review should not make a high-risk unreviewed output appear safe.

`tokenize`/reversible lookup is **not** part of the first release without a separate, carefully reviewed token-vault design. If a policy specifies reversible tokenization, policy validation must reject it with an actionable error. Never quietly implement it as pseudonymization.

### 4.4 Default actions and default policy behavior

Provide a conservative built-in default policy/profile that can be used for a local first run, but make scope obvious. Recommended starting behavior:

- Credentials/secrets: `block` for unknown/external destinations; a policy may `redact` in a safe local copy, but the tool must never pass credentials through by default to external destinations.
- High-confidence direct identifiers: `redact` or keyed `pseudonymize` based on configured goal; if the needed key is missing, stop rather than allow.
- High-risk/ambiguous content: `review` or `block`; never infer `allow` from an absent rule for an untrusted destination.
- Low-risk categories: explicit profile-specific action; no global claim that low confidence means safe.
- Unknown structured fields: scan values, preserve only when rules and destination context permit; report unclassified fields without echoing values. For an unknown/external destination, a configurable strict profile should block or require review if suspicious patterns are detected.

An inspection command can always report potential findings without writing an output. Applying a policy must respect explicit block/review conditions.

### 4.5 Rule precedence and conflict resolution

Design and document a deterministic precedence order. Recommended:

1. Invalid configuration, missing required context, or hard security constraints (cannot be overridden by ordinary allow rules).
2. Explicit hard block rules for credentials/secrets and blocked destinations.
3. Environment-boundary guardrails, including the configured rules for PRD-to-STG and PRD-to-external transfers.
4. More specific path/field/category rules.
5. Destination/use-case/environment/domain-profile-specific rules.
6. Sensitivity category rules.
7. Confidence threshold rules.
8. Profile defaults.
9. Conservative engine fallback (`review` or `block`), never universal `allow`.

Within the same precedence level, use explicit integer `priority`, then stable declaration order only if the schema clearly documents it. Prefer policy validation to reject equally ranked conflicting rules rather than silently choose. Never let a broad low-priority `allow` override a more specific block or hard security constraint.

The policy engine must return the decision explanation: `action`, `rule_id`, `reason_code`, matching criteria (safe metadata only), any required transform options, and whether a human review is required.

### 4.6 Policy file format and validation

Use YAML for human-authored policy. Validate with Pydantic (or an equally strict typed schema). Reject unknown keys by default except in an explicitly versioned `metadata`/extension namespace. Validate regexes, action parameters, category IDs, profile names, confidence ranges, environment values (`dev`, `stg`, `prd`, `unknown`), target environment values (`dev`, `stg`, `prd`, `external`, `unknown`), destination names, field selectors, replacement values, and key references. Include a `policy_version`/schema version.

Illustrative shape (adjust field spelling to match the final typed schema, but keep semantics):

```yaml
policy_version: 1
name: developer-log-safe-share
metadata:
  description: "Starter template for preparing PRD-origin developer logs for an external AI destination. Review before use."
context:
  environment: prd
  target_environment: external
  domain_profile: developer_logs
  use_case: debugging
  destination: external_ai
settings:
  strict: true
  unknown_sensitive_behavior: review
  fail_on_parse_error: true
  report_raw_values: false
rules:
  - id: block-credentials
    priority: 1000
    match:
      categories: [credential.secret]
    action: block
    reason: credentials_are_not_permitted_for_this_destination

  - id: pseudonymize-email
    priority: 300
    match:
      categories: [pii.email]
      min_confidence: 0.80
    action: pseudonymize
    params:
      key_env: CIPHERGATE_HMAC_KEY
      scope: category
      prefix: "email_"
    reason: replace_email_but_keep_repeatable_join_key

  - id: redact-phone
    priority: 250
    match:
      categories: [pii.phone]
    action: redact
    params:
      marker: "[REDACTED:pii.phone]"
    reason: remove_phone_number

  - id: generalize-date
    priority: 200
    match:
      field_names: [birth_date, date_of_birth, dob]
    action: generalize
    params:
      strategy: year
    reason: preserve_year_only
```

This is an example of intended semantics, not a demand to copy an unsafe or invalid schema blindly. Make the final schema consistent across code, examples, and docs. If a referenced action needs a key, validate key availability at execution time without printing the key.

### 4.7 Starter policy profiles

Include template profiles, clearly marked **templates requiring review**:

- `dev_local`: source environment `dev`, target environment `dev`, destination `local_dev`; support useful debugging context while still protecting credentials and any real customer/sensitive data detected by policy.
- `stg_test`: source environment `stg`, target environment `stg`, destination `staging_test`; prefer synthetic/appropriately masked data; treat production-derived data as potentially sensitive.
- `prd_external_ai`: source environment `prd`, target environment `external`, destination `external_ai`; strict export posture, credential block, explicit rules for direct/indirect identifiers and internal infrastructure details, and strict rescan gate. A blocked run must not publish a final output file.
- `developer_logs`: credentials block; emails/phones are redacted or pseudonymized; internal hostnames/IPs and user IDs are policy-controlled; request/trace IDs can be retained only for declared trusted contexts; unknown high-risk values require review.
- `test_dataset`: use synthetic replacement values; stable pseudonyms where cross-row joins matter; protect dates, identifiers, and contact details; report fields with uncertain classification.
- `external_ai`: strict external-destination posture for any supported source environment; block credentials; require explicit policies for direct/indirect identifiers and sensitive data; block or review unclassified suspicious values; never claim that a successful run is automatically safe for a particular AI provider.
- `healthcare_template`: distinct rules for identifiers versus clinical/health values; do not claim HIPAA compliance; highlight that re-identification risk and applicable legal requirements require expert review.
- `financial_template`: distinguish credentials, payment card data, bank/account identifiers, transaction metadata, and amounts; do not claim PCI DSS compliance.
- `local_debug`: more permissive behavior may be possible for a trusted local destination, but hard blocks and report privacy constraints remain.

Environment templates must not duplicate policy-engine logic. They should be declarative policies using the same validated schema. Provide examples for DEV, STG, and PRD and test each example. The examples should demonstrate that source environment alone does not grant permission; the destination and data category still matter.

Avoid duplicating policy-engine logic by domain. Profiles should be declarative data.

### 4.8 Explainability and report reasons

Use stable, machine-readable reason codes, for example:

- `credential_detected_hard_block`
- `explicit_policy_match`
- `field_name_sensitive`
- `value_pattern_match`
- `confidence_below_rule_threshold`
- `no_applicable_rule_requires_review`
- `unsupported_transform`
- `destination_required_but_missing`
- `environment_required_but_missing`
- `target_environment_required_but_missing`
- `environment_context_conflict`
- `unsupported_environment`
- `policy_conflict`
- `key_missing`
- `parse_error`
- `size_limit_exceeded`

Reason strings must not include values, keys, regex matches, or raw input excerpts.

---

## 5. Pseudonymization and transform safety

### 5.1 HMAC-based pseudonymization

Implement deterministic pseudonymization using `hmac` and `hashlib` from the Python standard library. Requirements:

- Key material comes from a named environment variable or another explicit secure local source configured by the user. Never hardcode a secret or use a checked-in default key.
- Require a documented minimum key length (recommend at least 32 random bytes of effective key material; explain that base64/hex strings need decoding or length checks done consistently).
- Never print the key, a prefix of the key, or environment variable contents.
- Use domain separation with an unambiguous, versioned context, such as `ciphergate:v1:<profile>:<category>:<scope>`, plus a delimiter-safe encoding for the original value.
- Do not mix values of different types ambiguously. Normalize consistently per policy (e.g. convert to a canonical UTF-8 representation with type information) and document it.
- Provide a configurable namespace/scope (`field`, `category`, or explicitly named entity scope) to control linkability. Default to narrow scope; broader linkage must be deliberate.
- Use a sufficiently long digest prefix and encoding to make collisions extremely unlikely for the expected data volume; avoid short tokens. Detect collision within a run where feasible and fail/warn safely.
- Include a transform version so future changes do not silently change outputs without documentation.
- No original-value mapping is stored.
- HMAC is pseudonymization, not anonymization. Reusing the same key/scope allows linking equal values.

Use safe encodings such as URL-safe base64 or hex, with optional category prefix. Preserve source type only when the policy explicitly defines a safe typed replacement. If a numeric-looking identifier must stay numeric, do not take arbitrary digest digits and pretend that this preserves its original semantics; use a documented deterministic numeric mapping only if it is carefully designed and tested, otherwise output a string and state the type change or require `replace`.

### 5.2 Key handling

- Read key material only when a transform needs it.
- Do not accept a key via a command-line flag because process listings and shell history can expose it.
- Prefer an environment variable such as `CIPHERGATE_HMAC_KEY`; a separate key file support may be implemented only with restrictive file-permission checks and explicit documentation.
- On platforms with different permission models, document what can and cannot be enforced.
- Never write keys to policy files, reports, sample output, logs, exception messages, test snapshots, or documentation.
- Never create a fallback key when key lookup fails.
- Tests should generate ephemeral keys and verify that no key is present in files or output.
- Test behavior when the same key is reused, the key changes, and the required key is absent.

### 5.3 Redaction and replacement

- A replacement marker should identify category only if that is acceptable; do not embed source data.
- Escape the marker according to the output format; CSV should rely on a correct CSV writer, and JSON should use a JSON serializer.
- Avoid replacement values that look like real credentials or real personal identifiers. Use reserved/test domains (for example `.invalid`) and synthetic conventions.
- Test Unicode, embedded delimiters, quotes, newline characters, nulls, and unusual value types.
- Do not partially mask secrets by default. Full redaction or a block action is safer.

### 5.4 Generalization and date shifting

Support only well-defined strategies in the first release, e.g.:

- Dates: exact date to year, year-month, or another explicitly configured precision.
- Age: configurable bands, with protection against overflow and negative values.
- Geographic coordinates: round precision or map to a coarser grid, with documented limitations.
- Numeric ranges: optional bins only when explicitly configured.

For date shift:

- Support input formats explicitly; do not guess a date where parsing is ambiguous without policy.
- Preserve relative relationships for a configured subject/entity scope if that is the policy goal.
- Define behavior for leap days, timezone offsets, timestamps, epoch values, and invalid dates.
- Do not shift a timestamp by parsing it as a naive date if timezone correctness matters.
- Test boundary dates, DST/timezone offset handling, invalid values, and stable offsets.

### 5.5 Data integrity

- Keep JSON types unchanged for actions that promise type preservation.
- Preserve CSV header ordering and row ordering unless an explicit action drops fields/records.
- Preserve empty cells, quoted strings, escaped newlines, and the distinction between missing/null/empty/zero/false.
- JSON output formatting need not byte-match source whitespace, but semantically unchanged values should remain unchanged where no transform applies.
- Record all type-changing transformations in safe metadata.
- When dropping a field changes file schema, show the changed schema in a privacy-safe report.

---

## 6. Input/output formats and parser behavior

### 6.1 Supported formats

MVP:

- `.csv`
- `.json`
- `.jsonl` and `.ndjson`
- `.txt`, `.log`, and explicitly selected plain text

Support format auto-detection only when unambiguous. Always provide an explicit `--format` override. Do not infer a safe format from filename alone if content contradicts it. Unknown extensions should require `--format` or a clear parser choice rather than guessing.

### 6.2 Size and resource controls

- Configure maximum input bytes, record/line bytes, nesting depth, number of findings, and optional processing time budget where practical.
- Do not read arbitrarily large files fully into memory by default. Stream CSV/JSONL/text line-by-line where possible. JSON parsing may require whole-document parsing; apply a documented size limit unless a robust streaming parser is added.
- Reject excessive JSON nesting/oversized lines safely.
- Count bytes and records; detect if input changed while being processed when feasible.
- Never silently truncate input and still report successful sanitization.
- A size-limit failure must leave no final output presented as sanitized.
- Make limits configurable with conservative defaults and documented units.

### 6.3 Encoding and newline behavior

- Default to UTF-8, with safe handling of a UTF-8 BOM.
- Support an explicit encoding option if appropriate. Do not silently replace undecodable bytes without surfacing the fact.
- Offer strict failure by default on decoding errors; a documented replacement mode may be available for inspect-only or explicit lossy processing.
- Preserve or normalize newlines according to a documented mode; test LF and CRLF.
- Avoid writing malformed or incomplete content as a successful output.

### 6.4 CSV specifics

- Use Python's `csv` module or a tested equivalent; never split rows on commas manually.
- Support quoted separators, quoted newlines, escaped quotes, empty fields, duplicate/empty headers (define a behavior), BOM, CRLF, and configurable delimiter/quote settings if implemented.
- Handle duplicate header names safely. Do not merge columns silently. Either reject duplicate headers in strict mode or internally disambiguate them while preserving a documented output/header policy.
- Validate row width. In strict mode, inconsistent columns should fail the operation; a tolerant inspect mode may report row-width issues but must never silently conceal them.
- Preserve column order. Dropped columns must be handled at the dataset level.
- Numeric-looking fields remain text unless an explicit schema/type option says otherwise; CSV itself does not type values.
- Do not log malformed row contents.

### 6.5 JSON specifics

- Support objects, arrays, nested objects, nested arrays, strings, numbers, booleans, and null.
- Traverse values and optionally keys only when an explicit policy enables key scanning; keys may be user-defined and can themselves disclose data.
- Use JSON Pointer-compatible paths and escape special characters correctly.
- Reject duplicate object keys in strict mode or preserve/report them with a carefully chosen parser strategy; do not silently discard duplicates without documentation.
- Set explicit limits for depth and bytes.
- Use UTF-8 JSON output and valid serialization. Preserve number/string types when no transform applies.
- Handle JSON parser error messages without echoing source excerpts.

### 6.6 JSONL specifics

- Each non-empty line represents one JSON value/object according to configuration.
- Preserve blank lines only if configured and documented.
- Report parse errors by line number and error code, never include the raw line.
- Process sequentially with bounded memory.
- If `fail_on_parse_error` is true, stop and remove temporary output. If false, do not silently copy malformed records unchanged into an output advertised as sanitized; require an explicit per-policy handling rule such as block/drop/quarantine and report the exact count. The safest default is fail.

### 6.7 Text/log specifics

- Treat each line as text and scan for patterns; never treat a text file as structured key/value data unless a parser is explicitly selected.
- Provide a conservative text sanitizer for direct patterns and secrets.
- Do not promise that arbitrary log messages are fully classified.
- Multiline private keys, stack traces, JSON fragments, URLs, connection strings, escaped secrets, and encoding variants are important adversarial cases. Implement supported cases and document gaps honestly.
- An optional structured-log parser may be a later extension; do not claim support for every log format.

### 6.8 File safety and paths

- Resolve paths carefully and check input/output relationships.
- Never overwrite source input. Reject output resolving to the same file/inode as input, including common symlink/path alias cases.
- Protect against path traversal when user-controlled names are used to create output/report files.
- Do not automatically follow symlinks when doing directory batch processing unless an explicit safe design supports it. If symlinks are encountered, default to reject/report them rather than following them outside the intended root.
- Use restrictive permissions for temp/output/report files where supported by the OS (e.g. owner-only where practical); explain platform differences.
- Avoid leaking sensitive filenames in reports where that may matter; support basename or redacted path output.
- Refuse to process special files/devices/FIFOs by default; handle only regular files unless explicitly supported.
- Do not recursively traverse a directory in the MVP unless carefully implemented with skip rules and symlink protections.

---

## 7. Reports, logs, and audit metadata

### 7.1 Privacy-safe reporting

Reports should answer “what was found, where, and what decision was made?” without exposing the source data. A report may include:

- Run ID generated locally (random, non-sensitive).
- UTC timestamp.
- CipherGate version.
- Input basename or safely configured path representation; optional privacy setting to suppress names.
- Input format, total bytes, record/line counts.
- Policy name/version and digest (digest of policy contents can be included if computed without secrets).
- Source `environment`, optional `target_environment`, destination, use case, and domain profile.
- Whether the environment was policy-pinned or supplied on the command line, and whether an explicit permitted override occurred.
- Counts by category, detector, action, and confidence band.
- Counts of unclassified/high-risk candidates, parse errors, dropped records, blocked findings, and review items.
- Safe field paths / line numbers where useful.
- Rule IDs and reason codes.
- Whether output was written, withheld, blocked, or needs review.
- Keyed-pseudonymization configuration identifier, but never the key or any derivation of the key.

Do not include by default:

- Raw matched values or snippets.
- Full input lines/rows/documents.
- Passwords, tokens, private key contents, authorization headers, or connection strings.
- Pseudonymization key material.
- A reversible mapping table.
- A “sample value” for each category.

A hashed fingerprint of the original value is also potentially linkable and must not be included by default. If a future diagnostic fingerprint is added, require explicit opt-in and use a keyed digest with clear linkability warning.

### 7.2 Logging

- Use standard `logging` with controlled verbosity.
- Normal logs must not include source values.
- `--verbose` may expose additional process metadata but still must not expose raw values.
- `--debug` must not turn on data dumping. It may include stack traces only when they contain no input values; otherwise sanitize the exception/context before printing.
- Keep third-party parser error messages from echoing input. Wrap/sanitize them where necessary.
- Ensure terminal output escapes control characters to prevent log/terminal injection.
- Do not add a telemetry/analytics system. No reporting to a remote service.

### 7.3 Report formats

Support a human-readable terminal summary and a machine-readable JSON report. A YAML report is optional. Reports should have a versioned schema and be stable enough for CI consumers. Use deterministic field ordering where practical.

### 7.4 Output rescan

Provide `ciphergate rescan` (or an equivalent inspect mode for sanitized output) that runs configured detectors against output and reports residual candidate findings. Rescan is a useful quality gate but not proof of safety. It should:

- Use an explicit or referenced policy.
- Never show matched values.
- Support a strict “fail if any category in this set remains” mode.
- Clearly distinguish allowed residuals from unexpected residuals.
- Not automatically mutate output as a side effect.

---

## 8. CLI and Python API

### 8.1 CLI goals

Use `typer` or a comparable lightweight CLI library. Use `rich` only if it helps and keep a plain output mode for CI. All commands must have usable `--help`, predictable exit codes, clear errors, and no data disclosure.

### 8.2 Required commands

Implement these commands (exact subcommand syntax may be improved, but features must remain available):

1. `ciphergate --version`
2. `ciphergate init` — create a starter policy with an explicit warning that the template needs review; do not overwrite existing policy files unless `--force` is supplied.
3. `ciphergate validate-policy POLICY.yml` — validate schema and semantic constraints without reading any input dataset.
4. `ciphergate inspect INPUT --policy POLICY.yml` — detect and report findings; never alter source or create sanitized output.
5. `ciphergate plan INPUT --policy POLICY.yml` — preview intended decisions and estimated action counts; no output data file is written.
6. `ciphergate sanitize INPUT --policy POLICY.yml --output OUTPUT --apply` — apply approved transformations. Require explicit `--apply`; without it, show/emit a plan only. Refuse overwrite unless `--force`.
7. `ciphergate rescan INPUT --policy POLICY.yml` — inspect potential residual findings in an existing sanitized output; never alter it.

Optional command:

- `ciphergate explain --policy POLICY.yml --field PATH --category CATEGORY --environment prd --destination external_ai` to explain policy outcomes for a hypothetical finding without needing raw values. Support `--target-environment` when applicable.

The CLI can support stdin/stdout for pipelines if implemented safely, but the first release must support regular file paths robustly. If stdin/stdout is implemented, document output/report separation, broken pipes, error handling, and the fact that stdout should not accidentally contain human logs mixed with JSON data.

### 8.3 Key flags

Provide appropriate options such as:

- `--policy PATH`
- `--output PATH`
- `--format csv|json|jsonl|text`
- `--report PATH`
- `--report-format json|text`
- `--environment dev|stg|prd|unknown` (source data environment; `--source-environment` may be provided as an alias)
- `--target-environment dev|stg|prd|external|unknown` when the output is headed into a known target environment
- `--destination NAME` (recipient/channel, distinct from the source and target environment)
- `--use-case NAME`
- `--profile NAME`
- `--strict / --no-strict` where semantics are clear
- `--max-bytes N`
- `--encoding NAME`
- `--force`
- `--apply`
- `--quiet`
- `--verbose`
- `--no-color`
- `--version`

Avoid a proliferation of overlapping flags. Source and target context may be set in policy or supplied as explicit CLI context. If an explicit CLI value conflicts with a policy-pinned value, fail unless the policy has an explicit, validated override setting. All effective environment/destination values and permitted overrides must appear in the report. Never silently default an omitted environment to `dev` or a destination to trusted.

### 8.4 Exit codes

Define stable documented exit codes, for example:

- `0`: operation succeeded; no blocking/review failure under the selected policy and all required environment/destination context was validated.
- `1`: policy block or unresolved review item prevented safe completion.
- `2`: command-line usage or invalid arguments.
- `3`: policy syntax/schema/semantic validation error.
- `4`: input parse/encoding/size/format error.
- `5`: output I/O/atomic-write/permission error.
- `6`: required key or transform configuration missing/invalid.
- `7`: residual finding caused strict rescan failure.
- `8`: unexpected internal error (safe message; debug traceback may be available without input data).

Choose a coherent mapping, test each code path, and document it. Do not use exit code zero when the file was only partially processed or the policy requires review/block.

### 8.5 Python API

Expose a small stable public API, e.g.:

- `load_policy(path) -> Policy`
- `validate_policy(policy) -> ValidationResult`
- `inspect_file(path, policy, context=None) -> InspectionReport`
- `plan_file(path, policy, context=None) -> SanitizationPlan`
- `sanitize_file(input_path, output_path, policy, context=None, options=None) -> SanitizationReport`
- `rescan_file(path, policy, context=None) -> InspectionReport`

Use typed return objects. Do not make internal modules the public API by accident. Document the supported API and versioning expectations.

---

## 9. Atomic writes and error handling

### 9.1 Output write contract

- Never write directly to the final target before successful processing.
- Write to a temporary file in the same filesystem/directory as the destination (or a clearly safe temp location with compatible atomic rename semantics), flush, and `fsync` when supported/appropriate.
- Apply restrictive permissions as early as practical.
- Rename atomically to final output only after processing and policy checks complete.
- Use a no-overwrite default. If `--force` is given, implement a clear, documented replacement strategy that does not risk deleting the previous output before the new one is complete.
- Ensure the final output is not created when a block/review/parse/write failure should prevent release.
- Clean up temporary files on normal exceptions and cancellation signals where possible.
- If cleanup fails, report the temp path safely and tell the user to remove it; do not expose raw data in the diagnostic.

### 9.2 Cancellation and partial output

Handle `KeyboardInterrupt` and supported termination signals so the application does not claim successful completion. Close files, clean temp output, and exit nonzero. Do not suppress termination indefinitely. If an output is produced by streaming, do not place it at the final target until all rules and parser checks are satisfied.

### 9.3 Exceptions

Create a small exception hierarchy with stable error codes and safe user messages, such as:

- `CipherGateError`
- `PolicyValidationError`
- `DetectionError`
- `TransformError`
- `InputFormatError`
- `InputLimitError`
- `UnsafePathError`
- `OutputWriteError`
- `MissingKeyError`
- `PolicyBlockedError`

Avoid exposing raw parser snippets, secrets, filesystem paths beyond what is needed, or data values in exceptions. The internal exception cause may be chained for debugging, but CLI rendering must sanitize it.

---

## 10. Repository structure

Use a clear package layout similar to the following. Adapt names only when repository conventions justify it; preserve the separation of concerns.

```text
ciphergate/
├── pyproject.toml
├── README.md
├── CLAUDE.md
├── LICENSE                     # choose/document a license; do not invent one silently
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md           # optional but recommended
├── .gitignore
├── .editorconfig
├── .pre-commit-config.yaml
├── .claude/                     # project skills/agents/hooks only when justified
│   ├── skills/
│   ├── agents/
│   └── settings.json            # safe, shared settings only; validate current schema
├── scripts/
│   └── claude_hooks/            # optional local-only hook scripts, if implemented
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── policy-schema.md
│   ├── detector-coverage.md
│   ├── security-and-privacy.md
│   ├── limitations.md
│   └── examples.md
├── policies/
│   ├── dev_local.yml
│   ├── stg_test.yml
│   ├── prd_external_ai.yml
│   ├── developer_logs.yml
│   ├── test_dataset.yml
│   ├── external_ai.yml
│   ├── healthcare_template.yml
│   ├── financial_template.yml
│   └── local_debug.yml
├── examples/
│   ├── sample.csv
│   ├── sample.json
│   ├── sample.jsonl
│   ├── sample.log
│   └── expected/                 # sanitized synthetic examples only
├── src/
│   └── ciphergate/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── constants.py
│       ├── errors.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py
│       │   ├── policy.py
│       │   ├── report.py
│       │   └── plan.py
│       ├── readers/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── csv_reader.py
│       │   ├── json_reader.py
│       │   ├── jsonl_reader.py
│       │   └── text_reader.py
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── field_names.py
│       │   ├── email.py
│       │   ├── phone.py
│       │   ├── ip_address.py
│       │   ├── payment_card.py
│       │   ├── dates.py
│       │   ├── secrets.py
│       │   ├── custom_regex.py
│       │   └── registry.py
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── loader.py
│       │   ├── validator.py
│       │   ├── engine.py
│       │   └── precedence.py
│       ├── transforms/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── redact.py
│       │   ├── replace.py
│       │   ├── pseudonymize.py
│       │   ├── generalize.py
│       │   ├── date_shift.py
│       │   ├── drop.py
│       │   └── registry.py
│       ├── pipeline/
│       │   ├── __init__.py
│       │   ├── inspector.py
│       │   ├── planner.py
│       │   ├── sanitizer.py
│       │   ├── rescan.py
│       │   └── atomic_output.py
│       └── reporting/
│           ├── __init__.py
│           ├── serializer.py
│           ├── terminal.py
│           └── audit.py
└── tests/
    ├── conftest.py
    ├── unit/
    │   ├── test_detectors_*.py
    │   ├── test_policy_*.py
    │   ├── test_transforms_*.py
    │   ├── test_readers_*.py
    │   └── test_reporting_privacy.py
    ├── integration/
    │   ├── test_csv_pipeline.py
    │   ├── test_json_pipeline.py
    │   ├── test_jsonl_pipeline.py
    │   ├── test_text_pipeline.py
    │   ├── test_atomic_output.py
    │   └── test_cli_e2e.py
    ├── security/
    │   ├── test_no_raw_value_leaks.py
    │   ├── test_path_safety.py
    │   ├── test_policy_fail_closed.py
    │   └── test_no_network.py
    ├── regression/
    │   └── test_known_cases.py
    └── fixtures/                  # synthetic only
```

Do not create every file as an empty placeholder. A smaller set of well-designed modules is better than empty architecture theatre, but keep the named boundaries reflected in actual code.

---

## 11. Technology, packaging, and coding standards

### 11.1 Runtime and dependencies

- Target Python `>=3.11` unless the existing repository has a compelling supported baseline. State the exact supported versions in `pyproject.toml` and CI.
- Use `pyproject.toml` with a standard build backend such as Hatchling or setuptools.
- Keep runtime dependencies limited. Suggested baseline: `typer`, `pydantic`, `PyYAML`; `rich` optional for presentation. Prefer the Python standard library for HMAC, hashing, CSV, JSON, IP validation, logging, filesystem operations, and temporary files.
- Dev dependencies may include `pytest`, `pytest-cov`, `ruff`, `mypy` or `pyright`, and `pre-commit`.
- Optional detectors must be declared as extras, not imported unconditionally.
- Pin or bound dependencies responsibly; use a lockfile if the chosen workflow supports one. Do not claim an SBOM/security scan exists unless generated and tested.
- Do not add packages without explaining why they are needed. Prefer known maintained libraries and review transitive dependencies.

### 11.2 Type and quality standards

- Type hints for public APIs and important internal methods.
- Pydantic models or typed dataclasses for policy, findings, plans, and reports.
- Consistent naming, small functions, meaningful error types, and readable control flow.
- No broad `except Exception: pass` patterns.
- No swallowed detector/transform errors; classify them and fail safely.
- No unused public methods or misleading abstractions.
- Keep secrets out of object representations (`repr=False` on secret fields where applicable); preferably do not store secret values inside long-lived models.
- Avoid global mutable registries that make tests order-dependent.
- Make deterministic behavior testable.
- Keep dependencies and imports cycle-free.
- Use stable reason/error codes; avoid parsing human error strings in tests.

### 11.3 Configuration

- Define one typed settings model for operational limits and one typed policy model for data-handling rules. Do not mix user policy with machine runtime settings unnecessarily.
- Provide secure defaults. Document every setting that can weaken security or increase data disclosure.
- Environment variables may configure key names/paths and operational options; do not silently override policy decisions with environment variables.
- Avoid ambient configuration that makes identical command lines behave differently without an explicit report note.

### 11.4 License and dependencies

Do not silently choose a license. Inspect whether the user/repository already selected one. If not, include a concise license-selection note in the final report and either:

- use a clearly labelled placeholder file only if release is blocked pending user choice, or
- choose a common permissive license only if the repository owner has clearly asked for that default.

Do not paste third-party code without checking licensing and attribution.

---

## 12. Testing strategy (mandatory)

Tests should verify behavior, not merely exercise code. Use only synthetic fixtures. For every detector, include positive cases, negative cases, edge cases, and known ambiguity cases.

### 12.1 Detector tests

At minimum:

- Valid/invalid emails, Unicode/local-part behavior where supported, punctuation and trailing delimiters.
- Phone number formats, country prefixes, extension numbers, numbers with too few/many digits, dates and IDs that resemble phone numbers.
- IPv4 boundary cases, invalid octets, IPv6 compressed forms, bracketed/port forms where supported, hostnames that resemble IPs.
- Card-like values with valid and invalid Luhn checksum, separators, leading zeros, and long numeric identifiers that should not be high-confidence cards absent context.
- Secret-like strings across supported pattern families, false-positive examples, multiline private-key headers, bearer tokens, environment assignments, URLs with userinfo, and escaped/quoted values.
- Date formats, ambiguous locale dates, timestamps, null bytes, invalid dates, timezone offsets.
- Field-name normalization across snake_case, camelCase, kebab-case, abbreviations, case changes, and misleading fields (e.g. `monkey`, `token_count`, `key_name`).
- Custom regex validation, invalid regex, zero-length match, overly long patterns, and bounded input behavior.
- Ensure the exact raw match is never present in returned public finding representations or log output.

### 12.2 Policy tests

- Every action and supported action parameter.
- Profile/context selection and explicit CLI overrides.
- `dev`, `stg`, `prd`, and `unknown` environment handling; invalid values rejected.
- Environment and destination dimensions remain distinct; `environment=prd` must not imply `destination=production_monitoring` or any other trusted destination.
- `prd -> stg` and `prd -> external` behavior follows the strict policy defaults; required missing context fails closed.
- Environment-pinned policy conflicts with CLI arguments fail safely unless a tested, explicit policy override is enabled.
- Specificity and precedence rules.
- Conflicting equal-precedence rules rejected or resolved exactly as documented.
- Broad allow cannot override hard block.
- Missing destination/environment/target environment when required fails closed.
- Missing key fails; no generated fallback key.
- Unknown category/action/parameter fails validation.
- Unsupported `tokenize` action fails validation with safe error.
- Invalid confidence thresholds and invalid paths rejected.
- No matching rule for high-risk external content leads to review/block, not allow.
- Policy load is deterministic and doesn't execute arbitrary YAML tags or code.

### 12.3 Transform tests

- Redaction and replacement with Unicode, quotes, comma, tabs, CR/LF, null-like text, and output-format escaping.
- HMAC pseudonym stability for same key/value/scope; separation across fields/categories/scopes; changes when key changes; adequate output length; no original string leakage; no key leakage; no raw hash used.
- Correct behavior for empty string, null, booleans, integers, floats, leading-zero identifiers, and values with Unicode normalization differences.
- Generalization boundaries, unsupported strategy rejection, coordinates and date values.
- Date shift: stable per-entity behavior where configured, leap days, timezone offsets, DST-adjacent timestamps, min/max supported date range, invalid date, and no accidental partial parsing.
- Dropped field/record counts and schema handling.
- Block produces no final output.
- Review never silently counts as safe application.

### 12.4 Reader/writer tests

- CSV delimiters, quotes, embedded newlines, duplicate headers, empty headers, BOM, CRLF, blank lines, mismatched row widths, empty file, very large field, and UTF-8 decode errors.
- JSON nested structures, arrays, nulls, booleans, numbers, unusual Unicode, escaped keys, duplicate keys, invalid syntax, excessive depth, and oversized input.
- JSONL blank lines, valid records around malformed records, invalid UTF-8, and very long lines.
- Text with no findings, repeated findings, Unicode, control characters, Windows newlines, multiline content, and secret boundaries.
- Data not selected by a transform remains semantically unchanged.
- Format output can be parsed by a standard parser.

### 12.5 Pipeline and CLI tests

- `inspect` never alters source or writes sanitized output.
- `plan` predicts the same decisions as apply mode.
- No `--apply` means no output data file is written.
- Sanitization preserves source; output content reflects policy.
- Existing output is not overwritten without `--force`.
- Input and output same path is rejected, including symlink aliases where test platform allows.
- Atomic output leaves no final file on block, parse error, cancellation, or write error.
- Temporary file cleanup is attempted and tested.
- Report output contains counts and safe paths but not raw values.
- Exit codes match documented semantics.
- `--quiet`, `--verbose`, and `--no-color` do not change transformation decisions.
- CLI works through `python -m ciphergate` and installed entry point.
- Broken pipe and stdout/report separation if stdin/stdout support is implemented.

### 12.6 Security and adversarial tests

- Raw sensitive values absent from stdout, stderr, logs, JSON reports, exception strings, and snapshots.
- API keys and private-key strings do not appear in stack traces.
- Terminal escape/control characters are safely escaped.
- Symlink/path traversal and output alias protections.
- Special files are rejected where supported.
- No network: patch/fail socket-level connection attempts or use a suitable test harness; run a core CLI path with network access prohibited where feasible.
- Malformed policy YAML cannot instantiate arbitrary objects or execute code.
- Resource-limit behavior on giant lines, deep nesting, too many findings, and pathological regex inputs.
- Cancellation cleanup and atomic output safety.
- No source file mutations and no unexpected temp files.
- No secrets or sensitive test values checked into examples; use obviously synthetic values.

### 12.7 Property-based and fuzz tests

Use Hypothesis if added as a development dependency; otherwise use parameterized generative tests. Useful invariants:

- Parser/serializer round-trip preserves unaffected data semantically.
- No supported transform ever emits an unhandled exception for supported input types; unsupported types fail with typed errors.
- Redaction output never contains the matched raw value when the marker differs from it.
- Same HMAC key/value/scope yields same pseudonym.
- Applying a deterministic sanitizer twice is idempotent where intended (document exceptions, e.g. marker handling).
- Output is parseable whenever successful.
- No output final target exists after a failed strict run.

Do not make tests brittle by asserting implementation details that have no security or API significance. Add regression tests whenever a bug is fixed.

### 12.8 Coverage and quality gates

Aim for at least 85% line coverage overall and 95% coverage for policy precedence, key handling, atomic output, privacy-safe reporting, and hard-block paths. Coverage is not proof of security. Do not game coverage by excluding sensitive modules from reports.

CI should run on at least Linux and on the supported Python versions; add Windows/macOS jobs if feasible. Test platform-specific permissions/path behavior conditionally and document differences.

---

## 13. Privacy and compliance boundaries

### 13.1 No compliance guarantees

CipherGate is a software utility, not legal advice, a compliance management system, or a certified de-identification service. Policies named for healthcare, finance, GDPR, HIPAA, or PCI DSS are **starter templates only**. Do not write “HIPAA-compliant,” “GDPR-compliant,” “PCI-compliant,” or “guaranteed anonymized” as a product claim.

Documentation should say, as applicable:

- A detector can miss values, especially contextual, free-text, multilingual, encoded, or domain-specific content.
- Pseudonymized data can still be personal data or otherwise confidential.
- Re-identification risk depends on auxiliary information, uniqueness, linkage, context, and release conditions.
- De-identification requirements vary by jurisdiction and use case; expert review may be required.
- HIPAA Safe Harbor and Expert Determination are distinct approaches; the existence of a profile named healthcare does not satisfy either one by itself.
- PCI DSS applicability depends on environment and data-handling scope; a regex scan does not validate compliance.
- A successful run means that the configured processing completed under the selected policy. It does not prove the result contains no sensitive information.

### 13.2 Domain-specific warnings

- **Healthcare/PHI:** Clinical text, patient identifiers, dates, free-text notes, rare conditions, small geographic areas, and combinations of quasi-identifiers may remain identifying. Do not claim clinical concept removal or HIPAA de-identification unless a separately scoped, validated process exists.
- **Finance/payment:** Card-like pattern checks are incomplete. Do not claim that a scan removes all payment-card data or validates PCI scope. Secrets/financial identifiers may need stricter handling than masking a card-like value.
- **Credentials/secrets:** Pattern detection has false negatives. A sanitized sample must never be assumed credential-free simply because no pattern matched. The user should consider secret rotation if a credential has already been exposed.
- **Logs/telemetry:** Request IDs, hostnames, trace IDs, timestamps, URLs, exception messages, and user-defined fields can reveal identities or system architecture through linkage.
- **Source code/proprietary IP:** Generic PII scanners do not detect all proprietary logic, trade secrets, or copyrighted material. A human review and repository-specific rules may be necessary.

### 13.3 Safe examples

Use fictitious domains such as `example.com`, `example.org`, and `example.invalid`, synthetic IDs such as `USER_TEST_001`, obviously fake keys such as `TEST_ONLY_NOT_A_CREDENTIAL`, and non-routable/reserved examples where appropriate. Never use real secret formats copied from production. Ensure example strings are clearly marked nonfunctional.

---

## 14. Documentation requirements

### 14.1 README.md

Include:

- One-sentence mission and problem statement.
- Explicit “what it is / what it is not” section.
- Feature list aligned with the actual implementation.
- Supported input formats and limits.
- Installation commands for a clean environment.
- Quick start from policy initialization through validate, inspect, plan, sanitize with `--apply`, and rescan.
- Example policies and synthetic input/output.
- Policy and action semantics.
- Key setup instructions without asking users to put secrets in command history or checked-in files.
- CLI exit codes and common troubleshooting.
- Security/privacy design and report behavior.
- Detector coverage and known limitations.
- Contribution/testing instructions.
- License status and disclaimer.

### 14.2 docs/architecture.md

Describe data flow and actual module responsibility boundaries. Include a small diagram, for example:

```text
Input file
   ↓
Safe parser / format adapter
   ↓
Structure + field/value detectors
   ↓
Findings (no raw values in public metadata)
   ↓
Policy engine (context + precedence + fail-closed fallback)
   ↓
Plan / review / block decision
   ↓
Transform registry
   ↓
Temporary output → validation → atomic publish
   ↓
Privacy-safe report + optional residual rescan
```

Explain error paths, trust boundaries, key use, report generation, and where optional detectors fit.

### 14.3 docs/policy-schema.md

Document every policy field, type, default, valid action, action parameter, rule precedence, context source, conflict rule, and failure behavior. Include valid and invalid examples.

### 14.4 docs/detector-coverage.md

For each detector document:

- What it targets.
- Positive/negative examples using synthetic values.
- Context required.
- Confidence behavior.
- Locale/format limitations.
- Known false positives/negatives.
- Optional vs base dependency status.
- Test coverage location.

Do not call detection coverage “complete.”

### 14.5 docs/threat-model.md and docs/security-and-privacy.md

Include assets, adversaries, assumptions, failure modes, mitigation, residual risk, data-flow, key handling, reports, local-only/no-network posture, dependency risks, and how to report a vulnerability.

### 14.6 SECURITY.md

Include a responsible vulnerability-reporting process and realistic response expectations. Do not invent an email address. If no security contact has been provided, use repository-hosting guidance or a clearly labelled placeholder requiring maintainer configuration before public release.

### 14.7 CONTRIBUTING.md

Describe setup, test/lint/type-check commands, synthetic-only fixtures, policy compatibility requirements, security-sensitive review expectations, changelog updates, and a definition of ready-to-merge.

### 14.8 CHANGELOG.md

Add an initial unreleased/first version entry that accurately describes what is implemented. Follow a consistent changelog format.

---

## 15. CI, repo hygiene, and supply-chain controls

Create a GitHub Actions workflow that:

- Installs supported Python versions and dependencies in a clean environment.
- Runs Ruff formatting/linting (or selected equivalent), type checks, unit/integration/security tests, and coverage.
- Installs the package and runs `ciphergate --help`, `ciphergate --version`, policy validation, and a synthetic end-to-end example.
- Does not need credentials or external services.
- Does not upload raw datasets, secret fixtures, or test artifacts containing sensitive values.

Add `.gitignore` entries for virtual environments, build artifacts, caches, coverage, local data, real datasets, output files, secrets/env files, temporary files, and editor/OS artifacts. Do not ignore policy templates or synthetic examples.

Recommended safeguards:

- `.env`, `.env.*` and local key files ignored; if an example env file exists, it must contain only placeholders and an explicit warning.
- Pre-commit for formatting, linting, and basic secret checks if configured.
- Dependency vulnerability checks may be added, but document exactly which tool runs and whether the workflow is advisory or blocking.
- No hardcoded secrets.
- No automatic release/publish credentials required for CI.
- Before public package publication, check package-name and repository naming availability; do not block local development on this check and do not claim a domain/trademark clearance that has not been performed.
- No version badge or security claim unless its underlying workflow exists.
- Never store real raw inputs as test fixtures, GitHub artifacts, screenshots, or logs.

---

## 16. Example user journey and acceptance examples

These are behavioral requirements; test strings are synthetic and must not be treated as real personal information.

### 16.1 Local setup

Expected developer workflow (adjust exact syntax only if needed; keep it consistent everywhere):

```bash
python -m venv .venv
# Activate the environment using the command for the current shell/OS.
python -m pip install -e ".[dev]"
ciphergate --version
ciphergate init --output ciphergate-policy.yml
ciphergate validate-policy ciphergate-policy.yml
```

If an init target already exists, initialization must fail safely unless the user explicitly requests `--force`.

### 16.2 Inspect without changing the input

```bash
ciphergate inspect examples/sample.csv --policy policies/developer_logs.yml --environment dev --destination local_dev --report inspection.json
```

Acceptance:

- Source file hash/content is unchanged.
- No sanitized data output is created.
- Summary gives counts by category/action/reason.
- Matched values do not appear in terminal output or report.
- Any high-risk finding without a safe applicable rule is visibly review/block status.

### 16.3 Plan

```bash
ciphergate plan examples/sample.jsonl --policy policies/external_ai.yml --environment prd --target-environment external --destination external_ai
```

Acceptance:

- No output data file is written.
- Planned actions match actual apply-mode decisions for the same context/policy.
- Summary explains blocked/review items and estimated output changes.

### 16.4 Sanitize

```bash
export CIPHERGATE_HMAC_KEY="<set-a-locally-generated-random-key; do not commit it>"
ciphergate sanitize examples/sample.csv \
  --policy policies/prd_external_ai.yml \
  --environment prd \
  --target-environment external \
  --destination external_ai \
  --output build/sample.sanitized.csv \
  --report build/sample.report.json \
  --apply
```

The example command is illustrative; ensure the actual policy action and key requirements match the selected profile. Never place a real key in the file. Consider platform-specific quoting in documentation.

Acceptance:

- Without `--apply`, no sanitized file is written.
- With `--apply`, transformations match the policy.
- Source remains unchanged.
- Output is not overwritten without explicit `--force`.
- If the policy blocks or requires unresolved review, no final output is published.
- Report describes actions without recording raw values or keys.
- Output file is syntactically valid for its format.

### 16.5 Rescan

```bash
ciphergate rescan build/sample.sanitized.csv --policy policies/prd_external_ai.yml --environment prd --target-environment external --destination external_ai
```

Acceptance:

- Rescan is read-only.
- Findings are not assumed to prove or disprove overall safety; residual categories are clearly identified.
- Strict mode fails when configured forbidden categories remain.

### 16.6 Policy conflict

Given a high-priority credential block and a broad low-priority allow, the credential block must win. If two equally ranked contradictory rules cannot be disambiguated, validation must reject the policy and tell the user which rule IDs conflict—without exposing data values.

### 16.7 Missing key

Given a policy requiring HMAC pseudonymization, if the configured key is absent or invalid, `plan`/`inspect` may report the required configuration without applying any transform; `sanitize --apply` must fail safely, must not fall back to redaction or allow, and must not create a final output unless the policy explicitly defines a separately validated fallback action. Prefer no implicit fallback.

### 16.8 Secrets

If a synthetic test input contains a fake credential-like string and the policy says `block`, `sanitize --apply` must exit nonzero, create no final output, and show only category, location, reason code, and remediation—not the token itself.

### 16.9 DEV/STG/PRD environment matrix (mandatory)

Create synthetic fixtures and automated tests proving that context changes policy outcomes. Use the same synthetic values across scenarios so tests prove the context logic—not merely differences in the files.

| Source environment | Target / destination | Expected baseline behavior |
|---|---|---|
| `dev` | `dev` / `local_dev` | Protect credentials and sensitive identifiers according to the local debugging policy; retain only explicitly permitted diagnostic context. Local execution does not mean sensitive values are automatically safe. |
| `stg` | `stg` / `staging_test` | Prefer synthetic or approved masked data; treat staging records as potentially production-derived; block/review high-risk unhandled values. |
| `prd` | `external` / `external_ai` | Strict external-release policy; credentials block, identifying/sensitive fields are transformed or blocked as configured, and unresolved high-risk findings prevent publication of the final output. |
| `prd` | `stg` / `staging_test` | Block by default unless an explicit, reviewed policy permits the intended transformed dataset and the configured checks/rescan succeed. |
| `prd` | `prd` / `production_monitoring` | Permit only explicitly allowlisted monitoring fields/categories; credentials remain blocked from output by default. |
| `unknown` | any destination | Fail closed or require review when the selected policy is strict; never assume `dev`. |

The tests must verify environment and destination are independent: changing only `environment` can change the policy outcome, changing only `destination` can change the policy outcome, and a policy-pinned context conflict fails safely. At least one integration test must show a PRD-to-external block leaves no final output file. Do not make a successful rescan or a user-supplied environment string sound like proof that the source is truly safe or truly from that environment.

---

## 17. Implementation plan and ordering

Work in the following order. It is acceptable to improve sequence if dependencies require it, but complete all MVP requirements.

### Milestone 1 — Repository baseline and typed models

- Inspect repository and document current state.
- Set up packaging, dev tools, src layout, CLI entry point, errors, constants.
- Implement typed policy/finding/report/plan/context models.
- Create basic tests and CI skeleton.
- Verify install and basic `--help` / `--version`.

### Milestone 2 — Policy loader and fail-closed engine

- Implement YAML safe loading and strict schema validation.
- Validate semantic rule fields, source/target environments, destinations, actions, parameters, and profile names.
- Implement documented precedence/conflict behavior and context pinning/override behavior.
- Add unit tests for hard blocks, missing rules, conflicts, unknown actions, missing context, and environment/destination mismatch.
- Define and test the baseline DEV/STG/PRD posture and the PRD-to-STG/external release rules.

### Milestone 3 — Readers and data locations

- Implement CSV, JSON, JSONL, and text/log adapters.
- Add size/encoding/depth constraints and path protections.
- Preserve structure/types according to format contracts.
- Test malformed and adversarial files.

### Milestone 4 — Built-in detectors

- Implement field-name heuristics, email, phone, IP, payment-card, date/context, and secret patterns.
- Add detector registry and custom regex support with safeguards.
- Add positive/negative/ambiguous tests.
- Make detector findings free of raw matched values.

### Milestone 5 — Transform registry

- Implement redact, replace, keyed HMAC pseudonymize, generalize, date shift, drop field, and drop record where valid for each format.
- Reject unsupported actions and invalid parameters.
- Add deterministic, typing, and leakage tests.

### Milestone 6 — Inspection, planning, sanitization pipeline

- Connect readers → detectors → policy → planner → transforms.
- Implement inspect/plan/apply workflows and review/block behavior.
- Implement atomic output and temp-file cleanup.
- Add report generation and rescan.

### Milestone 7 — CLI completion

- Implement init, validate-policy, inspect, plan, sanitize, rescan, and optional explain commands.
- Stable exit codes, safe error messages, output/report separation, help docs.
- End-to-end CLI tests.

### Milestone 8 — Policies and examples

- Write starter profiles for DEV/local debugging, STG/test data, PRD/external AI, general logs, test datasets, external AI, healthcare template, finance template, and local debug.
- Include a synthetic environment matrix showing different policy outcomes for the same finding across DEV, STG, and PRD and across destinations.
- Create synthetic input and expected output examples.
- Validate all included policy files in CI.
- Ensure no samples use real identifiers or real credentials.

### Milestone 9 — Security and resilience pass

- Run the security test suite, leakage tests, no-network test, path tests, malformed-input tests, and atomic-write failure tests.
- Review all logging and exception paths.
- Review key handling, regex resource concerns, report privacy, and unsafe rule allowances.
- Resolve severe findings before calling the release ready.

### Milestone 10 — Documentation and release readiness

- Complete README, architecture, threat model, policy schema, detector coverage, limitations, SECURITY, CONTRIBUTING, changelog, and license notes.
- Run all checks from a fresh environment.
- Re-run example workflow from the README.
- Provide final implementation summary and honest limitations.

---

## 18. Acceptance checklist (use as the final verification checklist)

### Product behavior

- [ ] CLI package installs and entry point works.
- [ ] `init`, `validate-policy`, `inspect`, `plan`, `sanitize`, `rescan` work.
- [ ] CSV/JSON/JSONL/text inputs supported and tested.
- [ ] Core workflow works without network access or optional models.
- [ ] Detector, policy, and transform layers are separate.
- [ ] Report-only inspection and dry-run/plan never modify source or write sanitized output.
- [ ] Apply mode requires explicit confirmation flag.
- [ ] High-risk unhandled content blocks or requires review under strict/external profiles.
- [ ] Action semantics and precedence are documented and tested.
- [ ] Unsupported action is rejected explicitly.

### Security and privacy

- [ ] No raw value leaks through CLI output, logs, reports, errors, tracebacks, or test snapshots.
- [ ] No network calls from core code paths.
- [ ] No hardcoded keys or fallback keys.
- [ ] HMAC pseudonymization is scoped, versioned, deterministic, and tested.
- [ ] Keys are not accepted through command-line arguments.
- [ ] Invalid policy, missing key, parser errors, and blocks fail safely.
- [ ] Output is atomically published; failed runs do not leave a final sanitized file.
- [ ] Output overwrite and input/output path collision protections work.
- [ ] Temporary-file cleanup and interruption behavior are tested.
- [ ] Input size/depth limits and regex/resource protections exist.
- [ ] Reports avoid raw values and avoid unkeyed value fingerprints by default.
- [ ] Synthetic fixtures only.

### Engineering quality

- [ ] Tests cover happy path, edge cases, negative cases, malformed inputs, and adversarial cases.
- [ ] Coverage goals met or shortfall explicitly documented with rationale.
- [ ] Lint, formatting, type checks, and CI pass.
- [ ] Policy files are validated in CI.
- [ ] README examples execute as written in a clean environment.
- [ ] Dependencies are minimal and optional integrations are truly optional.
- [ ] Documentation accurately reflects feature availability and limitations.
- [ ] No empty placeholder modules or unimplemented promised commands.
- [ ] Version and changelog are consistent.

---

## 19. Final response required from Claude Code

When implementation work is complete, return a concise but concrete report with these sections:

1. **Implemented:** Files/modules and features completed.
2. **Verification:** Exact commands run and pass/fail outcomes for tests, coverage, lint, format, type checks, package install, CLI smoke test, policy validation, end-to-end sample, and no-network/leakage tests.
3. **Security decisions:** How fail-closed behavior, key handling, raw-value non-logging, atomic writes, path safety, and policy conflicts are implemented.
4. **Known limitations:** Unsupported formats, detector gaps, optional extras, platform caveats, and anything not proven by tests.
5. **Deferred work:** Anything deliberately not implemented, why, and what would be required to add it safely.
6. **User actions required:** E.g. choose a license, review domain policy templates, generate a local HMAC key, or configure a maintainer security contact. Do not ask the user to share secrets.

Do not say “all cases are covered” or “zero risk.” Explain that comprehensive tests reduce risk but cannot eliminate detector false negatives, policy mistakes, or re-identification risk. Do not claim compliance guarantees.

---

## 20. CipherGate product differentiation and roadmap discipline

CipherGate’s potential differentiation is a hypothesis to validate—not an established market fact. The intended three-pillar product direction is: (1) environment-aware and destination-aware policies for DEV/STG/PRD and external sharing; (2) utility-preserving sanitization that keeps useful debugging context when policy permits; and (3) a repeatable inspect → plan → sanitize → rescan release gate for local use and CI/CD. Existing tools may already support parts of this. The team must benchmark CipherGate against existing tools and validate that the combined workflow is simpler and useful before making uniqueness or superiority claims. Do not add a dashboard, agent, hosted API, or enterprise feature before the CLI works reliably.

Potential later milestones, not required for MVP:

- Optional, explicitly installed local NER/Presidio integration.
- Structured application log parsers and user-defined parser plugins.
- Repository-specific policy packs and CI integrations.
- More locale-aware identifiers and custom detector packs.
- A carefully designed reversible token vault only after a separate threat model, access control design, key lifecycle design, recovery policy, and security review.
- Database/Parquet/PDF support, each with a separate parser/security scope.
- Human-review export/import workflow with integrity protection and a clear rule for treating reviewed data as approved.
- Statistical disclosure-risk reports for structured/tabular data, without misrepresenting them as proof of anonymization.

A future feature should be added only when it improves a concrete use case without weakening core security guarantees or expanding scope beyond what can be tested.

---

## 21. Start here

Now inspect the repository and begin implementation. First report a short internal task breakdown in the working notes if useful, but do not wait for user approval. Follow the milestones above, create and test the actual project, and continue until the first-release acceptance checklist is met or a genuine environmental blocker prevents it. If anything cannot be completed, implement the safest useful subset, document exactly what is missing, and do not present the project as fully release-ready.
