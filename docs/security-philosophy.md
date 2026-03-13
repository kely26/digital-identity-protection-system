# Security Philosophy

DIPS is built around a simple premise: identity-risk tooling should improve user visibility without creating a second privacy problem.

This project is intentionally opinionated about local processing, defensive scope, and careful handling of sensitive data. The goal is not just to detect exposure, but to do so in a way that security engineers and privacy-conscious operators can trust.

## Local-First Security Model

The default execution path stays on the local machine.

Why that matters:

- identity-related findings often include highly sensitive information
- many users want insight without uploading local artifacts to a cloud service
- local execution keeps the trust boundary smaller and easier to reason about

In practice, DIPS prioritizes:

- local filesystem and profile scanning
- local browser posture analysis
- local report generation
- local dashboard review
- optional online enrichment only when explicitly enabled

## Privacy-Respecting Design

DIPS treats scan results as sensitive security artifacts, not casual telemetry.

That design shows up in several ways:

- report evidence is redacted by default
- breach lookups use hashed identifiers instead of plaintext values where supported
- cached data is bounded and stored locally
- demo mode uses synthetic data so screenshots and examples stay safe to publish
- exported examples and fixtures avoid real user secrets

The guiding rule is that the product should minimize exposure while measuring exposure.

## Minimal External Dependencies

DIPS avoids unnecessary service dependencies in the core product path.

Why:

- fewer mandatory external services means fewer trust assumptions
- a smaller dependency surface is easier to audit and maintain
- local-first tools remain useful in offline, restricted, or privacy-sensitive environments

Optional provider integrations exist for defensive enrichment, but they are not the baseline requirement for using the system.

## Defensive Security Focus

DIPS is a defensive security project. It is built to help users understand and reduce risk, not to weaponize information.

That means the project explicitly prioritizes:

- detection of exposure and weak posture
- explanation of risk in plain language
- remediation guidance
- safe reporting and analyst review

And it explicitly avoids:

- offensive exploitation workflows
- credential theft or vault decryption
- weaponized scanning behavior
- default cloud-first collection of local artifacts

## Safe Handling Of Sensitive Data

Identity, credential, browser, and phishing findings can all contain material that should be handled carefully.

DIPS therefore emphasizes:

- bounded file reads
- safer path handling
- local cache controls
- redacted terminal and report output
- plugin validation before activation
- graceful failure paths instead of noisy, unsafe crash output

The product is designed so that sensitive evidence is useful for investigation without being overexposed in logs, screenshots, or exported reports.

## Transparent Reporting

Security tools are easier to trust when their output is understandable.

DIPS aims for transparent reporting by:

- producing structured JSON for automation and review
- producing standalone HTML for human-readable analyst workflows
- surfacing risk scores alongside the findings that contributed to them
- keeping recommendations tied to concrete scan results
- exposing timeline and correlation data rather than hiding scoring logic behind a black box

The intent is to help users understand what was found, why it matters, and what to do next.

## Why Privacy And Defensive Scope Come First

Digital identity tooling often sits close to the most sensitive parts of a user’s environment: credentials, browser data, inbox artifacts, tokens, and personal identifiers.

If a tool in this space is careless, it can become part of the problem it is supposed to solve.

That is why DIPS favors:

- local-first execution over default remote collection
- redaction over raw disclosure
- explicit opt-in integrations over hidden external calls
- defensive visibility over offensive capability
- transparent outputs over opaque automation

The result is a tool intended to be useful for real defensive work while still respecting the privacy and trust of the person running it.
