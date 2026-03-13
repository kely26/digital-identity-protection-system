# Feature Documentation

## Platform Scope

DIPS is a local-first digital identity defense platform for Windows and Linux. It focuses on detection, hygiene analysis, analyst visibility, and privacy-respecting reporting rather than offensive capability.

## Core Scanner Modules

### Identity Exposure Scanner

Purpose:

- find plaintext identity indicators and secrets in the configured scan scope

Detects:

- email addresses
- token patterns
- JWT-like strings
- private-key headers
- secret-like `.env` content
- risky export and backup artifacts

Inputs:

- `scan.paths`
- pre-discovered `candidate_files`

Outputs:

- `identity_exposure` findings
- evidence and remediation guidance

### Credential Hygiene Analyzer

Purpose:

- evaluate password candidates for weak hygiene patterns

Detects:

- short passwords
- low complexity
- common-password matches
- reuse
- passwords containing user identifiers

Inputs:

- `credential.password_file`
- `credential.passwords`

Outputs:

- `credential_hygiene` findings
- module metrics such as reviewed password count

### Local Privacy Risk Scanner

Purpose:

- detect risky local artifacts that can expose identity or session material

Detects:

- shell history leakage
- credential exports
- risky token files
- broad file permissions
- local secret stores

### Browser Security Audit

Purpose:

- inspect local browser profiles for risky posture and stored-data warnings

Covers:

- Chromium-family browsers
- Firefox

Detects:

- disabled protections
- saved session or credential artifacts
- extension sprawl
- risky privacy settings

### Email and Phishing Analyzer

Purpose:

- parse email samples and identify phishing indicators

Detects:

- suspicious URLs
- From and Reply-To mismatches
- missing or failing auth headers when present
- pressure language
- risky attachment types

Inputs:

- `.eml` or text email files supplied by config or CLI

## Advanced Modules

### Breach Intelligence

Purpose:

- detect identity exposure against breach datasets and optional providers

Design properties:

- identifiers are normalized and hashed
- offline datasets are supported
- results are cached locally
- plaintext credentials are never stored

### Threat Intelligence

Purpose:

- enrich URLs, domains, and IPs with reputation data

Design properties:

- offline feeds first
- provider abstraction
- rate-limited optional online mode
- local caching

### AI Security Analysis

Purpose:

- explain technical findings in operator-friendly language

Produces:

- security summary
- risk explanation
- recommended actions
- suspicious cross-module patterns

### Security Event Timeline

Purpose:

- keep scan findings as chronological security events and correlate related activity

Produces:

- timeline events
- correlated patterns
- history inputs for the dashboard trend views

### Plugin System

Purpose:

- allow external modules to extend DIPS without modifying core source

Capabilities:

- add scanners
- enrich results
- extend reports
- integrate local security tools

## Scoring and Reporting

### Digital Identity Risk Engine

Combines:

- breach exposure
- password hygiene
- browser posture
- phishing risk
- threat intelligence
- token exposure
- privacy risk

Outputs:

- overall score
- severity label
- module scores
- category scores
- top recommendations
- main contributing findings

### Report Export

Formats:

- JSON
- standalone HTML

Design properties:

- evidence redaction by default
- plugin extension support
- timeline and correlation included

## Desktop Dashboard

The dashboard surfaces:

- Identity Protection Score
- priority alerts
- threat intelligence
- breach exposure
- security event timeline
- alert correlation clusters
- severity heatmap
- scan history trend
- module pages
- settings and report loading
