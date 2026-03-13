# Operations Guide

This guide covers the workflows that make DIPS feel like a maintainable product instead of a one-off security script.

## Core Operator Checks

Run a local health check before handing the build to another person:

```bash
dips doctor
```

Machine-readable diagnostics:

```bash
dips doctor --doctor-format json
```

What `doctor` checks:

- Python runtime compatibility
- dashboard dependency availability
- report output path writability
- cache and timeline storage writability
- configured scan/input paths
- enabled plugin loading health

Exit behavior:

- `0` when checks pass or produce warnings only
- `7` when a hard environment failure is detected

## Policy-Gated Scans

DIPS can now act like an automation gate for CI, scheduled jobs, or managed-service workflows.

Fail when a finding reaches a severity threshold:

```bash
dips scan --path ~/Documents --fail-on-severity high
```

Fail when the overall risk score crosses a threshold:

```bash
dips scan --path ~/Documents --fail-on-score 70
```

Important behavior:

- reports are still written before the command exits non-zero
- policy failures return exit code `6`
- this is additive and does not change the default `dips scan` success path

## Continuous Integration

The repository includes a GitHub Actions workflow at [../.github/workflows/ci.yml](../.github/workflows/ci.yml) that runs:

- `ruff check .`
- `pytest`
- `python -m build`
- `python -m twine check dist/*`

The matrix covers:

- Ubuntu and Windows
- Python `3.11`, `3.12`, and `3.13`

## Maintainer Baseline

For a release-ready maintenance loop:

```bash
make lint
make test
make build
dips doctor
make smoke
```

For a stricter package gate:

```bash
make release-check
```

## Recommended Beta Rollout Pattern

If you are giving DIPS to early users for free:

- keep default scan behavior stable and additive
- ask beta users to run `dips doctor` before filing bugs
- request JSON doctor output and the generated report ID when triaging issues
- use policy-gated scans only for managed environments or internal automation
- keep plugin validation strict unless you are deliberately testing custom integrations
