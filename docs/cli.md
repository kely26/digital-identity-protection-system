# CLI Usage Guide

## Command Summary

```bash
dips --help
```

Subcommands:

- `scan`: run a full scan and write reports
- `watch`: run repeated scans in the foreground
- `show-config`: print the merged effective config
- `doctor`: run runtime diagnostics and operator health checks
- `gui`: launch the dashboard
- `dashboard`: launch the dashboard
- `demo`: generate safe synthetic demo reports

## Common Options

Available on `scan`, `watch`, `show-config`, and dashboard commands where relevant:

- `--config`: JSON config file
- `--path`: add scan path
- `--email-file`: email sample input
- `--password-file`: password list input
- `--password`: inline password candidate
- `--identifier`: email or username for breach intelligence
- `--breach-dataset`: offline breach dataset JSON
- `--threat-feed`: offline threat intelligence feed JSON
- `--online-threat-intel`: allow online threat provider lookups
- `--output-dir`: report directory
- `--format`: `json` or `html`
- `--debug`: debug logging
- `--log-file`: JSON log file path

## Scan Command

Basic scan:

```bash
dips scan --config config/example.config.json
```

Targeted scan:

```bash
dips scan \
  --path tests/fixtures/exposure \
  --email-file tests/fixtures/email/phish.eml \
  --password-file tests/fixtures/exposure/passwords.txt \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json \
  --threat-feed tests/fixtures/threat/malicious_feed.json \
  --output-dir reports
```

JSON-only output:

```bash
dips scan --path ~/Documents --format json
```

Policy-gated severity enforcement:

```bash
dips scan --path ~/Documents --fail-on-severity high
```

Policy-gated score enforcement:

```bash
dips scan --path ~/Documents --fail-on-score 70
```

## Watch Command

One-cycle smoke test:

```bash
dips watch --config config/example.config.json --cycles 1 --interval 0
```

Repeated monitoring:

```bash
dips watch --path ~/Documents --interval 300
```

## Show-Config Command

Print the merged effective config:

```bash
dips show-config --config config/example.config.json
```

Print config with inline overrides:

```bash
dips show-config \
  --path ~/Documents \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json
```

## Doctor Command

Run a runtime health check:

```bash
dips doctor
```

Emit JSON for support tooling or managed rollout automation:

```bash
dips doctor --doctor-format json
```

## Dashboard Command

Launch the dashboard:

```bash
dips dashboard
```

Launch from a saved report:

```bash
dips dashboard --load-report reports/<scan-id>.json
```

Launch with synthetic demo data:

```bash
dips dashboard --demo
```

Start the dashboard and run a scan immediately:

```bash
dips dashboard --auto-scan --config config/example.config.json
```

Capture a screenshot:

```bash
dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

## Logging

Text console logs:

```bash
dips scan --config config/example.config.json --debug
```

JSON file logging:

```bash
dips scan --config config/example.config.json --log-file logs/dips.json
```

## Demo Command

Generate demo reports:

```bash
dips demo
```

Write demo reports into a custom directory:

```bash
dips demo --output-dir examples/demo-reports
```

Generate the reports and open the dashboard immediately:

```bash
dips demo --dashboard --page overview
```

## Exit Behavior

- normal successful commands return `0`
- `doctor` returns `7` when a hard environment failure is detected
- policy-gated scans return `6` after reports are written when a configured threshold is violated
- config and validation errors return a DIPS-specific non-zero exit code
- unexpected failures are converted into clean CLI error messages instead of raw tracebacks
