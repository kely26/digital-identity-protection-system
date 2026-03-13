# Quick Start

This guide gets DIPS scanning locally in a few minutes.

## 1. Install

Use the steps in [installation.md](installation.md), then activate the virtual environment.

## 2. Confirm the CLI

```bash
dips --help
```

## 3. Run a Realistic Local Scan

Use the maintained example config:

```bash
dips scan --config config/example.config.json
```

This writes reports into `reports/` by default.

## 4. Review the Reports

Expected outputs:

- `reports/<scan-id>.json`
- `reports/<scan-id>.html`

Open the HTML report in a browser or inspect the JSON directly.

## 5. Launch the Dashboard

```bash
dips dashboard
```

Or load the report you just generated:

```bash
dips dashboard --load-report reports/<scan-id>.json
```

## 6. Try a Safe Fixture-Backed Demo

This path is good for screenshots, tests, and local validation:

```bash
dips scan \
  --path tests/fixtures/exposure \
  --email-file tests/fixtures/email/phish.eml \
  --password-file tests/fixtures/exposure/passwords.txt \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json \
  --threat-feed tests/fixtures/threat/malicious_feed.json
```

## 7. Inspect the Effective Config

```bash
dips show-config --config config/example.config.json
```

This is the fastest way to confirm merged paths, formats, modules, and plugin settings.

## 8. Run the Test Suite

```bash
pytest
ruff check .
```

## 9. Useful Next Steps

- Run `dips dashboard --demo` to see the full UI with safe synthetic data.
- Load `examples/demo-reports/demo-incident-003.json` for a GitHub-ready incident scenario.
- Read [features.md](features.md) to understand each module.
- Read [cli.md](cli.md) for automation and watch-mode usage.
- Read [gui.md](gui.md) for dashboard workflows and screenshots.
- Read [reports.md](reports.md) for report structure and integration guidance.
