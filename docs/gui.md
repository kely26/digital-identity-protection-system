# Dashboard Usage Guide

## Purpose

The DIPS dashboard provides a professional desktop investigation surface on top of the same scan engine used by the CLI. It is intended for local analyst workflows, screenshot capture, report review, and defensive triage.

## Launch Options

Preferred command:

```bash
dips dashboard
```

Compatibility aliases:

```bash
dips gui
dips-dashboard
```

Load a saved report:

```bash
dips dashboard --load-report reports/<scan-id>.json
```

Launch directly with synthetic demo data:

```bash
dips dashboard --demo
```

Start an immediate scan:

```bash
dips dashboard --auto-scan --config config/example.config.json
```

## Main Pages

### Overview

Primary surfaces:

- Identity Protection Score
- Priority alert queue
- Risk trend graph
- Threat intelligence summary
- Security event timeline
- severity heatmap
- alert correlation clusters
- identity exposure map

### Module Pages

Dedicated pages for:

- Identity Exposure Monitor
- Breach Exposure Alerts
- Credential Security
- Local Privacy Risk Scanner
- Browser Security Audit
- Phishing Analyzer
- Threat Intelligence
- AI Security Analysis

Each module page includes:

- module protection score
- focused metrics
- findings table
- recommendations

### Reports

The reports page is built for:

- loading historical JSON reports
- opening exported HTML or JSON artifacts
- reviewing top drivers and recommendations

### Settings

The settings page exposes:

- scan paths
- password and email inputs
- breach datasets and identifiers
- threat feed paths
- reporting formats and output directory

## Screenshot Workflow

Fastest path for the curated repository screenshot set:

```bash
./.venv/bin/python screenshots/capture_dashboard_assets.py
```

That command refreshes the repo-ready assets:

- `dashboard-overview.png`
- `risk-score-panel.png`
- `severity-distribution.png`
- `event-timeline.png`
- `breach-exposure-alert.png`
- `scan-report-view.png`

Generate a screenshot from a known report:

```bash
dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

On headless Linux:

```bash
QT_QPA_PLATFORM=offscreen dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

## Suggested Demo Flow

1. Run a fixture-backed scan.
2. Open the JSON report in the dashboard.
3. Capture `overview`, `breach_intelligence`, and `reports` screenshots.
4. Use the resulting assets in the repo README and release material.

Fast synthetic demo workflow:

1. Run `dips demo`.
2. Launch `dips dashboard --demo`.
3. Capture the `overview`, `breach_intelligence`, and `reports` pages.
4. Reuse the committed sample reports from `examples/demo-reports/` when you want deterministic screenshots.

## Dashboard Architecture

Main modules:

- `dips.gui.main`: dashboard argument handling
- `dips.gui.window`: main shell and worker orchestration
- `dips.gui.pages`: page composition
- `dips.gui.widgets`: cards, tables, charts, badges, and timeline widgets
- `dips.gui.state`: report-to-view-model transformation
- `dips.gui.theme`: styling and UI tokens
- `dips.ui_dashboard`: stable launch and widget surface

## Data Sources

The dashboard reads:

- live scan results from the shared engine
- JSON report files
- timeline and history information from report payloads

It does not require a separate backend service.

## Common Problems

### Dashboard does not start

Check:

```bash
dips dashboard --help
pip install -r requirements.txt
```

### Dashboard loads but shows no data

Run a scan first:

```bash
dips scan --config config/example.config.json
```

Then load the report:

```bash
dips dashboard --load-report reports/<scan-id>.json
```

### Screenshot command fails

Use a valid `.png` path and confirm the output directory exists or is writable.
