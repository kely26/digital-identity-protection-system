# Screenshots

This folder stores the curated dashboard captures used in the README, documentation, and release material.

## Primary Screenshot Set

- `dashboard-overview.png`: full identity protection dashboard with risk score, alert cards, severity heatmap, and SOC overview
- `risk-score-panel.png`: focused risk-scoring panel from the overview dashboard
- `severity-distribution.png`: severity chart view from the overview dashboard
- `event-timeline.png`: security timeline panel with filtered chronological events
- `breach-exposure-alert.png`: breach exposure page highlighting alert posture and affected identities
- `scan-report-view.png`: reports page showing export actions and report paths

## Additional Supporting Captures

- `identity-exposure.png`
- `breach-exposure.png`
- `threat-intelligence.png`
- `reports.png`

## Recommended Placement

- README top gallery: `dashboard-overview.png`, `risk-score-panel.png`, `event-timeline.png`
- dashboard feature sections: `severity-distribution.png`, `breach-exposure-alert.png`, `scan-report-view.png`
- docs and release notes: `identity-exposure.png`, `threat-intelligence.png`
- recruiter or portfolio callouts: `dashboard-overview.png`

## One-Command Capture Workflow

Generate the full professional screenshot set from safe synthetic demo data:

```bash
./.venv/bin/python screenshots/capture_dashboard_assets.py
```

This command refreshes:

- `dashboard-overview.png`
- `risk-score-panel.png`
- `severity-distribution.png`
- `event-timeline.png`
- `breach-exposure-alert.png`
- `scan-report-view.png`

## Regeneration Workflow

Generate a new screenshot from an existing JSON report:

```bash
dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

Headless Linux:

```bash
QT_QPA_PLATFORM=offscreen dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

Manual page capture suggestions:

- `overview` for the full identity protection dashboard
- `breach_intelligence` for breach exposure alert views
- `reports` for export and report review screens

## Recommended Capture Pages

- `overview`
- `identity_exposure`
- `breach_intelligence`
- `reports`
- `threat_intelligence`

Use fixture-backed reports when possible so screenshots remain safe to publish.

Demo mode provides a fully synthetic alternative:

```bash
dips dashboard --demo --page overview --screenshot screenshots/dashboard-overview.png
```
