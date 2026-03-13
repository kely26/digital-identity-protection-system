# Report Format Documentation

## Report Outputs

DIPS writes reports to the configured output directory in one or both formats:

- JSON for automation and downstream tooling
- standalone HTML for analyst review and sharing

## Default Output Location

By default, reports are written to:

```text
reports/
```

Override with:

```bash
dips scan --output-dir /path/to/output
```

## JSON Report Structure

Top-level fields:

```json
{
  "scan_id": "504c6c3d90ae",
  "started_at": "2026-03-12T21:00:21+00:00",
  "finished_at": "2026-03-12T21:00:22+00:00",
  "duration_ms": 1240,
  "platform_name": "linux",
  "hostname": "[REDACTED_HOST]",
  "username": "[REDACTED_USER]",
  "user_profile": "~/...",
  "target_paths": ["~/Documents"],
  "notes": [],
  "modules": [],
  "summary": {},
  "timeline": {},
  "config": {},
  "extensions": {}
}
```

### `modules`

Each module contains:

- `module`
- `description`
- `status`
- `findings`
- `warnings`
- `metadata`
- `duration_ms`

### `findings`

Each finding contains:

- `id`
- `module`
- `severity`
- `confidence`
- `title`
- `summary`
- `evidence`
- `location`
- `recommendation`
- `tags`

### `summary`

Risk summary fields:

- `overall_score`
- `overall_label`
- `severity_counts`
- `module_scores`
- `top_recommendations`
- `category_scores`
- `contributing_findings`
- `risk_model`

### `timeline`

Timeline fields:

- `store_path`
- `total_events`
- `events`
- `patterns`

### `extensions`

Plugin-provided report sections live under:

```json
{
  "extensions": {
    "plugins": {
      "custom_scanner": {
        "version": "1.0.0",
        "report": {}
      }
    }
  }
}
```

## HTML Report Contents

The HTML report is a single standalone file containing:

- overall risk cards
- module breakdown
- category score table
- recommendations
- top risk drivers
- AI Security Analysis section when present
- plugin extension cards
- security timeline
- correlated patterns
- full findings table

## Redaction Behavior

By default, report generation redacts sensitive values, including:

- usernames
- hostnames
- password inputs
- breach identifiers
- secret-shaped evidence
- home-directory path details

This behavior is designed for local sharing and screenshots while keeping the raw runtime safer by default.

## Recommended Consumption Patterns

Use JSON when you need:

- automation
- custom dashboards
- regression checks
- external integration

Use HTML when you need:

- human review
- stakeholder summaries
- investigation exports
- GitHub or portfolio-friendly walkthrough material

## Loading Reports in the Dashboard

```bash
dips dashboard --load-report reports/<scan-id>.json
```

The dashboard reads JSON reports and builds the overview, module pages, timeline, and history views from that payload.

## Demo Reports

The repository includes committed synthetic demo reports in `examples/demo-reports/`.

These are useful for:

- screenshot generation
- dashboard walkthroughs
- GitHub portfolio presentation
- verifying the UI without requiring a live scan
