# Example Reports

This directory contains a curated set of safe synthetic report artifacts for repository visitors, dashboard demos, and documentation.

Included files:

- `synthetic-incident-report.json`: realistic JSON scan output using the DIPS report structure
- `synthetic-incident-report.html`: a shareable HTML analyst view of the same incident
- `risk-scoring-summary.md`: a concise scoring and remediation summary
- `alert-findings-example.json`: selected high-priority findings extracted from the sample incident

These files contain no real user secrets or live scan data.

Generate similar report sets locally:

```bash
dips demo --output-dir examples/reports/generated
```

Or generate a real local report:

```bash
dips scan --config config/example.config.json --output-dir reports
```
