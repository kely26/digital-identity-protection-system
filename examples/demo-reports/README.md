# Demo Reports

This directory contains safe synthetic DIPS reports used for dashboard demos, screenshots, and GitHub presentation.

Included scenarios:

- `demo-baseline-001`: moderate identity-risk posture for quick product overviews
- `demo-escalation-002`: high-risk escalation scenario with stronger alert density
- `demo-incident-003`: critical incident scenario for the richest dashboard and report screenshots

Recommended usage:

- README and repo hero screenshots: `demo-incident-003`
- dashboard UX walkthroughs: `demo-escalation-002`
- clean first-run demonstrations: `demo-baseline-001`

Use them directly:

```bash
dips dashboard --load-report examples/demo-reports/demo-incident-003.json
```

Or regenerate them with:

```bash
dips demo --output-dir examples/demo-reports
```

Shipped outputs:

- `.json` files for dashboard loading and automated examples
- `.html` files for shareable analyst-style reports
