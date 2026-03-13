# Examples

This folder documents practical operator workflows without duplicating fixture data or config sources already maintained elsewhere in the repository.

It is also the safest place to start if you want believable screenshots, demo dashboards, or shareable outputs without touching real local data.

## Example Flows

### Full Example Config

```bash
dips scan --config config/example.config.json
```

### Targeted Local Demo

```bash
dips scan \
  --path tests/fixtures/exposure \
  --email-file tests/fixtures/email/phish.eml \
  --password-file tests/fixtures/exposure/passwords.txt \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json \
  --threat-feed tests/fixtures/threat/malicious_feed.json
```

### Dashboard Review

```bash
dips dashboard --load-report reports/<scan-id>.json --page overview
```

### Demo Mode

```bash
dips demo
dips dashboard --demo
```

Bundled sample reports:

- `examples/demo-reports/demo-baseline-001.json`
- `examples/demo-reports/demo-escalation-002.json`
- `examples/demo-reports/demo-incident-003.json`

Recommended showcase order:

- `demo-baseline-001`: low-friction product tour for first impressions
- `demo-escalation-002`: stronger dashboard and alerting screenshots
- `demo-incident-003`: full SOC-style portfolio demonstration

Example outputs shipped with the repo:

- JSON demo reports for dashboard loading and schema inspection
- HTML demo reports for shareable analyst-style output
- screenshot-ready safe synthetic data for README and release pages
- curated example report pack in [reports](reports)

### Screenshot Capture

```bash
dips dashboard \
  --load-report reports/<scan-id>.json \
  --page overview \
  --screenshot screenshots/dashboard-overview.png
```

### Plugin Workflow

The bundled plugin example lives in [../plugins/custom_scanner](../plugins/custom_scanner).

## Related Guides

- [../docs/quickstart.md](../docs/quickstart.md)
- [../docs/cli.md](../docs/cli.md)
- [../docs/gui.md](../docs/gui.md)
- [../docs/plugins.md](../docs/plugins.md)
- [../docs/project-profile.md](../docs/project-profile.md)
