# Contributing

Thank you for contributing to DIPS.

This project is meant to feel like a serious defensive-security engineering effort. Contributions should improve the product, preserve trust, and keep the scope clearly on privacy protection and identity-risk visibility.

## Repository Map

- `dips/core/`: orchestration, config, logging, plugin runtime, timeline, and risk scoring
- `dips/scanners/`: built-in local scan modules
- `dips/modules/`: advanced intelligence and analysis modules
- `dips/reporting/`: JSON and HTML report exporters
- `dips/ui_dashboard/` and `dips/gui/`: desktop dashboard surface and implementation
- `docs/`: operator, engineering, release, and project-positioning docs
- `examples/`: safe demo reports and walkthrough inputs
- `tests/`: regression coverage for CLI, scanners, UI, packaging, and integration paths

## Principles

- Keep the project defensive-only.
- Preserve Windows and Linux support.
- Prefer clear architecture over quick hacks.
- Add tests for behavior changes.
- Keep report evidence redacted by default.
- Avoid introducing mandatory cloud dependencies into the local scan path.

## Local Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[gui]
pip install -r requirements.txt
```

## Quality Checks

```bash
pytest
ruff check .
```

## Pull Request Expectations

- Keep changes scoped to one concern where possible.
- Update documentation when CLI, GUI, config, reporting, or architecture changes.
- Note Windows or Linux specific behavior explicitly.
- Use redacted evidence only in examples, tests, comments, and screenshots.
- Follow the pull request template checklist.

## Recommended Contribution Areas

- new defensive scanner modules
- better local hardening checks
- dashboard UX improvements
- reporting improvements
- packaging and release automation
- test coverage and platform compatibility

## Good First Contributions

- improve scanner coverage with new safe detection heuristics
- strengthen documentation or example workflows
- refine dashboard data presentation without changing the core scan model
- improve test fixtures, CI reliability, or packaging automation
- add plugin examples for defensive local tooling

## Scanner Extensions

New scanners should:

- subclass `ScannerModule`
- return `ModuleResult`
- avoid mutating the host
- degrade safely when required inputs are missing
- reuse `ScanContext.candidate_files` instead of rescanning paths

Detailed module guidance is in [docs/module-development.md](docs/module-development.md).

## Security-Related Changes

If a proposed change touches secrets, browser data handling, local storage, or sensitive evidence rendering, review [SECURITY.md](SECURITY.md) before opening the pull request.

## Documentation Expectations

The repository should read like a maintained security product, not a loose collection of scripts.

When changing user-facing behavior, update the relevant docs:

- [README.md](README.md)
- [docs/installation.md](docs/installation.md)
- [docs/quickstart.md](docs/quickstart.md)
- [docs/cli.md](docs/cli.md)
- [docs/gui.md](docs/gui.md)
- [docs/reports.md](docs/reports.md)
- [docs/plugins.md](docs/plugins.md)
- [docs/troubleshooting.md](docs/troubleshooting.md)
