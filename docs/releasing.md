# Release Packaging Guide

This guide is the maintainer path for preparing, validating, and publishing a professional DIPS release.

## Recommended Release Layout

Repository root:

```text
digital-identity-protection-system/
├── CHANGELOG.md
├── LICENSE
├── README.md
├── SECURITY.md
├── config/
├── dips/
├── docs/
├── examples/
├── plugins/
├── screenshots/
├── tests/
├── MANIFEST.in
├── pyproject.toml
└── requirements.txt
```

Build artifacts:

```text
dist/
├── digital_identity_protection_system-<version>.tar.gz
└── digital_identity_protection_system-<version>-py3-none-any.whl
```

Release-facing content should always include:

- `README.md` with install, quick start, screenshots, and dashboard instructions
- `CHANGELOG.md`
- `LICENSE`
- `config/defaults.json`
- `config/example.config.json`
- `examples/demo-reports/`
- `screenshots/`

## Versioning Strategy

Use Semantic Versioning.

- `0.y.z` while APIs, report schema, and plugin hooks are still evolving quickly
- `1.0.0` when CLI, config schema, report structure, and plugin interfaces are intentionally stabilized
- Patch releases (`x.y.Z`) for bug fixes, hardening, packaging fixes, and documentation-only corrections
- Minor releases (`x.Y.0`) for backward-compatible features, new modules, or dashboard/reporting improvements
- Major releases (`X.0.0`) only when compatibility guarantees change

Single source of truth:

- Set the release version in `dips/__init__.py`
- Package metadata reads that version dynamically through `pyproject.toml`

## Build And Run Locally

Contributor bootstrap:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

Run DIPS locally:

```bash
dips --help
dips --version
dips scan --config config/example.config.json
dips dashboard --demo
```

Build release artifacts:

```bash
make build
```

Run the full release gate:

```bash
make release-check
```

Manual equivalents:

```bash
ruff check .
pytest
python -m compileall dips tests
python -m build
twine check dist/*
```

Install from the built wheel in a fresh environment:

```bash
python3 -m venv /tmp/dips-wheel-test
source /tmp/dips-wheel-test/bin/activate
pip install -U pip
pip install dist/*.whl
dips --help
dips dashboard --help
deactivate
```

## Example Config And Sample Data Verification

Validate the repo-shipped JSON files:

```bash
python -m json.tool config/defaults.json >/dev/null
python -m json.tool config/example.config.json >/dev/null
python -m json.tool tests/fixtures/breach/offline_dataset.json >/dev/null
python -m json.tool tests/fixtures/threat/malicious_feed.json >/dev/null
python -m json.tool examples/demo-reports/demo-incident-003.json >/dev/null
```

Quick smoke run against repository fixtures:

```bash
dips scan \
  --path tests/fixtures/exposure \
  --email-file tests/fixtures/email/phish.eml \
  --password-file tests/fixtures/exposure/passwords.txt \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json \
  --threat-feed tests/fixtures/threat/malicious_feed.json
```

## Pre-Release Checklist

- Update `dips/__init__.py` with the release version.
- Add a dated release entry to `CHANGELOG.md`.
- Confirm `README.md` screenshots and install steps are current.
- Run `make release-check`.
- Run `dips scan --config config/example.config.json`.
- Run `dips dashboard --demo`.
- Verify demo reports, example config paths, and sample JSON files still load cleanly.
- Review `.gitignore` and ensure no generated artifacts are staged.
- Confirm `dist/` contains both a wheel and sdist.
- Smoke-test a clean wheel install in a fresh virtual environment.

## First GitHub Release Checklist

1. Create and push a release tag such as `v0.1.0`.
2. Open a GitHub release draft.
3. Copy `.github/RELEASE_TEMPLATE.md` into the release body and fill it in.
4. Attach:
   - `dist/*.whl`
   - `dist/*.tar.gz`
5. Link the changelog entry for the release.
6. Verify the README, screenshots, and demo instructions render correctly on GitHub.
7. Mark the release as the latest stable release only after the uploaded assets were downloaded and tested once.

## Recommended Maintainer Sequence

```bash
git pull --ff-only
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
make release-check
dips scan --config config/example.config.json
dips dashboard --demo
git status
```
