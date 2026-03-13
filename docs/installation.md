# Installation Guide

## Supported Platforms

- Linux distributions with Python 3.11+
- Windows with Python 3.11+ and PowerShell

## What Gets Installed

`requirements.txt` installs:

- the DIPS package in editable mode
- the PySide6 desktop dashboard dependency
- contributor tooling for tests and linting
- release tooling for building and checking wheel and sdist artifacts

If you only need the runtime package and dashboard, use:

```bash
pip install -e .[gui]
```

## Linux Installation

```bash
git clone <your-repo-url>
cd digital-identity-protection-system
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

Verify the install:

```bash
dips --help
dips dashboard --help
```

Debian package shortcut:

```bash
sudo dpkg -i downloads/dips_0.1.1_all.deb
dips doctor
sudo dips-enable-gui   # Optional, enables the desktop dashboard
```

## Windows Installation

```powershell
git clone <your-repo-url>
cd digital-identity-protection-system
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
```

Verify the install:

```powershell
dips --help
dips dashboard --help
```

If PowerShell blocks activation, see [troubleshooting.md](troubleshooting.md).

## Development Install

Contributor setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

Run the quality checks:

```bash
pytest
ruff check .
python -m compileall dips tests
```

## Runtime-Only Install

This is the smallest supported desktop install path:

```bash
pip install -e .[gui]
```

It provides:

- `dips`
- `dips-dashboard`
- the PySide6 dashboard runtime

It does not install the contributor QA tools from the `dev` extra.

## Recommended First Run

```bash
dips scan --config config/example.config.json
dips dashboard
```

If you want a safer local smoke test using bundled fixture data:

```bash
dips scan \
  --path tests/fixtures/exposure \
  --email-file tests/fixtures/email/phish.eml \
  --password-file tests/fixtures/exposure/passwords.txt \
  --identifier security.user@example.com \
  --breach-dataset tests/fixtures/breach/offline_dataset.json \
  --threat-feed tests/fixtures/threat/malicious_feed.json
```

## Upgrade Workflow

```bash
git pull
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pytest
```

Windows:

```powershell
git pull
.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
pytest
```
