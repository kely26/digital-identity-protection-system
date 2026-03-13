# Troubleshooting

## Installation Problems

### `dips: command not found`

Cause:

- the virtual environment is not activated
- the package was not installed successfully

Fix:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### PowerShell blocks activation

Try:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

## Config Problems

### `error: Config file was not found`

Cause:

- the `--config` path is wrong

Fix:

```bash
dips show-config --config config/example.config.json
```

If that fails, verify the path from the repository root.

### `error: ... is not valid JSON`

Cause:

- malformed config, dataset, or feed file

Fix:

- validate the JSON syntax
- confirm the file is UTF-8 text
- compare with `config/example.config.json`

## Scan Problems

### Scan finds no candidate files

Cause:

- the scan path is empty
- only unsupported file types are present
- file size limits exclude the files

Fix:

- verify `scan.paths`
- verify `scan.extensions`
- confirm the files are inside the target path

### Scan score is unexpectedly high

Cause:

- the example config uses bundled fixture data and may also include real local profile state

Fix:

- inspect the `summary.category_scores`
- inspect the top findings and top recommendations
- run a narrower path with `--path`

### Breach intelligence returns no hits

Cause:

- no identifiers were provided
- the offline dataset does not contain the hashed target
- the dataset path is wrong

Fix:

```bash
dips show-config --identifier security.user@example.com --breach-dataset tests/fixtures/breach/offline_dataset.json
```

## Dashboard Problems

### Dashboard will not launch

Cause:

- PySide6 is missing
- the environment is not activated

Fix:

```bash
pip install -r requirements.txt
dips dashboard --help
```

### Dashboard fails to load a report

Cause:

- the path is missing
- the file is not JSON
- the JSON report is malformed

Fix:

```bash
dips dashboard --load-report reports/<scan-id>.json
```

Check that the file exists and is a DIPS JSON report.

### Screenshot capture fails

Cause:

- invalid output path
- GUI environment problems

Fix:

```bash
dips dashboard --load-report reports/<scan-id>.json --page overview --screenshot screenshots/dashboard-overview.png
```

On headless Linux, use `QT_QPA_PLATFORM=offscreen`.

## Plugin Problems

### Plugin does not load

Cause:

- invalid plugin name
- invalid `plugin.py`
- validation failure
- plugin not enabled in config

Fix:

- confirm the plugin exists under `plugins/<name>/plugin.py`
- confirm `plugin_system.enabled_plugins` contains the plugin
- check `docs/plugins.md`

## Logging and Diagnostics

Use debug logging:

```bash
dips scan --config config/example.config.json --debug
```

Write a JSON log file:

```bash
dips scan --config config/example.config.json --log-file logs/dips.json
```

## Last Resort Checks

```bash
dips --help
dips show-config --config config/example.config.json
pytest
ruff check .
```
