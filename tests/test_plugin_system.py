from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

from dips.core.engine import run_scan
from dips.core.exceptions import PluginError
from dips.core.plugin_system import load_plugin_registry


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = PROJECT_ROOT / "plugins"


def _test_logger() -> logging.Logger:
    logger = logging.getLogger("dips.tests.plugins")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return logger


def test_plugin_registry_loads_example_plugin(default_config):
    config = default_config
    config.plugin_system.search_paths = [str(PLUGIN_ROOT)]
    config.plugin_system.enabled_plugins = ["custom_scanner"]

    registry = load_plugin_registry(config, base_directory=PROJECT_ROOT, logger=_test_logger())

    assert [plugin.name for plugin in registry.plugins] == ["custom_scanner"]
    assert "custom_sensitive_file_scanner" in registry.module_map()


def test_plugin_registry_accepts_windows_style_search_path(default_config, monkeypatch):
    config = default_config
    monkeypatch.setenv("PLUGIN_ROOT", str(PLUGIN_ROOT))
    config.plugin_system.search_paths = [r"%PLUGIN_ROOT%"]
    config.plugin_system.enabled_plugins = ["custom_scanner"]

    registry = load_plugin_registry(config, base_directory=PROJECT_ROOT, logger=_test_logger())

    assert [plugin.name for plugin in registry.plugins] == ["custom_scanner"]


def test_plugin_registry_rejects_invalid_plugin(default_config, tmp_path):
    plugin_root = tmp_path / "plugins"
    bad_plugin_dir = plugin_root / "broken_plugin"
    bad_plugin_dir.mkdir(parents=True)
    (bad_plugin_dir / "plugin.py").write_text("BROKEN = True\n", encoding="utf-8")

    config = default_config
    config.plugin_system.search_paths = [str(plugin_root)]
    config.plugin_system.enabled_plugins = ["broken_plugin"]

    with pytest.raises(PluginError):
        load_plugin_registry(config, base_directory=tmp_path, logger=_test_logger())


def test_plugin_registry_wraps_import_errors(default_config, tmp_path):
    plugin_root = tmp_path / "plugins"
    bad_plugin_dir = plugin_root / "syntax_plugin"
    bad_plugin_dir.mkdir(parents=True)
    (bad_plugin_dir / "plugin.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

    config = default_config
    config.plugin_system.search_paths = [str(plugin_root)]
    config.plugin_system.enabled_plugins = ["syntax_plugin"]

    with pytest.raises(PluginError, match="Failed to import plugin"):
        load_plugin_registry(config, base_directory=tmp_path, logger=_test_logger())


def test_plugin_registry_rejects_path_traversal_plugin_names(default_config):
    config = default_config
    config.plugin_system.search_paths = [str(PLUGIN_ROOT)]
    config.plugin_system.enabled_plugins = ["../custom_scanner"]

    with pytest.raises(PluginError, match="Plugin name"):
        load_plugin_registry(config, base_directory=PROJECT_ROOT, logger=_test_logger())


def test_plugin_scan_enriches_results_and_report_extensions(default_config, tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    scan_target = tmp_path / "scan-target"
    scan_target.mkdir()
    shutil.copy(
        Path(__file__).parent / "fixtures" / "exposure" / "leaky.env",
        scan_target / "leaky.env",
    )
    (scan_target / "browser-export.json").write_text("{}", encoding="utf-8")

    config = default_config
    config.scan.paths = [str(scan_target)]
    config.reporting.output_dir = str(tmp_path / "reports")
    config.reporting.formats = ["json", "html"]
    config.plugin_system.search_paths = [str(PLUGIN_ROOT)]
    config.plugin_system.enabled_plugins = ["custom_scanner"]
    config.plugin_system.plugin_configs = {
        "custom_scanner": {
            "severity": "high",
            "external_tool_command": "local-yara --scan",
        }
    }
    config.modules.enabled = [
        "identity_exposure",
        "custom_sensitive_file_scanner",
        "ai_security_analysis",
    ]

    artifacts = run_scan(config, _test_logger())
    payload = json.loads(next(Path(config.reporting.output_dir).glob("*.json")).read_text(encoding="utf-8"))

    identity_result = next(result for result in artifacts.report.modules if result.module == "identity_exposure")
    custom_result = next(result for result in artifacts.report.modules if result.module == "custom_sensitive_file_scanner")

    assert custom_result.findings
    assert any("custom-plugin-reviewed" in finding.tags for finding in identity_result.findings)
    assert artifacts.report.extensions["plugins"]["custom_scanner"]["report"]["enriched_findings"] >= 1
    assert payload["extensions"]["plugins"]["custom_scanner"]["report"]["detected_files"]
    assert "Plugin Extensions" in next(Path(config.reporting.output_dir).glob("*.html")).read_text(encoding="utf-8")
