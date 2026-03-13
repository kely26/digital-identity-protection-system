from __future__ import annotations

import json

import pytest

from dips.core.config import AppConfig, load_config
from dips.core.exceptions import ConfigError


def test_load_config_merges_and_validates(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/tmp/home-test")
    override = tmp_path / "override.json"
    override.write_text(
        json.dumps(
            {
                "scan": {"paths": ["${HOME}/Documents"], "max_workers": 4},
                "reporting": {"output_dir": "${HOME}/reports", "formats": ["json"]},
            }
        ),
        encoding="utf-8",
    )

    config = load_config(str(override))

    assert isinstance(config, AppConfig)
    assert config.scan.paths == ["/tmp/home-test/Documents"]
    assert config.reporting.output_dir == "/tmp/home-test/reports"
    assert config.reporting.formats == ["json"]


def test_load_config_normalizes_windows_style_path_fields(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    plugin_root = tmp_path / "plugins"
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("PLUGIN_ROOT", str(plugin_root))
    override = tmp_path / "windows-paths.json"
    override.write_text(
        json.dumps(
            {
                "scan": {"paths": [r"%USERPROFILE%\Documents"]},
                "credential": {"password_file": r"%USERPROFILE%\secrets\passwords.txt"},
                "email": {"inputs": [r"%USERPROFILE%\mail\alert.eml"]},
                "breach_intelligence": {
                    "offline_datasets": [r"%USERPROFILE%\intel\breach.json"],
                    "cache_path": r"%USERPROFILE%\cache\breach.json",
                },
                "threat_intelligence": {
                    "feed_paths": [r"%USERPROFILE%\intel\threat.json"],
                    "cache_path": r"%USERPROFILE%\cache\threat.json",
                },
                "event_timeline": {"store_path": r"%USERPROFILE%\cache\timeline.json"},
                "plugin_system": {"search_paths": [r"%PLUGIN_ROOT%\custom"]},
                "reporting": {"output_dir": r"%USERPROFILE%\reports"},
            }
        ),
        encoding="utf-8",
    )

    config = load_config(str(override))

    assert config.scan.paths == [f"{profile}/Documents"]
    assert config.credential.password_file == f"{profile}/secrets/passwords.txt"
    assert config.email.inputs == [f"{profile}/mail/alert.eml"]
    assert config.breach_intelligence.offline_datasets == [f"{profile}/intel/breach.json"]
    assert config.breach_intelligence.cache_path == f"{profile}/cache/breach.json"
    assert config.threat_intelligence.feed_paths == [f"{profile}/intel/threat.json"]
    assert config.threat_intelligence.cache_path == f"{profile}/cache/threat.json"
    assert config.event_timeline.store_path == f"{profile}/cache/timeline.json"
    assert config.plugin_system.search_paths == [f"{plugin_root}/custom"]
    assert config.reporting.output_dir == f"{profile}/reports"


def test_load_config_rejects_invalid_formats(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"reporting": {"formats": ["xml"]}}), encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(str(invalid))


def test_load_config_rejects_non_boolean_redact_evidence(tmp_path):
    invalid = tmp_path / "invalid-redact.json"
    invalid.write_text(json.dumps({"reporting": {"redact_evidence": "false"}}), encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(str(invalid))


def test_load_config_rejects_unreadable_config_path(tmp_path):
    config_dir = tmp_path / "config-dir"
    config_dir.mkdir()

    with pytest.raises(ConfigError):
        load_config(str(config_dir))


def test_example_config_includes_breach_fixture():
    config = load_config("config/example.config.json")

    assert "security.user@example.com" in config.breach_intelligence.identifiers
    assert "tests/fixtures/breach/offline_dataset.json" in config.breach_intelligence.offline_datasets
    assert "tests/fixtures/threat/malicious_feed.json" in config.threat_intelligence.feed_paths
    assert config.event_timeline.max_events == 250
    assert config.ai_security_analysis.provider == "local_heuristic"
    assert config.ai_security_analysis.max_recommendations == 5
    assert config.plugin_system.enabled_plugins == ["custom_scanner"]
    assert config.plugin_system.plugin_configs["custom_scanner"]["severity"] == "high"
    assert "custom_sensitive_file_scanner" in config.modules.enabled
