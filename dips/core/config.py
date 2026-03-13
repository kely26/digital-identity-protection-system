"""Configuration loading and validation."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dips.core.exceptions import ConfigError
from dips.core.models import SEVERITY_ORDER
from dips.utils.paths import normalize_path_text, path_from_input
from dips.utils.secure_io import read_json_file

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_FILE = PROJECT_ROOT / "config" / "defaults.json"
EXAMPLE_CONFIG_FILE = PROJECT_ROOT / "config" / "example.config.json"
SUPPORTED_REPORT_FORMATS = {"json", "html"}
MAX_CONFIG_BYTES = 1_048_576


def read_json(path: Path) -> dict[str, Any]:
    try:
        raw = read_json_file(path, max_bytes=MAX_CONFIG_BYTES)
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Config file must be UTF-8 text: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {path}") from exc
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    except OSError as exc:
        raise ConfigError(f"Failed to read config file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Expected a JSON object in {path}")
    return raw


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _string_list(value: Any, *, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"Expected '{key}' to be a list of strings.")
    return [os.path.expandvars(item) for item in value]


def _string_value(value: Any, *, key: str, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"Expected '{key}' to be a string.")
    return os.path.expandvars(value)


def _path_list(value: Any, *, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"Expected '{key}' to be a list of strings.")
    return [normalize_path_text(item) for item in value]


def _path_value(value: Any, *, key: str, default: str = "") -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(f"Expected '{key}' to be a string.")
    return normalize_path_text(value)


def _bool_value(value: Any, *, key: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"Expected '{key}' to be a boolean.")
    return value


def _int_value(value: Any, *, key: str, minimum: int = 0) -> int:
    if not isinstance(value, int):
        raise ConfigError(f"Expected '{key}' to be an integer.")
    if value < minimum:
        raise ConfigError(f"Expected '{key}' to be at least {minimum}.")
    return value


def _float_mapping(value: Any, *, key: str) -> dict[str, float]:
    if not isinstance(value, dict):
        raise ConfigError(f"Expected '{key}' to be an object.")
    result: dict[str, float] = {}
    for mapping_key, mapping_value in value.items():
        if not isinstance(mapping_key, str) or not isinstance(mapping_value, (int, float)):
            raise ConfigError(f"Expected '{key}' to map strings to numbers.")
        result[mapping_key] = float(mapping_value)
    return result


def _int_mapping(value: Any, *, key: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ConfigError(f"Expected '{key}' to be an object.")
    result: dict[str, int] = {}
    for mapping_key, mapping_value in value.items():
        if not isinstance(mapping_key, str) or not isinstance(mapping_value, int):
            raise ConfigError(f"Expected '{key}' to map strings to integers.")
        result[mapping_key] = mapping_value
    return result


def _object_mapping(value: Any, *, key: str) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"Expected '{key}' to be an object.")
    result: dict[str, dict[str, Any]] = {}
    for mapping_key, mapping_value in value.items():
        if not isinstance(mapping_key, str) or not isinstance(mapping_value, dict):
            raise ConfigError(f"Expected '{key}' to map strings to objects.")
        result[mapping_key] = mapping_value
    return result


@dataclass(slots=True)
class BreachProviderSettings:
    name: str
    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    timeout_seconds: int = 10

    def validate(self) -> None:
        if not self.name:
            raise ConfigError("breach_intelligence.providers[].name must not be empty.")
        if self.enabled and not self.endpoint:
            raise ConfigError(
                f"breach_intelligence.providers[{self.name!r}] is enabled but endpoint is empty."
            )
        if self.timeout_seconds < 1:
            raise ConfigError(
                f"breach_intelligence.providers[{self.name!r}].timeout_seconds must be at least 1."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "endpoint": self.endpoint,
            "api_key_env": self.api_key_env,
            "timeout_seconds": self.timeout_seconds,
        }


def _provider_list(value: Any, *, key: str) -> list[BreachProviderSettings]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"Expected '{key}' to be a list.")
    providers: list[BreachProviderSettings] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ConfigError(f"Expected '{key}[{index}]' to be an object.")
        provider = BreachProviderSettings(
            name=_string_value(item.get("name", ""), key=f"{key}[{index}].name"),
            enabled=_bool_value(item.get("enabled", False), key=f"{key}[{index}].enabled"),
            endpoint=_string_value(item.get("endpoint", ""), key=f"{key}[{index}].endpoint"),
            api_key_env=_string_value(item.get("api_key_env", ""), key=f"{key}[{index}].api_key_env"),
            timeout_seconds=_int_value(
                item.get("timeout_seconds", 10),
                key=f"{key}[{index}].timeout_seconds",
                minimum=1,
            ),
        )
        providers.append(provider)
    return providers


@dataclass(slots=True)
class ThreatIntelProviderSettings:
    name: str
    plugin: str = "http_json"
    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    timeout_seconds: int = 10
    min_interval_seconds: int = 1

    def validate(self) -> None:
        if not self.name:
            raise ConfigError("threat_intelligence.providers[].name must not be empty.")
        if not self.plugin:
            raise ConfigError("threat_intelligence.providers[].plugin must not be empty.")
        if self.enabled and self.plugin == "http_json" and not self.endpoint:
            raise ConfigError(
                f"threat_intelligence.providers[{self.name!r}] is enabled but endpoint is empty."
            )
        if self.timeout_seconds < 1:
            raise ConfigError(
                f"threat_intelligence.providers[{self.name!r}].timeout_seconds must be at least 1."
            )
        if self.min_interval_seconds < 0:
            raise ConfigError(
                f"threat_intelligence.providers[{self.name!r}].min_interval_seconds must be zero or greater."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "plugin": self.plugin,
            "enabled": self.enabled,
            "endpoint": self.endpoint,
            "api_key_env": self.api_key_env,
            "timeout_seconds": self.timeout_seconds,
            "min_interval_seconds": self.min_interval_seconds,
        }


def _threat_provider_list(value: Any, *, key: str) -> list[ThreatIntelProviderSettings]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"Expected '{key}' to be a list.")
    providers: list[ThreatIntelProviderSettings] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ConfigError(f"Expected '{key}[{index}]' to be an object.")
        provider = ThreatIntelProviderSettings(
            name=_string_value(item.get("name", ""), key=f"{key}[{index}].name"),
            plugin=_string_value(item.get("plugin", "http_json"), key=f"{key}[{index}].plugin", default="http_json"),
            enabled=_bool_value(item.get("enabled", False), key=f"{key}[{index}].enabled"),
            endpoint=_string_value(item.get("endpoint", ""), key=f"{key}[{index}].endpoint"),
            api_key_env=_string_value(item.get("api_key_env", ""), key=f"{key}[{index}].api_key_env"),
            timeout_seconds=_int_value(
                item.get("timeout_seconds", 10),
                key=f"{key}[{index}].timeout_seconds",
                minimum=1,
            ),
            min_interval_seconds=_int_value(
                item.get("min_interval_seconds", 1),
                key=f"{key}[{index}].min_interval_seconds",
                minimum=0,
            ),
        )
        providers.append(provider)
    return providers


@dataclass(slots=True)
class ScanSettings:
    paths: list[str] = field(default_factory=list)
    max_file_size_mb: int = 2
    max_files: int = 5000
    max_workers: int = 8
    extensions: list[str] = field(default_factory=list)
    exclude_dirs: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.max_file_size_mb < 1:
            raise ConfigError("scan.max_file_size_mb must be at least 1.")
        if self.max_files < 1:
            raise ConfigError("scan.max_files must be at least 1.")
        if self.max_workers < 1:
            raise ConfigError("scan.max_workers must be at least 1.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": self.paths,
            "max_file_size_mb": self.max_file_size_mb,
            "max_files": self.max_files,
            "max_workers": self.max_workers,
            "extensions": self.extensions,
            "exclude_dirs": self.exclude_dirs,
        }


@dataclass(slots=True)
class ModulesSettings:
    enabled: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if not self.enabled:
            raise ConfigError("modules.enabled must include at least one module.")

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled}


@dataclass(slots=True)
class BrowserSettings:
    max_extension_count: int = 15

    def validate(self) -> None:
        if self.max_extension_count < 0:
            raise ConfigError("browser.max_extension_count must be zero or greater.")

    def to_dict(self) -> dict[str, Any]:
        return {"max_extension_count": self.max_extension_count}


@dataclass(slots=True)
class CredentialSettings:
    password_file: str = ""
    passwords: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"password_file": self.password_file, "passwords": self.passwords}


@dataclass(slots=True)
class EmailSettings:
    inputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"inputs": self.inputs}


@dataclass(slots=True)
class ReportingSettings:
    output_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["json", "html"])
    redact_evidence: bool = True

    def validate(self) -> None:
        if not self.output_dir:
            raise ConfigError("reporting.output_dir must not be empty.")
        if not self.formats:
            raise ConfigError("reporting.formats must include at least one format.")
        unsupported = sorted(set(self.formats) - SUPPORTED_REPORT_FORMATS)
        if unsupported:
            raise ConfigError(
                f"Unsupported reporting formats: {', '.join(unsupported)}. Supported formats are json and html."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_dir": self.output_dir,
            "formats": self.formats,
            "redact_evidence": self.redact_evidence,
        }


@dataclass(slots=True)
class BreachIntelligenceSettings:
    identifiers: list[str] = field(default_factory=list)
    offline_datasets: list[str] = field(default_factory=list)
    allow_external: bool = False
    cache_path: str = ".cache/dips/breach_cache.json"
    cache_ttl_seconds: int = 86400
    hash_salt: str = ""
    providers: list[BreachProviderSettings] = field(default_factory=list)

    def validate(self) -> None:
        if not self.cache_path:
            raise ConfigError("breach_intelligence.cache_path must not be empty.")
        if self.cache_ttl_seconds < 0:
            raise ConfigError("breach_intelligence.cache_ttl_seconds must be zero or greater.")
        for provider in self.providers:
            provider.validate()

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifiers": self.identifiers,
            "offline_datasets": self.offline_datasets,
            "allow_external": self.allow_external,
            "cache_path": self.cache_path,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "hash_salt": self.hash_salt,
            "providers": [provider.to_dict() for provider in self.providers],
        }


@dataclass(slots=True)
class ScoringSettings:
    weights: dict[str, int] = field(default_factory=dict)
    module_multipliers: dict[str, float] = field(default_factory=dict)

    def validate(self) -> None:
        missing = [severity for severity in SEVERITY_ORDER if severity not in self.weights]
        if missing:
            raise ConfigError(f"scoring.weights is missing severities: {', '.join(missing)}.")
        if any(weight < 0 for weight in self.weights.values()):
            raise ConfigError("scoring.weights must not contain negative values.")
        if any(multiplier <= 0 for multiplier in self.module_multipliers.values()):
            raise ConfigError("scoring.module_multipliers must be greater than zero.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "weights": self.weights,
            "module_multipliers": self.module_multipliers,
        }


@dataclass(slots=True)
class ThreatIntelligenceSettings:
    feed_paths: list[str] = field(default_factory=list)
    allow_online: bool = False
    cache_path: str = ".cache/dips/threat_intel_cache.json"
    cache_ttl_seconds: int = 43200
    max_indicators: int = 250
    providers: list[ThreatIntelProviderSettings] = field(default_factory=list)

    def validate(self) -> None:
        if not self.cache_path:
            raise ConfigError("threat_intelligence.cache_path must not be empty.")
        if self.cache_ttl_seconds < 0:
            raise ConfigError("threat_intelligence.cache_ttl_seconds must be zero or greater.")
        if self.max_indicators < 1:
            raise ConfigError("threat_intelligence.max_indicators must be at least 1.")
        for provider in self.providers:
            provider.validate()

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_paths": self.feed_paths,
            "allow_online": self.allow_online,
            "cache_path": self.cache_path,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "max_indicators": self.max_indicators,
            "providers": [provider.to_dict() for provider in self.providers],
        }


@dataclass(slots=True)
class EventTimelineSettings:
    store_path: str = ".cache/dips/event_timeline.json"
    max_events: int = 500
    correlation_window_hours: int = 24

    def validate(self) -> None:
        if not self.store_path:
            raise ConfigError("event_timeline.store_path must not be empty.")
        if self.max_events < 1:
            raise ConfigError("event_timeline.max_events must be at least 1.")
        if self.correlation_window_hours < 1:
            raise ConfigError("event_timeline.correlation_window_hours must be at least 1.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "store_path": self.store_path,
            "max_events": self.max_events,
            "correlation_window_hours": self.correlation_window_hours,
        }


@dataclass(slots=True)
class AiSecurityAnalysisSettings:
    provider: str = "local_heuristic"
    allow_online: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    model: str = "local-heuristic-v1"
    timeout_seconds: int = 15
    max_findings: int = 12
    max_recommendations: int = 6

    def validate(self) -> None:
        if not self.provider:
            raise ConfigError("ai_security_analysis.provider must not be empty.")
        if self.allow_online and self.provider != "local_heuristic" and not self.endpoint:
            raise ConfigError("ai_security_analysis.endpoint must be set when online AI analysis is enabled.")
        if self.timeout_seconds < 1:
            raise ConfigError("ai_security_analysis.timeout_seconds must be at least 1.")
        if self.max_findings < 1:
            raise ConfigError("ai_security_analysis.max_findings must be at least 1.")
        if self.max_recommendations < 1:
            raise ConfigError("ai_security_analysis.max_recommendations must be at least 1.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "allow_online": self.allow_online,
            "endpoint": self.endpoint,
            "api_key_env": self.api_key_env,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "max_findings": self.max_findings,
            "max_recommendations": self.max_recommendations,
        }


@dataclass(slots=True)
class PluginSystemSettings:
    search_paths: list[str] = field(default_factory=lambda: ["plugins"])
    enabled_plugins: list[str] = field(default_factory=list)
    plugin_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    strict_validation: bool = True

    def validate(self) -> None:
        if any(not item.strip() for item in self.enabled_plugins):
            raise ConfigError("plugin_system.enabled_plugins must not contain empty names.")
        if any(not item.strip() for item in self.search_paths):
            raise ConfigError("plugin_system.search_paths must not contain empty values.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "search_paths": self.search_paths,
            "enabled_plugins": self.enabled_plugins,
            "plugin_configs": self.plugin_configs,
            "strict_validation": self.strict_validation,
        }


@dataclass(slots=True)
class RiskEngineSettings:
    enabled: bool = True
    category_weights: dict[str, float] = field(default_factory=dict)
    thresholds: dict[str, int] = field(default_factory=dict)
    max_recommendations: int = 6
    max_finding_titles: int = 6

    def validate(self) -> None:
        if any(weight < 0 for weight in self.category_weights.values()):
            raise ConfigError("risk_engine.category_weights must not contain negative values.")
        required = ["minimal", "low", "moderate", "high", "critical"]
        missing = [key for key in required if key not in self.thresholds]
        if missing:
            raise ConfigError(f"risk_engine.thresholds is missing levels: {', '.join(missing)}.")
        ordered = [self.thresholds[key] for key in required]
        if ordered != sorted(ordered):
            raise ConfigError("risk_engine.thresholds must be ordered from minimal to critical.")
        if self.max_recommendations < 1:
            raise ConfigError("risk_engine.max_recommendations must be at least 1.")
        if self.max_finding_titles < 1:
            raise ConfigError("risk_engine.max_finding_titles must be at least 1.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "category_weights": self.category_weights,
            "thresholds": self.thresholds,
            "max_recommendations": self.max_recommendations,
            "max_finding_titles": self.max_finding_titles,
        }


@dataclass(slots=True)
class WatchSettings:
    interval_seconds: int = 300

    def validate(self) -> None:
        if self.interval_seconds < 0:
            raise ConfigError("watch.interval_seconds must be zero or greater.")

    def to_dict(self) -> dict[str, Any]:
        return {"interval_seconds": self.interval_seconds}


@dataclass(slots=True)
class AppConfig:
    scan: ScanSettings
    modules: ModulesSettings
    browser: BrowserSettings
    credential: CredentialSettings
    email: EmailSettings
    breach_intelligence: BreachIntelligenceSettings
    threat_intelligence: ThreatIntelligenceSettings
    event_timeline: EventTimelineSettings
    ai_security_analysis: AiSecurityAnalysisSettings
    plugin_system: PluginSystemSettings
    reporting: ReportingSettings
    scoring: ScoringSettings
    risk_engine: RiskEngineSettings
    watch: WatchSettings

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "AppConfig":
        scan_raw = mapping.get("scan", {})
        modules_raw = mapping.get("modules", {})
        browser_raw = mapping.get("browser", {})
        credential_raw = mapping.get("credential", {})
        email_raw = mapping.get("email", {})
        breach_raw = mapping.get("breach_intelligence", {})
        threat_raw = mapping.get("threat_intelligence", {})
        timeline_raw = mapping.get("event_timeline", {})
        ai_raw = mapping.get("ai_security_analysis", {})
        plugin_raw = mapping.get("plugin_system", {})
        reporting_raw = mapping.get("reporting", {})
        scoring_raw = mapping.get("scoring", {})
        risk_engine_raw = mapping.get("risk_engine", {})
        watch_raw = mapping.get("watch", {})

        if not all(
            isinstance(item, dict)
            for item in [
                scan_raw,
                modules_raw,
                browser_raw,
                credential_raw,
                email_raw,
                breach_raw,
                threat_raw,
                timeline_raw,
                ai_raw,
                plugin_raw,
                reporting_raw,
                scoring_raw,
                risk_engine_raw,
                watch_raw,
            ]
        ):
            raise ConfigError("Top-level configuration sections must all be JSON objects.")

        config = cls(
            scan=ScanSettings(
                paths=_path_list(scan_raw.get("paths", []), key="scan.paths"),
                max_file_size_mb=_int_value(scan_raw.get("max_file_size_mb", 2), key="scan.max_file_size_mb", minimum=1),
                max_files=_int_value(scan_raw.get("max_files", 5000), key="scan.max_files", minimum=1),
                max_workers=_int_value(scan_raw.get("max_workers", 8), key="scan.max_workers", minimum=1),
                extensions=_string_list(scan_raw.get("extensions", []), key="scan.extensions"),
                exclude_dirs=_string_list(scan_raw.get("exclude_dirs", []), key="scan.exclude_dirs"),
            ),
            modules=ModulesSettings(
                enabled=_string_list(modules_raw.get("enabled", []), key="modules.enabled"),
            ),
            browser=BrowserSettings(
                max_extension_count=_int_value(browser_raw.get("max_extension_count", 15), key="browser.max_extension_count", minimum=0),
            ),
            credential=CredentialSettings(
                password_file=_path_value(credential_raw.get("password_file", ""), key="credential.password_file"),
                passwords=_string_list(credential_raw.get("passwords", []), key="credential.passwords"),
            ),
            email=EmailSettings(
                inputs=_path_list(email_raw.get("inputs", []), key="email.inputs"),
            ),
            breach_intelligence=BreachIntelligenceSettings(
                identifiers=_string_list(
                    breach_raw.get("identifiers", []),
                    key="breach_intelligence.identifiers",
                ),
                offline_datasets=_path_list(
                    breach_raw.get("offline_datasets", []),
                    key="breach_intelligence.offline_datasets",
                ),
                allow_external=_bool_value(
                    breach_raw.get("allow_external", False),
                    key="breach_intelligence.allow_external",
                ),
                cache_path=_path_value(
                    breach_raw.get("cache_path", ".cache/dips/breach_cache.json"),
                    key="breach_intelligence.cache_path",
                    default=".cache/dips/breach_cache.json",
                ),
                cache_ttl_seconds=_int_value(
                    breach_raw.get("cache_ttl_seconds", 86400),
                    key="breach_intelligence.cache_ttl_seconds",
                    minimum=0,
                ),
                hash_salt=_string_value(
                    breach_raw.get("hash_salt", ""),
                    key="breach_intelligence.hash_salt",
                ),
                providers=_provider_list(
                    breach_raw.get("providers", []),
                    key="breach_intelligence.providers",
                ),
            ),
            threat_intelligence=ThreatIntelligenceSettings(
                feed_paths=_path_list(
                    threat_raw.get("feed_paths", []),
                    key="threat_intelligence.feed_paths",
                ),
                allow_online=_bool_value(
                    threat_raw.get("allow_online", False),
                    key="threat_intelligence.allow_online",
                ),
                cache_path=_path_value(
                    threat_raw.get("cache_path", ".cache/dips/threat_intel_cache.json"),
                    key="threat_intelligence.cache_path",
                    default=".cache/dips/threat_intel_cache.json",
                ),
                cache_ttl_seconds=_int_value(
                    threat_raw.get("cache_ttl_seconds", 43200),
                    key="threat_intelligence.cache_ttl_seconds",
                    minimum=0,
                ),
                max_indicators=_int_value(
                    threat_raw.get("max_indicators", 250),
                    key="threat_intelligence.max_indicators",
                    minimum=1,
                ),
                providers=_threat_provider_list(
                    threat_raw.get("providers", []),
                    key="threat_intelligence.providers",
                ),
            ),
            event_timeline=EventTimelineSettings(
                store_path=_path_value(
                    timeline_raw.get("store_path", ".cache/dips/event_timeline.json"),
                    key="event_timeline.store_path",
                    default=".cache/dips/event_timeline.json",
                ),
                max_events=_int_value(
                    timeline_raw.get("max_events", 500),
                    key="event_timeline.max_events",
                    minimum=1,
                ),
                correlation_window_hours=_int_value(
                    timeline_raw.get("correlation_window_hours", 24),
                    key="event_timeline.correlation_window_hours",
                    minimum=1,
                ),
            ),
            ai_security_analysis=AiSecurityAnalysisSettings(
                provider=_string_value(
                    ai_raw.get("provider", "local_heuristic"),
                    key="ai_security_analysis.provider",
                    default="local_heuristic",
                ),
                allow_online=_bool_value(
                    ai_raw.get("allow_online", False),
                    key="ai_security_analysis.allow_online",
                ),
                endpoint=_string_value(
                    ai_raw.get("endpoint", ""),
                    key="ai_security_analysis.endpoint",
                ),
                api_key_env=_string_value(
                    ai_raw.get("api_key_env", ""),
                    key="ai_security_analysis.api_key_env",
                ),
                model=_string_value(
                    ai_raw.get("model", "local-heuristic-v1"),
                    key="ai_security_analysis.model",
                    default="local-heuristic-v1",
                ),
                timeout_seconds=_int_value(
                    ai_raw.get("timeout_seconds", 15),
                    key="ai_security_analysis.timeout_seconds",
                    minimum=1,
                ),
                max_findings=_int_value(
                    ai_raw.get("max_findings", 12),
                    key="ai_security_analysis.max_findings",
                    minimum=1,
                ),
                max_recommendations=_int_value(
                    ai_raw.get("max_recommendations", 6),
                    key="ai_security_analysis.max_recommendations",
                    minimum=1,
                ),
            ),
            plugin_system=PluginSystemSettings(
                search_paths=_path_list(
                    plugin_raw.get("search_paths", ["plugins"]),
                    key="plugin_system.search_paths",
                ),
                enabled_plugins=_string_list(
                    plugin_raw.get("enabled_plugins", []),
                    key="plugin_system.enabled_plugins",
                ),
                plugin_configs=_object_mapping(
                    plugin_raw.get("plugin_configs", {}),
                    key="plugin_system.plugin_configs",
                ),
                strict_validation=_bool_value(
                    plugin_raw.get("strict_validation", True),
                    key="plugin_system.strict_validation",
                    default=True,
                ),
            ),
            reporting=ReportingSettings(
                output_dir=_path_value(reporting_raw.get("output_dir", "reports"), key="reporting.output_dir", default="reports"),
                formats=_string_list(reporting_raw.get("formats", ["json", "html"]), key="reporting.formats"),
                redact_evidence=_bool_value(
                    reporting_raw.get("redact_evidence", True),
                    key="reporting.redact_evidence",
                    default=True,
                ),
            ),
            scoring=ScoringSettings(
                weights=_int_mapping(scoring_raw.get("weights", {}), key="scoring.weights"),
                module_multipliers=_float_mapping(
                    scoring_raw.get("module_multipliers", {}),
                    key="scoring.module_multipliers",
                ),
            ),
            risk_engine=RiskEngineSettings(
                enabled=_bool_value(
                    risk_engine_raw.get("enabled", True),
                    key="risk_engine.enabled",
                    default=True,
                ),
                category_weights=_float_mapping(
                    risk_engine_raw.get("category_weights", {}),
                    key="risk_engine.category_weights",
                ),
                thresholds=_int_mapping(
                    risk_engine_raw.get("thresholds", {}),
                    key="risk_engine.thresholds",
                ),
                max_recommendations=_int_value(
                    risk_engine_raw.get("max_recommendations", 6),
                    key="risk_engine.max_recommendations",
                    minimum=1,
                ),
                max_finding_titles=_int_value(
                    risk_engine_raw.get("max_finding_titles", 6),
                    key="risk_engine.max_finding_titles",
                    minimum=1,
                ),
            ),
            watch=WatchSettings(
                interval_seconds=_int_value(watch_raw.get("interval_seconds", 300), key="watch.interval_seconds", minimum=0),
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        self.scan.validate()
        self.modules.validate()
        self.browser.validate()
        self.breach_intelligence.validate()
        self.threat_intelligence.validate()
        self.event_timeline.validate()
        self.ai_security_analysis.validate()
        self.plugin_system.validate()
        self.reporting.validate()
        self.scoring.validate()
        self.risk_engine.validate()
        self.watch.validate()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": self.scan.to_dict(),
            "modules": self.modules.to_dict(),
            "browser": self.browser.to_dict(),
            "credential": self.credential.to_dict(),
            "email": self.email.to_dict(),
            "breach_intelligence": self.breach_intelligence.to_dict(),
            "threat_intelligence": self.threat_intelligence.to_dict(),
            "event_timeline": self.event_timeline.to_dict(),
            "ai_security_analysis": self.ai_security_analysis.to_dict(),
            "plugin_system": self.plugin_system.to_dict(),
            "reporting": self.reporting.to_dict(),
            "scoring": self.scoring.to_dict(),
            "risk_engine": self.risk_engine.to_dict(),
            "watch": self.watch.to_dict(),
        }


def load_config(config_path: str | None = None, cli_overrides: dict[str, Any] | None = None) -> AppConfig:
    config = read_json(DEFAULT_CONFIG_FILE)
    if config_path:
        config = deep_merge(config, read_json(path_from_input(config_path)))
    if cli_overrides:
        config = deep_merge(config, cli_overrides)
    return AppConfig.from_mapping(config)


def dump_config(config: AppConfig) -> str:
    return json.dumps(config.to_dict(), indent=2, sort_keys=True)
