"""Threat feed provider management and provider abstractions."""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dips.core.config import ThreatIntelProviderSettings, ThreatIntelligenceSettings
from dips.modules.threat_intelligence.ioc_parser import normalize_indicator
from dips.utils.paths import path_from_input
from dips.utils.secure_io import read_json_file


def _load_feed(path: Path) -> list[dict[str, Any]]:
    try:
        payload = read_json_file(path, max_bytes=25 * 1024 * 1024)
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
        return []
    if isinstance(payload, dict):
        records = payload.get("records", [])
        return records if isinstance(records, list) else []
    if isinstance(payload, list):
        return payload
    return []


def _normalize_record(record: dict[str, Any], *, default_source: str) -> dict[str, Any] | None:
    indicator = str(record.get("indicator", "")).strip()
    indicator_type = str(record.get("type", record.get("indicator_type", ""))).strip().lower()
    reputation = str(record.get("reputation", "unknown")).strip().lower()
    if not indicator or not indicator_type:
        return None
    try:
        confidence = float(record.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "indicator": normalize_indicator(indicator, indicator_type),
        "indicator_type": indicator_type,
        "reputation": reputation,
        "confidence": max(0.0, min(confidence, 1.0)),
        "source": str(record.get("source", default_source)),
    }


class ThreatProvider(ABC):
    name = "provider"
    min_interval_seconds = 0

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> list[dict[str, Any]]:
        raise NotImplementedError


class OfflineThreatFeedProvider(ThreatProvider):
    name = "offline_feed"
    min_interval_seconds = 0

    def __init__(self, feed_paths: list[Path]) -> None:
        self.feed_paths = feed_paths
        self.records: list[dict[str, Any]] = []
        for path in feed_paths:
            for raw_record in _load_feed(path):
                if not isinstance(raw_record, dict):
                    continue
                normalized = _normalize_record(raw_record, default_source=path.stem)
                if normalized is not None:
                    self.records.append(normalized)

    def lookup(self, indicator: str, indicator_type: str) -> list[dict[str, Any]]:
        normalized = normalize_indicator(indicator, indicator_type)
        return [
            dict(record)
            for record in self.records
            if record["indicator"] == normalized and record["indicator_type"] == indicator_type
        ]


class HttpThreatProvider(ThreatProvider):
    def __init__(self, settings: ThreatIntelProviderSettings) -> None:
        self.settings = settings
        self.name = settings.name
        self.min_interval_seconds = settings.min_interval_seconds

    def lookup(self, indicator: str, indicator_type: str) -> list[dict[str, Any]]:
        params = urlencode({"indicator": indicator, "type": indicator_type})
        separator = "&" if "?" in self.settings.endpoint else "?"
        request = Request(f"{self.settings.endpoint}{separator}{params}")
        api_key = os.environ.get(self.settings.api_key_env, "") if self.settings.api_key_env else ""
        if api_key:
            request.add_header("Authorization", f"Bearer {api_key}")
        request.add_header("Accept", "application/json")
        try:
            with urlopen(request, timeout=self.settings.timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except (URLError, json.JSONDecodeError, TimeoutError, OSError):
            return []

        if isinstance(payload, dict):
            if "indicator" in payload or "reputation" in payload:
                payload = [payload]
            else:
                payload = payload.get("results", payload.get("matches", payload.get("records", [])))
        if not isinstance(payload, list):
            return []

        results: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            normalized = _normalize_record(item, default_source=self.settings.name)
            if normalized is None:
                continue
            if normalized["indicator_type"] != indicator_type:
                continue
            if normalized["indicator"] != normalize_indicator(indicator, indicator_type):
                continue
            results.append(normalized)
        return results


class ThreatFeedManager:
    def __init__(self, settings: ThreatIntelligenceSettings, *, working_directory: Path) -> None:
        self.settings = settings
        self.working_directory = working_directory
        self._last_lookup: dict[str, float] = {}
        self.providers: list[ThreatProvider] = []
        feed_paths = [self._resolve_path(path) for path in settings.feed_paths]
        if feed_paths:
            self.providers.append(OfflineThreatFeedProvider(feed_paths))
        if settings.allow_online:
            for provider in settings.providers:
                if not provider.enabled:
                    continue
                if provider.plugin == "http_json":
                    self.providers.append(HttpThreatProvider(provider))

    def _resolve_path(self, value: str) -> Path:
        path = path_from_input(value)
        if path.is_absolute():
            return path
        return (self.working_directory / path).resolve()

    def _apply_rate_limit(self, provider: ThreatProvider) -> None:
        minimum = max(0, int(getattr(provider, "min_interval_seconds", 0)))
        if minimum == 0:
            return
        now = time.monotonic()
        last = self._last_lookup.get(provider.name, 0.0)
        delay = minimum - (now - last)
        if delay > 0:
            time.sleep(delay)
        self._last_lookup[provider.name] = time.monotonic()

    def lookup(self, indicator: str, indicator_type: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for provider in self.providers:
            self._apply_rate_limit(provider)
            matches.extend(provider.lookup(indicator, indicator_type))
        return matches
