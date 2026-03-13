"""Local cache for threat intelligence lookups."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from dips.utils.secure_io import atomic_write_json, read_json_file


class ThreatIntelCache:
    def __init__(self, path: Path, *, ttl_seconds: int = 43200) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            payload = read_json_file(self.path, max_bytes=4 * 1024 * 1024)
        except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _save(self) -> None:
        atomic_write_json(self.path, self._records, private=True)

    @staticmethod
    def _cache_key(indicator: str, indicator_type: str) -> str:
        digest = hashlib.sha256(f"{indicator_type}:{indicator}".encode("utf-8")).hexdigest()
        return f"{indicator_type}:{digest}"

    def get(self, indicator: str, indicator_type: str) -> dict[str, Any] | None:
        key = self._cache_key(indicator, indicator_type)
        record = self._records.get(key)
        if not isinstance(record, dict):
            return None
        cached_at = float(record.get("cached_at", 0))
        if self.ttl_seconds and (time.time() - cached_at) > self.ttl_seconds:
            self._records.pop(key, None)
            self._save()
            return None
        result = record.get("result")
        return result if isinstance(result, dict) else None

    def set(self, indicator: str, indicator_type: str, result: dict[str, Any]) -> None:
        key = self._cache_key(indicator, indicator_type)
        self._records[key] = {"cached_at": time.time(), "result": result}
        self._save()
