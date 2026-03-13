"""Local cache for breach intelligence lookups."""

from __future__ import annotations

import json
from pathlib import Path
from time import time
from typing import Any

from dips.utils.secure_io import atomic_write_json, read_json_file


class BreachCache:
    def __init__(self, cache_path: Path, *, ttl_seconds: int) -> None:
        self.cache_path = cache_path
        self.ttl_seconds = ttl_seconds
        self._payload: dict[str, Any] | None = None

    def _read(self) -> dict[str, Any]:
        if self._payload is not None:
            return self._payload
        try:
            payload = read_json_file(self.cache_path, max_bytes=4 * 1024 * 1024)
        except FileNotFoundError:
            self._payload = {}
            return self._payload
        except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
            self._payload = {}
            return self._payload
        self._payload = payload if isinstance(payload, dict) else {}
        return self._payload

    def _write(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        atomic_write_json(self.cache_path, payload, private=True)

    def get(self, key: str) -> dict[str, Any] | None:
        payload = self._read()
        item = payload.get(key)
        if not isinstance(item, dict):
            return None
        cached_at = float(item.get("cached_at", 0))
        if self.ttl_seconds and cached_at and (time() - cached_at) > self.ttl_seconds:
            return None
        data = item.get("data")
        return data if isinstance(data, dict) else None

    def set(self, key: str, data: dict[str, Any]) -> None:
        payload = self._read()
        payload[key] = {
            "cached_at": int(time()),
            "data": data,
        }
        self._write(payload)
