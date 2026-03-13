"""Persistent storage for DIPS security events."""

from __future__ import annotations

import json
from pathlib import Path

from dips.core.models import SecurityEvent, to_primitive
from dips.utils.secure_io import atomic_write_json, read_json_file


class EventStore:
    def __init__(self, path: Path, *, max_events: int = 500) -> None:
        self.path = path
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load_events(self) -> list[SecurityEvent]:
        try:
            payload = read_json_file(self.path, max_bytes=8 * 1024 * 1024)
        except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
            return []
        if not isinstance(payload, list):
            return []

        events: list[SecurityEvent] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                events.append(
                    SecurityEvent(
                        id=str(item.get("id", "")),
                        timestamp=str(item.get("timestamp", "")),
                        module=str(item.get("module", "")),
                        severity=str(item.get("severity", "info")),
                        event_type=str(item.get("event_type", "")),
                        title=str(item.get("title", "")),
                        summary=str(item.get("summary", "")),
                        location=str(item.get("location", "")),
                        scan_id=str(item.get("scan_id", "")),
                        tags=[str(tag) for tag in item.get("tags", []) if isinstance(tag, str)],
                        related_findings=[
                            str(value) for value in item.get("related_findings", []) if isinstance(value, str)
                        ],
                        correlations=[
                            str(value) for value in item.get("correlations", []) if isinstance(value, str)
                        ],
                    )
                )
            except TypeError:
                continue
        return events

    def save_events(self, events: list[SecurityEvent]) -> None:
        trimmed = sorted(events, key=lambda item: item.timestamp)[-self.max_events :]
        atomic_write_json(self.path, [to_primitive(event) for event in trimmed], private=True)

    def append(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        existing = self.load_events()
        merged: dict[str, SecurityEvent] = {event.id: event for event in existing}
        for event in events:
            merged[event.id] = event
        ordered = sorted(merged.values(), key=lambda item: item.timestamp)
        self.save_events(ordered)
        return ordered[-self.max_events :]
