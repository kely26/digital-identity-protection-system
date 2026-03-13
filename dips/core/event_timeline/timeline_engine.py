"""Build chronological security timelines for reports and the desktop dashboard."""

from __future__ import annotations

from dips.core.event_timeline.alert_correlator import correlate_events
from dips.core.event_timeline.event_collector import collect_events
from dips.core.event_timeline.event_store import EventStore
from dips.core.models import EventTimeline, ModuleResult
from dips.utils.paths import path_from_input


def build_event_timeline(context, results: list[ModuleResult]) -> EventTimeline:
    settings = context.config.event_timeline
    store_path = path_from_input(settings.store_path)
    if not store_path.is_absolute():
        store_path = (context.working_directory / store_path).resolve()

    store = EventStore(store_path, max_events=settings.max_events)
    current_events = collect_events(context.scan_id, context.started_at, results)
    all_events = store.append(current_events)
    all_patterns = correlate_events(all_events, window_hours=settings.correlation_window_hours)
    current_event_ids = {event.id for event in current_events}
    patterns = [
        pattern
        for pattern in all_patterns
        if current_event_ids and any(event_id in current_event_ids for event_id in pattern.event_ids)
    ]

    correlated_ids: dict[str, list[str]] = {}
    for pattern in patterns:
        for event_id in pattern.event_ids:
            correlated_ids.setdefault(event_id, []).append(pattern.name)

    visible_events = []
    for event in all_events[-settings.max_events :]:
        enriched = event
        enriched.correlations = correlated_ids.get(event.id, [])
        visible_events.append(enriched)

    return EventTimeline(
        store_path=str(store_path),
        total_events=len(all_events),
        events=visible_events,
        patterns=patterns,
    )
