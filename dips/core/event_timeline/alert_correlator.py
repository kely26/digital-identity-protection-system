"""Correlate security events into higher-order alert patterns."""

from __future__ import annotations

from datetime import datetime, timedelta

from dips.core.models import EventPattern, SecurityEvent, stable_finding_id


def _within_window(events: list[SecurityEvent], *, hours: int) -> list[SecurityEvent]:
    if not events:
        return []
    newest = max(datetime.fromisoformat(event.timestamp) for event in events)
    threshold = newest - timedelta(hours=hours)
    return [event for event in events if datetime.fromisoformat(event.timestamp) >= threshold]


def _build_pattern(name: str, severity: str, summary: str, events: list[SecurityEvent]) -> EventPattern:
    return EventPattern(
        id=stable_finding_id(name, *(event.id for event in events)),
        name=name,
        severity=severity,
        summary=summary,
        event_ids=[event.id for event in events],
        modules=sorted({event.module for event in events}),
    )


def correlate_events(events: list[SecurityEvent], *, window_hours: int = 24) -> list[EventPattern]:
    recent = _within_window(events, hours=window_hours)
    patterns: list[EventPattern] = []

    credential_reuse = [event for event in recent if event.event_type == "credential_reuse"]
    breach_exposure = [event for event in recent if event.event_type == "breach_exposure"]
    if credential_reuse and breach_exposure:
        correlated = [credential_reuse[-1], breach_exposure[-1]]
        patterns.append(
            _build_pattern(
                "Credential reuse plus breach exposure",
                "high",
                "Credential reuse and breach exposure were both observed, increasing takeover risk.",
                correlated,
            )
        )

    phishing = [event for event in recent if event.event_type == "phishing_analysis"]
    malicious_intel = [
        event for event in recent if event.module == "threat_intelligence" and event.severity in {"high", "critical"}
    ]
    if phishing and malicious_intel:
        correlated = [phishing[-1], malicious_intel[-1]]
        patterns.append(
            _build_pattern(
                "Phishing with malicious indicator",
                "critical",
                "A phishing signal was enriched with a malicious threat-intelligence indicator.",
                correlated,
            )
        )

    browser_risk = [event for event in recent if event.event_type == "browser_risk"]
    if browser_risk and malicious_intel:
        correlated = [browser_risk[-1], malicious_intel[-1]]
        patterns.append(
            _build_pattern(
                "Browser risk with hostile indicator",
                "high",
                "Browser posture issues overlap with a malicious domain, URL, or IP indicator.",
                correlated,
            )
        )

    secret_exposure = [event for event in recent if event.event_type == "secret_exposure"]
    privacy_risk = [event for event in recent if event.module == "privacy_risk"]
    if secret_exposure and privacy_risk:
        correlated = [secret_exposure[-1], privacy_risk[-1]]
        patterns.append(
            _build_pattern(
                "Secret exposure with privacy risk",
                "high",
                "Sensitive material and local privacy weaknesses were observed in the same timeline window.",
                correlated,
            )
        )

    return patterns
