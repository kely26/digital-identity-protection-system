"""Collect security events from scan findings."""

from __future__ import annotations

from datetime import datetime, timedelta

from dips.core.models import ModuleResult, SecurityEvent, stable_finding_id


def _event_type_for_finding(module_name: str, title: str, tags: list[str]) -> str:
    lowered_title = title.lower()
    lowered_tags = {tag.lower() for tag in tags}

    if module_name == "credential_hygiene" and ("reuse" in lowered_tags or "reuse" in lowered_title):
        return "credential_reuse"
    if module_name == "breach_intelligence":
        return "breach_exposure"
    if module_name == "email_phishing":
        return "phishing_analysis"
    if module_name == "browser_audit":
        return "browser_risk"
    if module_name == "threat_intelligence":
        return "threat_intelligence"
    if "token" in lowered_tags or "private-key" in lowered_tags:
        return "secret_exposure"
    return module_name


def collect_events(scan_id: str, started_at: str, results: list[ModuleResult]) -> list[SecurityEvent]:
    base_time = datetime.fromisoformat(started_at)
    events: list[SecurityEvent] = []

    for module_index, result in enumerate(results):
        module_time = base_time + timedelta(seconds=module_index * 2)
        for finding_index, finding in enumerate(result.findings):
            event_time = module_time + timedelta(milliseconds=finding_index * 250)
            event_type = _event_type_for_finding(result.module, finding.title, finding.tags)
            event_id = stable_finding_id(scan_id, result.module, finding.id, finding.location)
            events.append(
                SecurityEvent(
                    id=event_id,
                    timestamp=event_time.isoformat(),
                    module=result.module,
                    severity=finding.severity,
                    event_type=event_type,
                    title=finding.title,
                    summary=finding.summary,
                    location=finding.location,
                    scan_id=scan_id,
                    tags=list(finding.tags),
                    related_findings=[finding.id],
                )
            )

    events.sort(key=lambda item: (item.timestamp, item.module, item.title))
    return events
