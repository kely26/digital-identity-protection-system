from __future__ import annotations

from dips.core.event_timeline import build_event_timeline
from dips.core.models import Finding, ModuleResult
from dips.gui.state import timeline_events


def test_event_timeline_collects_and_correlates_events(default_config, make_context):
    config = default_config
    config.event_timeline.max_events = 50

    context = make_context(config=config)
    results = [
        ModuleResult(
            module="credential_hygiene",
            description="credential",
            status="completed",
            findings=[
                Finding(
                    id="reuse-1",
                    module="credential_hygiene",
                    severity="high",
                    confidence="high",
                    title="Password reuse detected",
                    summary="same password reused",
                    evidence={},
                    location="credential_inputs",
                    recommendation="Rotate reused passwords",
                    tags=["password", "reuse"],
                )
            ],
        ),
        ModuleResult(
            module="breach_intelligence",
            description="breach",
            status="completed",
            findings=[
                Finding(
                    id="breach-1",
                    module="breach_intelligence",
                    severity="high",
                    confidence="high",
                    title="Identity exposure detected in breach intelligence",
                    summary="exposed in breach dataset",
                    evidence={},
                    location="se***@example.com",
                    recommendation="Enable MFA",
                    tags=["breach", "identity", "email"],
                )
            ],
        ),
        ModuleResult(
            module="email_phishing",
            description="email",
            status="completed",
            findings=[
                Finding(
                    id="mail-1",
                    module="email_phishing",
                    severity="high",
                    confidence="high",
                    title="Suspicious URLs detected in email body",
                    summary="phishing urls found",
                    evidence={},
                    location="phish.eml",
                    recommendation="Do not click the links",
                    tags=["email", "url", "phishing"],
                )
            ],
        ),
        ModuleResult(
            module="threat_intelligence",
            description="threat",
            status="completed",
            findings=[
                Finding(
                    id="ti-1",
                    module="threat_intelligence",
                    severity="critical",
                    confidence="high",
                    title="Threat intelligence match for url",
                    summary="malicious url",
                    evidence={},
                    location="phish.eml",
                    recommendation="Block the URL",
                    tags=["threat-intel", "url", "malicious", "phishing"],
                )
            ],
        ),
    ]

    timeline = build_event_timeline(context, results)

    assert len(timeline.events) == 4
    assert timeline.total_events == 4
    assert timeline.events[0].timestamp <= timeline.events[-1].timestamp
    names = {pattern.name for pattern in timeline.patterns}
    assert "Credential reuse plus breach exposure" in names
    assert "Phishing with malicious indicator" in names
    assert any(event.correlations for event in timeline.events)


def test_timeline_events_filter_by_severity_and_module(default_config, make_context):
    context = make_context(config=default_config)
    results = [
        ModuleResult(
            module="browser_audit",
            description="browser",
            status="completed",
            findings=[
                Finding(
                    id="browser-1",
                    module="browser_audit",
                    severity="medium",
                    confidence="medium",
                    title="Safe browsing disabled",
                    summary="disabled protection",
                    evidence={},
                    location="browser-profile",
                    recommendation="Enable safe browsing",
                    tags=["browser"],
                )
            ],
        )
    ]
    timeline = build_event_timeline(context, results)
    timeline_payload = {
        "timeline": {
            "events": [
                {
                    "timestamp": event.timestamp,
                    "severity": event.severity,
                    "title": event.title,
                    "module": event.module,
                }
                for event in timeline.events
            ]
        }
    }

    filtered = timeline_events(timeline_payload, severity="medium", module_name="browser_audit")
    assert len(filtered) == 1
    assert filtered[0]["title"] == "Safe browsing disabled"


def test_event_timeline_does_not_surface_stale_patterns_on_empty_scan(default_config, make_context):
    config = default_config
    config.event_timeline.max_events = 50

    context = make_context(config=config)
    context.scan_id = "seed-scan"
    seeded = build_event_timeline(
        context,
        [
            ModuleResult(
                module="email_phishing",
                description="email",
                status="completed",
                findings=[
                    Finding(
                        id="mail-1",
                        module="email_phishing",
                        severity="high",
                        confidence="high",
                        title="Suspicious URLs detected in email body",
                        summary="phishing urls found",
                        evidence={},
                        location="phish.eml",
                        recommendation="Do not click the links",
                        tags=["email", "url", "phishing"],
                    )
                ],
            ),
            ModuleResult(
                module="threat_intelligence",
                description="threat",
                status="completed",
                findings=[
                    Finding(
                        id="ti-1",
                        module="threat_intelligence",
                        severity="critical",
                        confidence="high",
                        title="Threat intelligence match for url",
                        summary="malicious url",
                        evidence={},
                        location="phish.eml",
                        recommendation="Block the URL",
                        tags=["threat-intel", "url", "malicious", "phishing"],
                    )
                ],
            ),
        ],
    )
    assert seeded.patterns

    followup = make_context(config=config)
    followup.scan_id = "empty-scan"
    empty_timeline = build_event_timeline(followup, [])

    assert empty_timeline.total_events >= 2
    assert empty_timeline.patterns == []
