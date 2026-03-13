from __future__ import annotations

import json

import pytest

from dips.core.exceptions import ReportError
from dips.core.models import EventPattern, EventTimeline, Finding, ModuleResult, RiskSummary, ScanReport, SecurityEvent
from dips.gui.state import (
    alert_correlation_clusters,
    build_payload,
    identity_exposure_map_nodes,
    load_latest_payload,
    load_report_payload,
    module_metrics,
    normalize_report_payload,
    overall_protection_score,
    prioritized_alerts,
    recommendation_list,
    scan_history_points,
    severity_heatmap_rows,
    threat_intel_rows,
    timeline_events,
)


def _sample_report() -> ScanReport:
    return ScanReport(
        scan_id="gui-report-001",
        started_at="2026-03-12T00:00:00+00:00",
        finished_at="2026-03-12T00:00:05+00:00",
        duration_ms=5000,
        platform_name="linux",
        hostname="workstation",
        username="alice",
        user_profile="/home/alice",
        target_paths=["/home/alice/Documents"],
        notes=["discovered 2 candidate files"],
        modules=[
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
                        summary="duplicate candidate",
                        evidence={"count": 2},
                        location="credential_inputs",
                        recommendation="Use unique passwords for every account.",
                        tags=["password", "reuse"],
                    ),
                    Finding(
                        id="short-1",
                        module="credential_hygiene",
                        severity="medium",
                        confidence="high",
                        title="Short password detected",
                        summary="too short",
                        evidence={"length": 8},
                        location="credential_inputs",
                        recommendation="Use a longer passphrase.",
                        tags=["password", "length"],
                    ),
                ],
                metadata={"password_count": 2, "unique_passwords": 1},
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
                        summary="masked identity exposed in multiple datasets",
                        evidence={
                            "identifier": "al***@example.com",
                            "identifier_type": "email",
                            "breach_count": 2,
                            "sources": ["forum_dump", "credential_leak"],
                        },
                        location="al***@example.com",
                        recommendation="Rotate affected credentials and enable MFA.",
                        tags=["breach", "identity", "email"],
                    )
                ],
                metadata={"identifiers_scanned": 1, "identifiers_with_hits": 1},
            ),
            ModuleResult(
                module="email_phishing",
                description="email",
                status="completed",
                findings=[
                    Finding(
                        id="phish-1",
                        module="email_phishing",
                        severity="high",
                        confidence="high",
                        title="Suspicious URLs detected in email body",
                        summary="Punycode and deceptive mail pressure were detected.",
                        evidence={"urls": ["http://xn--microsft-3ya.example/login"]},
                        location="phish.eml",
                        recommendation="Do not open the message and report the sender.",
                        tags=["email", "url", "phishing"],
                    )
                ],
                metadata={"emails_scanned": 1},
            ),
            ModuleResult(
                module="threat_intelligence",
                description="intel",
                status="completed",
                findings=[
                    Finding(
                        id="intel-1",
                        module="threat_intelligence",
                        severity="critical",
                        confidence="high",
                        title="Threat intelligence match for domain",
                        summary="The domain is marked malicious by multiple sources.",
                        evidence={
                            "indicator": "xn--microsft-3ya.example",
                            "indicator_type": "domain",
                            "reputation": "malicious",
                            "confidence": 0.91,
                            "sources": ["threat_feed_1", "ioc_database"],
                        },
                        location="phish.eml",
                        recommendation="Block the domain and investigate affected accounts.",
                        tags=["threat-intel", "domain", "malicious", "phishing"],
                    )
                ],
                metadata={"indicators_scanned": 3, "indicators_enriched": 1},
            ),
            ModuleResult(
                module="ai_security_analysis",
                description="ai",
                status="completed",
                findings=[],
                metadata={
                    "analysis_mode": "local",
                    "findings_reviewed": 5,
                    "recommended_actions": [
                        "Use unique passwords for every account.",
                        "Enable MFA on exposed identities.",
                    ],
                    "suspicious_patterns": [
                        {
                            "title": "Compounded account takeover exposure",
                            "severity": "high",
                            "summary": "Credential reuse overlaps with breach exposure.",
                            "related_findings": ["reuse-1", "breach-1"],
                        }
                    ],
                },
            ),
        ],
        summary=RiskSummary(
            overall_score=68,
            overall_label="high",
            severity_counts={"critical": 1, "high": 3, "medium": 1},
            module_scores={
                "credential_hygiene": 40,
                "breach_intelligence": 62,
                "email_phishing": 70,
                "threat_intelligence": 82,
                "ai_security_analysis": 0,
            },
            top_recommendations=["Use unique passwords for every account."],
        ),
        config={"reporting": {"redact_evidence": True}},
        timeline=EventTimeline(
            store_path=".cache/dips/event_timeline.json",
            total_events=4,
            events=[
                SecurityEvent(
                    id="event-1",
                    timestamp="2026-03-12T00:00:01+00:00",
                    module="credential_hygiene",
                    severity="high",
                    event_type="credential_reuse",
                    title="Password reuse detected",
                    summary="same password reused",
                    location="credential_inputs",
                ),
                SecurityEvent(
                    id="event-2",
                    timestamp="2026-03-12T00:00:02+00:00",
                    module="breach_intelligence",
                    severity="high",
                    event_type="breach_exposure",
                    title="Identity exposure detected in breach intelligence",
                    summary="breach hit",
                    location="al***@example.com",
                    correlations=["Credential reuse plus breach exposure"],
                ),
                SecurityEvent(
                    id="event-3",
                    timestamp="2026-03-12T00:00:03+00:00",
                    module="email_phishing",
                    severity="high",
                    event_type="phishing_analysis",
                    title="Suspicious URLs detected in email body",
                    summary="phish detected",
                    location="phish.eml",
                    correlations=["Phishing with malicious indicator"],
                ),
                SecurityEvent(
                    id="event-4",
                    timestamp="2026-03-12T00:00:04+00:00",
                    module="threat_intelligence",
                    severity="critical",
                    event_type="threat_intelligence",
                    title="Threat intelligence match for domain",
                    summary="malicious domain",
                    location="phish.eml",
                    correlations=["Phishing with malicious indicator"],
                ),
            ],
            patterns=[
                EventPattern(
                    id="pattern-1",
                    name="Credential reuse plus breach exposure",
                    severity="high",
                    summary="Reuse and breach exposure align.",
                    event_ids=["event-1", "event-2"],
                    modules=["credential_hygiene", "breach_intelligence"],
                ),
                EventPattern(
                    id="pattern-2",
                    name="Phishing with malicious indicator",
                    severity="critical",
                    summary="A phishing sample overlaps with malicious infrastructure.",
                    event_ids=["event-3", "event-4"],
                    modules=["email_phishing", "threat_intelligence"],
                ),
            ],
        ),
    )


def test_gui_state_builds_module_metrics():
    payload = build_payload(_sample_report(), redact=True)

    assert overall_protection_score(payload) == 32
    assert recommendation_list(payload) == ["Use unique passwords for every account."]

    cards = module_metrics(payload, "credential_hygiene")
    values = {card["title"]: card["value"] for card in cards}

    assert values["Hygiene Score"] == "60"
    assert values["Reuse Detections"] == "1"
    assert values["Candidates Reviewed"] == "2"
    assert recommendation_list(payload, "ai_security_analysis") == [
        "Use unique passwords for every account.",
        "Enable MFA on exposed identities.",
    ]


def test_gui_state_builds_soc_views():
    payload = build_payload(_sample_report(), redact=True)

    alerts = prioritized_alerts(payload)
    assert alerts[0]["priority_label"] == "P1"

    intel_rows = threat_intel_rows(payload)
    assert intel_rows[0]["indicator"] == "xn--microsft-3ya.example"
    assert intel_rows[0]["reputation"] == "malicious"

    heatmap = severity_heatmap_rows(payload)
    intel_heatmap = next(row for row in heatmap if row["module"] == "threat_intelligence")
    assert intel_heatmap["values"][-1] == 1

    nodes = identity_exposure_map_nodes(payload)
    assert any(node["zone"] == "breach" for node in nodes)
    assert any(node["zone"] == "network" for node in nodes)

    clusters = alert_correlation_clusters(payload)
    assert clusters[0]["label"] == "Phishing with malicious indicator"

    events = timeline_events(payload, limit=2)
    assert [event["title"] for event in events] == [
        "Threat intelligence match for domain",
        "Suspicious URLs detected in email body",
    ]


def test_load_report_payload_rejects_invalid_json(tmp_path):
    report = tmp_path / "broken.json"
    report.write_text("{bad json", encoding="utf-8")

    with pytest.raises(ReportError):
        load_report_payload(report)


def test_load_report_payload_rejects_non_json_extension(tmp_path):
    report = tmp_path / "broken.txt"
    report.write_text("{}", encoding="utf-8")

    with pytest.raises(ReportError, match="must be a JSON file"):
        load_report_payload(report)


def test_normalize_report_payload_handles_missing_sections():
    payload = normalize_report_payload({"scan_id": "custom", "summary": None, "modules": None, "timeline": None})

    assert payload["scan_id"] == "custom"
    assert payload["summary"]["overall_score"] == 0
    assert isinstance(payload["modules"], list)
    assert isinstance(payload["timeline"], dict)


def test_load_latest_payload_skips_broken_reports(tmp_path):
    valid_report = tmp_path / "valid.json"
    valid_report.write_text(json.dumps(build_payload(_sample_report(), redact=True)), encoding="utf-8")
    broken_report = tmp_path / "broken.json"
    broken_report.write_text("{bad json", encoding="utf-8")

    latest_payload, outputs = load_latest_payload(tmp_path)

    assert latest_payload is not None
    assert latest_payload["scan_id"] == "gui-report-001"
    assert outputs["json"].endswith("valid.json")


def test_scan_history_points_reuses_cached_report_series(tmp_path, monkeypatch):
    payload = build_payload(_sample_report(), redact=True)
    report_path = tmp_path / "scan-001.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    outputs = {"json": str(report_path)}

    import dips.gui.state as state_module

    real_read_json_file = state_module.read_json_file
    read_calls = 0

    def _counting_read_json_file(*args, **kwargs):
        nonlocal read_calls
        read_calls += 1
        return real_read_json_file(*args, **kwargs)

    monkeypatch.setattr(state_module, "read_json_file", _counting_read_json_file)

    first = scan_history_points(payload, outputs, limit=8)
    second = scan_history_points(payload, outputs, limit=8)

    assert first == second
    assert read_calls == 1
