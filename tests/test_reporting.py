from __future__ import annotations

import json

from dips.core.models import Finding, ModuleResult, RiskSummary, ScanReport
from dips.reporting.html_report import write_html_report
from dips.reporting.json_report import write_json_report


def test_reporting_writes_redacted_outputs(tmp_path):
    report = ScanReport(
        scan_id="scan123",
        started_at="2026-03-12T00:00:00+00:00",
        finished_at="2026-03-12T00:00:05+00:00",
        duration_ms=5000,
        platform_name="linux",
        hostname="host",
        username="alice",
        user_profile="/home/alice",
        target_paths=["/home/alice/Documents"],
        notes=[],
        modules=[
            ModuleResult(
                module="identity_exposure",
                description="identity",
                status="completed",
                findings=[
                    Finding(
                        id="finding123",
                        module="identity_exposure",
                        severity="critical",
                        confidence="high",
                        title="GitHub token pattern detected",
                        summary="token found",
                        evidence={"sample": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 for sam@example.com"},
                        location="/tmp/example.env",
                        recommendation="Rotate token",
                        tags=["token"],
                    )
                ],
            ),
            ModuleResult(
                module="ai_security_analysis",
                description="ai",
                status="completed",
                findings=[],
                metadata={
                    "summary": "The latest scan detected token exposure and recommends rapid containment.",
                    "risk_explanation": "Exposed tokens can enable account abuse if they remain active.",
                    "recommended_actions": ["Rotate token", "Enable MFA"],
                    "suspicious_patterns": [
                        {
                            "title": "Local secret exposure may enable session abuse",
                            "summary": "A token was exposed locally.",
                        }
                    ],
                },
            ),
        ],
        summary=RiskSummary(
            overall_score=80,
            overall_label="critical",
            severity_counts={"critical": 1},
            module_scores={"identity_exposure": 80},
            top_recommendations=["Rotate token"],
            category_scores={"token_exposure": 80},
            contributing_findings=["identity_exposure: GitHub token pattern detected"],
        ),
        config={
            "reporting": {"redact_evidence": True},
            "credential": {"passwords": ["Sup3rSecret!"]},
            "breach_intelligence": {
                "identifiers": ["security.user@example.com"],
                "hash_salt": "pepper-value",
            },
            "plugin_system": {
                "plugin_configs": {"custom_scanner": {"api_key": "plain-secret", "external_tool_command": "scan"}},
            },
        },
        extensions={
            "plugins": {
                "custom_scanner": {
                    "version": "1.0.0",
                    "description": "Example custom scanner plugin",
                    "modules": ["custom_sensitive_file_scanner"],
                    "report": {
                        "title": "Custom Scanner Insights",
                        "summary": "Detected 1 custom artifact and enriched 2 findings.",
                    },
                }
            }
        },
    )

    json_path = write_json_report(report, tmp_path / "report.json", redact=True)
    html_path = write_html_report(report, tmp_path / "report.html", redact=True)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")

    assert json_path.exists()
    assert html_path.exists()
    assert "[REDACTED_GITHUB_TOKEN]" in json.dumps(payload)
    assert "sa***@example.com" in json.dumps(payload)
    assert payload["username"] == "[REDACTED_USER]"
    assert payload["hostname"] == "[REDACTED_HOST]"
    assert payload["config"]["credential"]["passwords"] == ["[REDACTED_PASSWORD_INPUT]"]
    assert payload["config"]["breach_intelligence"]["identifiers"] == ["[REDACTED_IDENTIFIER]"]
    assert payload["config"]["breach_intelligence"]["hash_salt"] == "[REDACTED_HASH_SALT]"
    assert payload["config"]["plugin_system"]["plugin_configs"]["custom_scanner"]["api_key"] == "[REDACTED_SECRET]"
    assert "[REDACTED_GITHUB_TOKEN]" in html
    assert "Risk Categories" in html
    assert "Top Risk Drivers" in html
    assert "AI Security Analysis" in html
    assert "The latest scan detected token exposure" in html
    assert "Plugin Extensions" in html
    assert "Custom Scanner Insights" in html
    assert "Security Timeline" in html
    assert "Correlated Patterns" in html
    assert "digital_identity_weighted_sum" in html
