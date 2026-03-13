from __future__ import annotations

from dips.core.models import Finding, ModuleResult
from dips.scoring.engine import summarize_results


def test_risk_engine_tracks_categories_and_contributing_findings(default_config):
    config = default_config
    config.scoring.module_multipliers["breach_intelligence"] = 1.0
    config.risk_engine.category_weights["breach_exposure"] = 2.0

    results = [
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
                    summary="user matched multiple breach records",
                    evidence={"breach_count": 3},
                    location="se***@example.com",
                    recommendation="Enable MFA",
                    tags=["breach", "email"],
                )
            ],
        ),
        ModuleResult(
            module="credential_hygiene",
            description="credential",
            status="completed",
            findings=[
                Finding(
                    id="cred-1",
                    module="credential_hygiene",
                    severity="high",
                    confidence="high",
                    title="Password reuse detected",
                    summary="same password reused",
                    evidence={"count": 2},
                    location="credential_inputs",
                    recommendation="Rotate reused passwords",
                    tags=["password", "reuse"],
                )
            ],
        ),
    ]

    summary = summarize_results(results, config)

    assert summary.overall_score == 30
    assert summary.overall_label == "low"
    assert summary.category_scores["breach_exposure"] == 20
    assert summary.category_scores["credential_reuse"] == 10
    assert summary.module_scores["breach_intelligence"] == 20
    assert summary.contributing_findings[0] == "breach_intelligence: Identity exposure detected in breach intelligence"
    assert summary.risk_model == "digital_identity_weighted_sum"


def test_risk_engine_maps_threat_intelligence_to_phishing_and_intel_categories(default_config):
    config = default_config
    results = [
        ModuleResult(
            module="threat_intelligence",
            description="threat",
            status="completed",
            findings=[
                Finding(
                    id="ti-1",
                    module="threat_intelligence",
                    severity="high",
                    confidence="high",
                    title="Threat intelligence match for url",
                    summary="malicious url",
                    evidence={},
                    location="mail.eml",
                    recommendation="Block the URL",
                    tags=["threat-intel", "url", "malicious", "phishing"],
                ),
                Finding(
                    id="ti-2",
                    module="threat_intelligence",
                    severity="medium",
                    confidence="medium",
                    title="Threat intelligence match for ip",
                    summary="suspicious ip",
                    evidence={},
                    location="mail.eml",
                    recommendation="Review the IP",
                    tags=["threat-intel", "ip", "suspicious"],
                ),
            ],
        )
    ]

    summary = summarize_results(results, config)

    assert summary.category_scores["phishing_risk"] == 11
    assert summary.category_scores["threat_intelligence"] == 7


def test_risk_engine_does_not_inflate_score_for_ai_analysis(default_config):
    config = default_config
    results = [
        ModuleResult(
            module="ai_security_analysis",
            description="ai",
            status="completed",
            findings=[
                Finding(
                    id="ai-1",
                    module="ai_security_analysis",
                    severity="critical",
                    confidence="medium",
                    title="AI security summary",
                    summary="advice only",
                    evidence={},
                    location="report_summary",
                    recommendation="Review the report",
                    tags=["ai-analysis"],
                )
            ],
        )
    ]

    summary = summarize_results(results, config)

    assert summary.overall_score == 0
    assert summary.module_scores["ai_security_analysis"] == 0
    assert summary.category_scores.get("analysis_advice", 0) == 0
