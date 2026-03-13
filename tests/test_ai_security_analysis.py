from __future__ import annotations

from dips.core.models import Finding, ModuleResult
from dips.modules.ai_security_analysis import AiSecurityAnalysisScanner


def _finding(
    *,
    module: str,
    severity: str,
    title: str,
    summary: str,
    recommendation: str,
    tags: list[str],
    location: str = "fixture",
) -> Finding:
    return Finding(
        id=f"{module}-{title}".lower().replace(" ", "-"),
        module=module,
        severity=severity,
        confidence="high",
        title=title,
        summary=summary,
        evidence={},
        location=location,
        recommendation=recommendation,
        tags=tags,
    )


def test_ai_security_analysis_detects_compound_patterns(default_config, make_context):
    context = make_context(config=default_config)
    prior_results = [
        ModuleResult(
            module="breach_intelligence",
            description="breach",
            status="completed",
            findings=[
                _finding(
                    module="breach_intelligence",
                    severity="high",
                    title="Identity exposure detected in breach intelligence",
                    summary="user matched breach records",
                    recommendation="Enable MFA on exposed accounts.",
                    tags=["breach", "email"],
                )
            ],
        ),
        ModuleResult(
            module="credential_hygiene",
            description="credential",
            status="completed",
            findings=[
                _finding(
                    module="credential_hygiene",
                    severity="high",
                    title="Password reuse detected",
                    summary="same password reused",
                    recommendation="Use unique passwords for each account.",
                    tags=["password", "reuse"],
                )
            ],
        ),
        ModuleResult(
            module="email_phishing",
            description="email",
            status="completed",
            findings=[
                _finding(
                    module="email_phishing",
                    severity="high",
                    title="Suspicious URLs detected",
                    summary="email contains suspicious links",
                    recommendation="Block the message and warn users.",
                    tags=["phishing", "url"],
                )
            ],
        ),
        ModuleResult(
            module="threat_intelligence",
            description="threat",
            status="completed",
            findings=[
                _finding(
                    module="threat_intelligence",
                    severity="high",
                    title="Threat intelligence match for url",
                    summary="malicious url identified",
                    recommendation="Block the URL at the gateway.",
                    tags=["threat-intel", "url", "malicious", "phishing"],
                )
            ],
        ),
    ]

    result = AiSecurityAnalysisScanner().timed_run(context, prior_results)

    assert result.status == "completed"
    assert result.metadata["analysis_mode"] == "local"
    assert "credential reuse" in result.metadata["summary"].lower()
    assert result.metadata["recommended_actions"]
    assert any(
        finding.title == "Compounded account takeover exposure"
        for finding in result.findings
    )
    assert any(
        finding.title == "Phishing sample linked to malicious infrastructure"
        for finding in result.findings
    )


def test_ai_security_analysis_handles_empty_findings(default_config, make_context):
    context = make_context(config=default_config)

    result = AiSecurityAnalysisScanner().timed_run(context, [])

    assert result.status == "completed"
    assert result.metadata["findings_reviewed"] == 0
    assert result.metadata["recommended_actions"]
    assert result.findings[0].title == "AI security summary"
