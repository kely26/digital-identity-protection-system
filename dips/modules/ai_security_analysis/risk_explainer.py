"""Plain-language risk explanations and compound-pattern detection."""

from __future__ import annotations

from dips.modules.ai_security_analysis.finding_summarizer import RankedFinding, extract_recommendations
from dips.utils.text import unique_preserve_order


def explain_risk(findings: list[RankedFinding]) -> str:
    if not findings:
        return "No compound identity-risk patterns were detected across the enabled modules in this scan."

    sentences = unique_preserve_order(
        sentence
        for sentence in [
            _breach_reuse_sentence(findings),
            _phishing_threat_sentence(findings),
            _secret_exposure_sentence(findings),
            _browser_sentence(findings),
            _generic_sentence(findings),
        ]
        if sentence
    )
    return " ".join(sentences[:3])


def detect_suspicious_patterns(findings: list[RankedFinding]) -> list[dict[str, object]]:
    patterns: list[dict[str, object]] = []

    if _has_credential_reuse(findings) and _has_module(findings, "breach_intelligence"):
        patterns.append(
            {
                "title": "Compounded account takeover exposure",
                "severity": "high",
                "summary": (
                    "Credential reuse appears alongside breach exposure, which increases the chance that "
                    "known credentials can be replayed against other accounts."
                ),
                "recommendation": "Rotate reused passwords immediately and enable MFA on exposed accounts.",
                "tags": ["ai-analysis", "compound-risk", "credential", "breach"],
                "related_findings": _related_titles(findings, {"credential_hygiene", "breach_intelligence"}),
            }
        )

    if _has_module(findings, "email_phishing") and _has_malicious_intel(findings):
        patterns.append(
            {
                "title": "Phishing sample linked to malicious infrastructure",
                "severity": "critical",
                "summary": (
                    "The phishing analyzer and threat intelligence layers both surfaced the same campaign, "
                    "which suggests the message contains infrastructure already associated with malicious activity."
                ),
                "recommendation": "Block the message, domain, and URLs, then notify affected users not to interact.",
                "tags": ["ai-analysis", "compound-risk", "phishing", "threat-intel"],
                "related_findings": _related_titles(findings, {"email_phishing", "threat_intelligence"}),
            }
        )

    if _has_secret_exposure(findings):
        patterns.append(
            {
                "title": "Local secret exposure may enable session abuse",
                "severity": "high",
                "summary": (
                    "Tokens, private keys, or other sensitive artifacts appear to be exposed locally. "
                    "If those secrets are still active, they can enable unauthorized access or persistence."
                ),
                "recommendation": "Rotate exposed tokens or keys and remove plaintext copies from local storage.",
                "tags": ["ai-analysis", "token", "secret-exposure"],
                "related_findings": _related_titles(findings, {"identity_exposure", "privacy_risk"}),
            }
        )

    if _has_module(findings, "browser_audit") and (
        _has_module(findings, "email_phishing") or _has_malicious_intel(findings)
    ):
        patterns.append(
            {
                "title": "Browser posture increases phishing impact",
                "severity": "medium",
                "summary": (
                    "Browser protection gaps appear in the same scan as phishing or malicious-indicator findings, "
                    "which can reduce the host's ability to block deceptive content."
                ),
                "recommendation": "Re-enable browser safe-browsing, leak detection, and extension controls.",
                "tags": ["ai-analysis", "browser", "phishing"],
                "related_findings": _related_titles(findings, {"browser_audit", "email_phishing", "threat_intelligence"}),
            }
        )

    return patterns


def synthesize_recommendations(
    findings: list[RankedFinding],
    patterns: list[dict[str, object]],
    *,
    max_recommendations: int,
) -> list[str]:
    base = extract_recommendations(findings, max_recommendations=max_recommendations * 2)
    pattern_actions = [
        str(item.get("recommendation", ""))
        for item in patterns
        if str(item.get("recommendation", "")).strip()
    ]
    heuristic_actions: list[str] = []

    if _has_module(findings, "breach_intelligence"):
        heuristic_actions.append("Enable MFA for exposed identities and review recent account sign-in activity.")
    if _has_credential_reuse(findings):
        heuristic_actions.append("Replace reused passwords with unique manager-generated credentials.")
    if _has_secret_exposure(findings):
        heuristic_actions.append("Revoke active tokens or keys that may have been written to local files.")
    if _has_module(findings, "email_phishing") or _has_malicious_intel(findings):
        heuristic_actions.append("Block suspicious URLs and domains before users can revisit them.")

    combined = unique_preserve_order([*pattern_actions, *base, *heuristic_actions])
    if not combined:
        combined = [
            "Keep periodic scans enabled and review changes after account, browser, or device updates."
        ]
    return combined[:max_recommendations]


def _has_module(findings: list[RankedFinding], module_name: str) -> bool:
    return any(item.module == module_name for item in findings)


def _has_credential_reuse(findings: list[RankedFinding]) -> bool:
    return any(
        item.module == "credential_hygiene"
        and ("reuse" in item.finding.title.lower() or "reuse" in {tag.lower() for tag in item.finding.tags})
        for item in findings
    )


def _has_malicious_intel(findings: list[RankedFinding]) -> bool:
    return any(
        item.module == "threat_intelligence"
        and "malicious" in {tag.lower() for tag in item.finding.tags}
        for item in findings
    )


def _has_secret_exposure(findings: list[RankedFinding]) -> bool:
    for item in findings:
        if item.module not in {"identity_exposure", "privacy_risk"}:
            continue
        tags = {tag.lower() for tag in item.finding.tags}
        title = item.finding.title.lower()
        if {"token", "private-key"} & tags or "token" in title or "private key" in title:
            return True
    return False


def _related_titles(findings: list[RankedFinding], modules: set[str]) -> list[str]:
    return [item.finding.title for item in findings if item.module in modules][:6]


def _breach_reuse_sentence(findings: list[RankedFinding]) -> str:
    if _has_credential_reuse(findings) and _has_module(findings, "breach_intelligence"):
        return (
            "Credential reuse combined with breach exposure increases the likelihood of account takeover "
            "because attackers can replay known secrets against other services."
        )
    return ""


def _phishing_threat_sentence(findings: list[RankedFinding]) -> str:
    if _has_module(findings, "email_phishing") and _has_malicious_intel(findings):
        return (
            "The phishing results are reinforced by threat intelligence matches, which means the suspicious "
            "message likely references infrastructure already associated with malicious activity."
        )
    return ""


def _secret_exposure_sentence(findings: list[RankedFinding]) -> str:
    if _has_secret_exposure(findings):
        return (
            "Exposed tokens, private keys, or plaintext secrets can give attackers a direct path to persistence, "
            "session theft, or API abuse if they remain active."
        )
    return ""


def _browser_sentence(findings: list[RankedFinding]) -> str:
    if _has_module(findings, "browser_audit"):
        return (
            "Browser hardening gaps weaken first-line defenses against malicious links, risky extensions, "
            "and credential-leak warnings."
        )
    return ""


def _generic_sentence(findings: list[RankedFinding]) -> str:
    top = findings[0]
    return (
        f"The highest-priority issue in this scan is {top.finding.title.lower()} from {top.module_title.lower()}, "
        "so remediation should start there."
    )
