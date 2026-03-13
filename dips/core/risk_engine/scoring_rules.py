"""Rule mapping from scanner findings to digital identity risk categories."""

from __future__ import annotations

from dips.core.models import Finding


DEFAULT_CATEGORY = {
    "identity_exposure": "token_exposure",
    "breach_intelligence": "breach_exposure",
    "credential_hygiene": "password_strength",
    "privacy_risk": "privacy_risk",
    "browser_audit": "browser_risk",
    "email_phishing": "phishing_risk",
    "threat_intelligence": "threat_intelligence",
    "ai_security_analysis": "analysis_advice",
}


def category_for_finding(module_name: str, finding: Finding) -> str:
    title = finding.title.lower()
    tags = {item.lower() for item in finding.tags}

    if module_name == "credential_hygiene":
        if "reuse" in tags or "reuse" in title:
            return "credential_reuse"
        return "password_strength"

    if module_name == "identity_exposure":
        if {"email", "identity", "breach"} & tags:
            return "breach_exposure"
        return "token_exposure"

    if module_name == "privacy_risk":
        if "token" in tags or "private-key" in tags:
            return "token_exposure"
        return "privacy_risk"

    if module_name == "threat_intelligence":
        if "url" in tags or "phishing" in tags:
            return "phishing_risk"
        return "threat_intelligence"

    if module_name == "ai_security_analysis":
        return "analysis_advice"

    return DEFAULT_CATEGORY.get(module_name, "privacy_risk")
