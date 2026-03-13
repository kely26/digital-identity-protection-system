"""Helpers for summarizing scanner findings in plain language."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from dips.core.models import Finding, ModuleResult, SEVERITY_ORDER
from dips.utils.text import unique_preserve_order

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

MODULE_TITLES = {
    "identity_exposure": "Identity Exposure Monitor",
    "breach_intelligence": "Breach Intelligence",
    "credential_hygiene": "Credential Security",
    "privacy_risk": "Local Privacy Risk Scanner",
    "browser_audit": "Browser Security Audit",
    "email_phishing": "Phishing Analyzer",
    "threat_intelligence": "Threat Intelligence",
}


@dataclass(slots=True)
class RankedFinding:
    module: str
    module_title: str
    finding: Finding


def collect_ranked_findings(
    prior_results: list[ModuleResult],
    *,
    limit: int | None = None,
) -> list[RankedFinding]:
    ranked: list[RankedFinding] = []
    for result in prior_results:
        if result.module == "ai_security_analysis" or result.status != "completed":
            continue
        for finding in result.findings:
            ranked.append(
                RankedFinding(
                    module=result.module,
                    module_title=MODULE_TITLES.get(result.module, result.module.replace("_", " ").title()),
                    finding=finding,
                )
            )
    ranked.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(item.finding.severity, -1),
            item.module_title,
            item.finding.title,
            item.finding.location,
        )
    )
    return ranked if limit is None else ranked[:limit]


def findings_reviewed(prior_results: list[ModuleResult]) -> int:
    return sum(len(result.findings) for result in prior_results if result.module != "ai_security_analysis")


def module_names(findings: list[RankedFinding]) -> list[str]:
    return unique_preserve_order(item.module for item in findings)


def severity_counts(findings: list[RankedFinding]) -> dict[str, int]:
    counts: Counter[str] = Counter(item.finding.severity for item in findings)
    return {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER if counts.get(severity, 0)}


def extract_recommendations(findings: list[RankedFinding], *, max_recommendations: int) -> list[str]:
    return unique_preserve_order(
        item.finding.recommendation for item in findings if item.finding.recommendation
    )[:max_recommendations]


def build_security_summary(findings: list[RankedFinding]) -> str:
    if not findings:
        return (
            "The latest scan did not surface urgent digital identity issues. "
            "Keep routine scans enabled and review your posture after account or device changes."
        )

    themes = unique_preserve_order(_theme_for_finding(item) for item in findings if _theme_for_finding(item))
    if not themes:
        top = findings[0]
        return (
            f"The latest scan highlighted {top.finding.title.lower()} in {top.module_title.lower()}. "
            "Review the detailed findings for the affected identity surface."
        )

    visible = themes[:3]
    extra_count = max(0, len(themes) - len(visible))
    summary = f"The latest scan detected {_join_phrases(visible)}"
    if extra_count:
        summary += f", plus {extra_count} additional risk theme(s)"
    summary += "."
    return summary


def build_finding_digest(findings: list[RankedFinding], *, max_items: int) -> list[str]:
    return [f"{item.module_title}: {item.finding.title}" for item in findings[:max_items]]


def _theme_for_finding(item: RankedFinding) -> str:
    title = item.finding.title.lower()
    tags = {tag.lower() for tag in item.finding.tags}

    if item.module == "breach_intelligence":
        return "exposure in breach intelligence"
    if item.module == "credential_hygiene":
        if "reuse" in tags or "reuse" in title:
            return "credential reuse"
        return "weak password hygiene"
    if item.module == "identity_exposure":
        if {"token", "private-key"} & tags or "token" in title or "private key" in title:
            return "local token or secret exposure"
        return "identity exposure artifacts"
    if item.module == "privacy_risk":
        if {"token", "private-key"} & tags:
            return "plaintext secrets on disk"
        return "local privacy risks"
    if item.module == "browser_audit":
        return "browser hardening gaps"
    if item.module == "email_phishing":
        return "phishing indicators"
    if item.module == "threat_intelligence":
        return "known malicious indicators"
    return ""


def _join_phrases(values: list[str]) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"
