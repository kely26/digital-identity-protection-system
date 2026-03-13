"""Configurable digital identity risk scoring engine."""

from __future__ import annotations

from collections import Counter
from heapq import nsmallest

from dips.core.config import AppConfig
from dips.core.models import ModuleResult, RiskSummary
from dips.core.risk_engine.scoring_rules import category_for_finding
from dips.core.risk_engine.severity_model import label_for_score


def summarize_risk(results: list[ModuleResult], config: AppConfig) -> RiskSummary:
    weights = config.scoring.weights
    multipliers = config.scoring.module_multipliers
    category_weights = config.risk_engine.category_weights

    severity_counts: Counter[str] = Counter()
    category_scores: Counter[str] = Counter()
    module_scores: dict[str, int] = {}
    recommendation_weights: dict[str, int] = {}
    finding_weights: dict[str, int] = {}
    total_score = 0

    for result in results:
        multiplier = float(multipliers.get(result.module, 1.0))
        module_score = 0
        for finding in result.findings:
            severity_counts[finding.severity] += 1
            category = category_for_finding(result.module, finding)
            category_weight = (
                float(category_weights.get(category, 1.0)) if config.risk_engine.enabled else 1.0
            )
            base_points = float(weights.get(finding.severity, 0)) * multiplier
            points = int(round(base_points * category_weight))
            category_scores[category] += points
            module_score += points
            total_score += points
            if finding.recommendation:
                recommendation_weights[finding.recommendation] = max(
                    recommendation_weights.get(finding.recommendation, 0),
                    points,
                )
            title_key = f"{result.module}: {finding.title}"
            finding_weights[title_key] = max(finding_weights.get(title_key, 0), points)
        module_scores[result.module] = min(module_score, 100)

    overall_score = min(total_score, 100)
    label = label_for_score(overall_score, config.risk_engine.thresholds)
    top_recommendations = [
        item[0]
        for item in nsmallest(
            config.risk_engine.max_recommendations,
            recommendation_weights.items(),
            key=lambda entry: (-entry[1], entry[0]),
        )
    ]
    contributing_findings = [
        item[0]
        for item in nsmallest(
            config.risk_engine.max_finding_titles,
            finding_weights.items(),
            key=lambda entry: (-entry[1], entry[0]),
        )
    ]

    return RiskSummary(
        overall_score=overall_score,
        overall_label=label,
        severity_counts=dict(severity_counts),
        module_scores=module_scores,
        top_recommendations=top_recommendations,
        category_scores=dict(category_scores),
        contributing_findings=contributing_findings,
        risk_model="digital_identity_weighted_sum",
    )
