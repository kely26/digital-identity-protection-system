from __future__ import annotations

from dips.core.models import Finding, ModuleResult
from dips.scoring.engine import summarize_results


def test_scoring_summarizes_findings(default_config):
    config = default_config
    config.scoring.module_multipliers["privacy_risk"] = 2.0
    results = [
        ModuleResult(
            module="privacy_risk",
            description="privacy",
            status="completed",
            findings=[
                Finding(
                    id="a1",
                    module="privacy_risk",
                    severity="high",
                    confidence="high",
                    title="A",
                    summary="A",
                    evidence={},
                    location="x",
                    recommendation="Fix A",
                    tags=[],
                )
            ],
        ),
        ModuleResult(
            module="identity_exposure",
            description="identity",
            status="completed",
            findings=[
                Finding(
                    id="b1",
                    module="identity_exposure",
                    severity="medium",
                    confidence="medium",
                    title="B",
                    summary="B",
                    evidence={},
                    location="y",
                    recommendation="Fix B",
                    tags=[],
                )
            ],
        ),
    ]

    summary = summarize_results(results, config)

    assert summary.overall_score == 26
    assert summary.overall_label == "low"
    assert summary.module_scores["privacy_risk"] == 20
    assert "Fix A" in summary.top_recommendations
