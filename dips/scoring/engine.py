"""Compatibility wrapper for the digital identity risk engine."""

from __future__ import annotations

from dips.core.config import AppConfig
from dips.core.models import ModuleResult, RiskSummary
from dips.core.risk_engine import summarize_risk


def summarize_results(results: list[ModuleResult], config: AppConfig) -> RiskSummary:
    return summarize_risk(results, config)
