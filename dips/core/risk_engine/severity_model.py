"""Severity and threshold helpers for digital identity scoring."""

from __future__ import annotations


RISK_LEVELS = ("minimal", "low", "moderate", "high", "critical")


def label_for_score(score: int, thresholds: dict[str, int]) -> str:
    normalized = max(0, min(100, int(score)))
    label = "minimal"
    for candidate in RISK_LEVELS:
        if normalized >= int(thresholds.get(candidate, 0)):
            label = candidate
    return label
