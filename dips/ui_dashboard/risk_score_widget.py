"""Risk-score widgets exposed as a stable dashboard API."""

from __future__ import annotations

from dips.gui.widgets import RiskGauge


class RiskScoreWidget(RiskGauge):
    """Named wrapper around the core dashboard gauge."""


__all__ = ["RiskScoreWidget"]
