"""Alert-focused dashboard panels."""

from __future__ import annotations

from collections.abc import Iterable

from dips.gui.widgets import SectionFrame
from dips.ui_dashboard.findings_table import FindingsTableWidget


class AlertsPanel(SectionFrame):
    """Reusable section for recent or high-priority findings."""

    def __init__(self, title: str, subtitle: str = "", parent=None) -> None:
        super().__init__(title, subtitle, parent)
        self.table = FindingsTableWidget()
        self.content.addWidget(self.table)

    def set_alerts(self, findings: Iterable[dict]) -> None:
        self.table.set_findings(list(findings))


__all__ = ["AlertsPanel"]
