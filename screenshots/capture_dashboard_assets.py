#!/usr/bin/env python3
"""Generate the curated DIPS screenshot set from safe demo data."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _process_events(app, *, delay: float = 0.08) -> None:
    app.processEvents()
    time.sleep(delay)
    app.processEvents()


def _save(widget, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    widget.grab().save(str(target))


def main() -> int:
    from dips.core.config import load_config
    from dips.gui.main import _lazy_qt
    from dips.gui.state import load_report_payload
    from dips.gui.theme import dashboard_stylesheet
    from dips.gui.window import DashboardLaunchOptions, DashboardWindow

    output_dir = Path(__file__).resolve().parent
    example_dir = REPO_ROOT / "examples" / "demo-reports"
    payload = load_report_payload(example_dir / "demo-incident-003.json")
    outputs = {
        "json": "examples/demo-reports/demo-incident-003.json",
        "html": "examples/demo-reports/demo-incident-003.html",
    }

    QApplication, QFont = _lazy_qt()
    app = QApplication.instance()
    if app is None:
        app = QApplication(["dips-screenshot-capture"])

    font = QFont()
    font.setFamilies(["Inter", "Segoe UI Variable", "Segoe UI", "Noto Sans", "Ubuntu Sans", "Sans Serif"])
    font.setPointSizeF(10.5)
    app.setFont(font)
    app.setStyleSheet(dashboard_stylesheet())

    config = load_config(None, {"reporting": {"output_dir": str(example_dir)}})
    window = DashboardWindow(
        config,
        initial_payload=payload,
        initial_outputs=outputs,
        options=DashboardLaunchOptions(start_page="overview"),
    )
    window.resize(1560, 960)
    window.show()
    _process_events(app)

    window.set_page("overview")
    window.overview_page.verticalScrollBar().setValue(0)
    _process_events(app)
    _save(window, output_dir / "dashboard-overview.png")
    _save(window.overview_page.gauge_section, output_dir / "risk-score-panel.png")
    _save(window.overview_page.heatmap_section, output_dir / "severity-distribution.png")

    window.overview_page.verticalScrollBar().setValue(window.overview_page.verticalScrollBar().maximum())
    _process_events(app, delay=0.12)
    _save(window.overview_page.timeline_section, output_dir / "event-timeline.png")

    window.set_page("breach_intelligence")
    _process_events(app)
    _save(window, output_dir / "breach-exposure-alert.png")

    window.set_page("reports")
    _process_events(app)
    _save(window, output_dir / "scan-report-view.png")

    window.close()
    app.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
