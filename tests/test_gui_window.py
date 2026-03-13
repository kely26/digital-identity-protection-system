from __future__ import annotations

import os
import sys
import time
from copy import deepcopy

import pytest

if sys.platform.startswith("linux"):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from dips.core.engine import ScanArtifacts


def _app():
    QtWidgets = pytest.importorskip("PySide6.QtWidgets")
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _process_until(app, predicate, *, timeout_ms: int = 2000) -> bool:
    deadline = time.monotonic() + (timeout_ms / 1000)
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    app.processEvents()
    return predicate()


def _sample_payload():
    from dips.gui.state import build_payload
    from test_gui_state import _sample_report

    return build_payload(_sample_report(), redact=True)


def _large_payload():
    payload = deepcopy(_sample_payload())
    for module in payload["modules"]:
        findings = []
        for finding in list(module.get("findings", [])):
            findings.append(finding)
            for index in range(1, 31):
                clone = dict(finding)
                clone["id"] = f"{finding['id']}-{index}"
                clone["title"] = f"{finding['title']} #{index}"
                findings.append(clone)
        module["findings"] = findings
    base_events = list(payload["timeline"]["events"])
    expanded_events = []
    for event in base_events:
        expanded_events.append(event)
        for index in range(1, 26):
            clone = dict(event)
            clone["id"] = f"{event['id']}-{index}"
            clone["title"] = f"{event['title']} #{index}"
            expanded_events.append(clone)
    payload["timeline"]["events"] = expanded_events
    payload["timeline"]["total_events"] = len(expanded_events)
    return payload


def test_dashboard_window_initializes(default_config):
    from dips.gui.state import empty_payload
    from dips.gui.window import DashboardWindow

    app = _app()
    window = DashboardWindow(default_config, initial_payload=empty_payload(), initial_outputs={})
    window.show()
    window.set_page("reports")
    app.processEvents()

    assert window.windowTitle() == "Digital Identity Protection System"
    assert window.page_title.text() == "Reports"
    assert not window.reports_page.open_json_button.isEnabled()
    assert not window.reports_page.open_html_button.isEnabled()
    window.close()


def test_dashboard_window_navigation_and_module_data(default_config):
    from dips.gui.window import DashboardWindow

    app = _app()
    payload = _sample_payload()
    outputs = {"json": "/tmp/report.json", "html": "/tmp/report.html"}
    window = DashboardWindow(default_config, initial_payload=payload, initial_outputs=outputs)
    window.show()
    app.processEvents()

    assert window.sidebar_metric_value.text() == "32"
    assert window.overview_page.gauge._score == 32
    assert window.module_pages["credential_hygiene"].findings_table.rowCount() == 2
    assert window.module_pages["threat_intelligence"].findings_table.rowCount() == 1

    window.open_reports_button.click()
    app.processEvents()
    assert window.page_title.text() == "Reports"

    window.nav_buttons["credential_hygiene"].click()
    app.processEvents()
    assert window.page_title.text() == "Credential Security"
    assert window.module_pages["credential_hygiene"].status_badge.text() == "COMPLETED"

    window.nav_buttons["overview"].click()
    app.processEvents()
    assert window.page_title.text() == "Overview"
    window.close()


def test_dashboard_window_scan_button_updates_payload(default_config, tmp_path, monkeypatch):
    from dips.gui.window import DashboardWindow
    from test_gui_state import _sample_report

    app = _app()
    json_path = tmp_path / "scan.json"
    html_path = tmp_path / "scan.html"
    json_path.write_text("{}", encoding="utf-8")
    html_path.write_text("<html></html>", encoding="utf-8")

    def _fake_run_scan(config, logger, *, hooks=None):
        del config, logger, hooks
        return ScanArtifacts(report=_sample_report(), outputs={"json": json_path, "html": html_path})

    monkeypatch.setattr("dips.gui.window.run_scan", _fake_run_scan)
    window = DashboardWindow(default_config)
    window.show()
    app.processEvents()

    window.scan_button.click()
    assert _process_until(app, lambda: window.payload.get("scan_id") == "gui-report-001")
    if window.scan_thread is not None:
        window.scan_thread.wait(1000)

    assert window.sidebar_metric_value.text() == "32"
    assert window.reports_page.open_json_button.isEnabled()
    assert window.reports_page.open_html_button.isEnabled()
    assert "gui-report-001" in window.status_badge.text()
    window.close()


def test_dashboard_window_refresh_handles_invalid_config(default_config, monkeypatch):
    from dips.gui.window import DashboardWindow

    app = _app()
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "dips.gui.window.QMessageBox.critical",
        lambda *args: calls.append((args[1], args[2])),
    )
    window = DashboardWindow(default_config)
    window.show()
    app.processEvents()
    for checkbox in window.settings_page.module_checkboxes.values():
        checkbox.setChecked(False)

    window.refresh_latest_report()
    app.processEvents()

    assert calls
    assert calls[0][0] == "Invalid configuration"
    window.close()


def test_dashboard_window_open_output_handles_missing_file(default_config, tmp_path, monkeypatch):
    from dips.gui.window import DashboardWindow

    app = _app()
    warnings: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "dips.gui.window.QMessageBox.warning",
        lambda *args: warnings.append((args[1], args[2])),
    )
    open_calls: list[str] = []
    monkeypatch.setattr(
        "dips.gui.window.QDesktopServices.openUrl",
        lambda url: open_calls.append(url.toString()) or True,
    )

    window = DashboardWindow(default_config)
    window.show()
    app.processEvents()
    window.open_output(str(tmp_path / "missing-report.json"))
    app.processEvents()

    assert warnings
    assert warnings[0][0] == "Report unavailable"
    assert not open_calls
    window.close()


def test_dashboard_window_renders_large_dataset_without_crashing(default_config):
    from dips.gui.window import DashboardWindow

    app = _app()
    window = DashboardWindow(default_config, initial_payload=_large_payload(), initial_outputs={})
    window.show()
    app.processEvents()

    assert not window.grab().isNull()
    assert not window.overview_page.history_chart.grab().isNull()
    assert not window.overview_page.heatmap_chart.grab().isNull()
    assert not window.overview_page.identity_map.grab().isNull()
    assert window.overview_page.priority_alerts.table.rowCount() > 0
    window.close()
