from __future__ import annotations

import json

from dips.demo_mode import build_demo_reports, write_demo_reports


def test_build_demo_reports_produces_rich_scenarios():
    reports = build_demo_reports()

    assert len(reports) == 3
    assert [report.scan_id for report in reports] == [
        "demo-baseline-001",
        "demo-escalation-002",
        "demo-incident-003",
    ]
    assert reports[-1].summary.overall_label in {"high", "critical"}
    assert reports[-1].timeline.events
    assert reports[-1].timeline.patterns
    assert any(module.findings for module in reports[-1].modules if module.module != "ai_security_analysis")


def test_write_demo_reports_writes_json_and_html(tmp_path):
    artifacts = write_demo_reports(tmp_path)

    assert artifacts.latest_report.scan_id == "demo-incident-003"
    latest_outputs = artifacts.latest_outputs
    assert latest_outputs["json"].exists()
    assert latest_outputs["html"].exists()

    payload = json.loads(latest_outputs["json"].read_text(encoding="utf-8"))
    assert payload["scan_id"] == "demo-incident-003"
    assert payload["summary"]["overall_score"] >= 60
    assert payload["timeline"]["events"]
    assert payload["modules"]
