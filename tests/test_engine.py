from __future__ import annotations

from copy import deepcopy

from dips.core.config import load_config
from dips.core.engine import diff_reports, render_terminal_summary, write_reports
from dips.core.models import Finding, ModuleResult, RiskSummary, ScanReport


def _report_with_ids(*ids: str) -> ScanReport:
    return ScanReport(
        scan_id="scan-id",
        started_at="2026-03-12T00:00:00+00:00",
        finished_at="2026-03-12T00:00:01+00:00",
        duration_ms=1000,
        platform_name="linux",
        hostname="host",
        username="alice",
        user_profile="/home/alice",
        target_paths=["/home/alice"],
        notes=[],
        modules=[
            ModuleResult(
                module="identity_exposure",
                description="identity",
                status="completed",
                findings=[
                    Finding(
                        id=item,
                        module="identity_exposure",
                        severity="medium",
                        confidence="high",
                        title=item,
                        summary=item,
                        evidence={},
                        location=item,
                        recommendation="Fix",
                        tags=[],
                    )
                    for item in ids
                ],
            )
        ],
        summary=RiskSummary(
            overall_score=20,
            overall_label="low",
            severity_counts={"medium": len(ids)},
            module_scores={"identity_exposure": 20},
            top_recommendations=["Fix"],
        ),
        config={},
    )


def test_diff_reports_tracks_new_and_resolved_findings():
    previous = _report_with_ids("a", "b")
    current = _report_with_ids("b", "c", "d")

    diff = diff_reports(previous, current)

    assert diff == {"new": 2, "resolved": 1}


def test_render_terminal_summary_includes_notes_and_warnings():
    report = _report_with_ids("a")
    report.notes = ["Context note"]
    report.modules[0].warnings = ["Module warning"]

    summary = render_terminal_summary(report, {})

    assert "Warnings:" in summary
    assert "- Context note" in summary
    assert "- Module warning" in summary


def test_render_terminal_summary_redacts_locations_and_recommendations():
    report = _report_with_ids("finding")
    report.modules[0].findings[0].location = "/home/alice/Documents/secrets.txt"
    report.modules[0].findings[0].title = "Token for sam@example.com"
    report.summary.top_recommendations = ["Review /home/alice/Documents/secrets.txt for sam@example.com"]

    summary = render_terminal_summary(report, {})

    assert "~/Documents/secrets.txt" in summary
    assert "/home/alice/Documents/secrets.txt" not in summary
    assert "sa***@example.com" in summary


def test_write_reports_renders_payload_once_for_multiple_formats(tmp_path, monkeypatch):
    report = _report_with_ids("finding")
    config = deepcopy(load_config())
    config.reporting.output_dir = str(tmp_path)
    config.reporting.formats = ["json", "html"]

    import dips.core.engine as engine_module

    real_render_json_payload = engine_module.render_json_payload
    render_calls = 0

    def _counting_render_json_payload(*args, **kwargs):
        nonlocal render_calls
        render_calls += 1
        return real_render_json_payload(*args, **kwargs)

    monkeypatch.setattr(engine_module, "render_json_payload", _counting_render_json_payload)

    outputs = write_reports(report, config)

    assert render_calls == 1
    assert outputs["json"].exists()
    assert outputs["html"].exists()
