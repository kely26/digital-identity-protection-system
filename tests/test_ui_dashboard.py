from __future__ import annotations

import os

import pytest

from dips import __version__
from dips.ui_dashboard.main_dashboard import build_parser, launch_dashboard


def test_dashboard_parser_accepts_breach_inputs():
    parser = build_parser()
    args = parser.parse_args(
        [
            "--identifier",
            "security.user@example.com",
            "--breach-dataset",
            "tests/fixtures/breach/offline_dataset.json",
            "--threat-feed",
            "tests/fixtures/threat/malicious_feed.json",
            "--online-threat-intel",
            "--page",
            "overview",
        ]
    )

    assert args.identifiers == ["security.user@example.com"]
    assert args.breach_datasets == ["tests/fixtures/breach/offline_dataset.json"]
    assert args.threat_feeds == ["tests/fixtures/threat/malicious_feed.json"]
    assert args.online_threat_intel is True
    assert args.page == "overview"


def test_dashboard_parser_accepts_demo_mode():
    parser = build_parser()
    args = parser.parse_args(["--demo", "--output-dir", "reports/demo", "--page", "overview"])

    assert args.demo is True
    assert args.output_dir == "reports/demo"
    assert args.page == "overview"


def test_dashboard_version_flag_prints_package_version(capsys):
    parser = build_parser()

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])

    captured = capsys.readouterr()

    assert exc.value.code == 0
    assert captured.out.strip() == f"dips-dashboard {__version__}"


def test_dashboard_launch_rejects_broken_report(tmp_path, capsys):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    broken_report = tmp_path / "broken.json"
    broken_report.write_text("{bad json", encoding="utf-8")

    exit_code = launch_dashboard(["--load-report", str(broken_report)])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert "error: Report file is not valid JSON" in captured.err


def test_dashboard_launch_rejects_missing_report(tmp_path, capsys):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    missing_report = tmp_path / "missing.json"

    exit_code = launch_dashboard(["--load-report", str(missing_report)])
    captured = capsys.readouterr()

    assert exit_code == 3
    assert "error: Report file not found" in captured.err


def test_dashboard_launch_accepts_sparse_report(tmp_path):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sparse_report = tmp_path / "sparse.json"
    sparse_report.write_text(
        '{"scan_id":"sparse","summary":null,"modules":null,"timeline":null}',
        encoding="utf-8",
    )
    screenshot = tmp_path / "sparse.png"

    exit_code = launch_dashboard(
        ["--load-report", str(sparse_report), "--page", "overview", "--screenshot", str(screenshot)]
    )

    assert exit_code == 0
    assert screenshot.exists()


def test_dashboard_launch_demo_mode_writes_reports_and_screenshot(tmp_path):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    output_dir = tmp_path / "demo-reports"
    screenshot = tmp_path / "demo.png"

    exit_code = launch_dashboard(
        ["--demo", "--output-dir", str(output_dir), "--page", "overview", "--screenshot", str(screenshot)]
    )

    assert exit_code == 0
    assert screenshot.exists()
    assert list(output_dir.glob("*.json"))
