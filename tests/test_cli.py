from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from dips import __version__
from dips.cli.main import run_cli


def test_scan_command_generates_reports(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    exposure_dir = tmp_path / "scan-target"
    exposure_dir.mkdir()
    shutil.copy(Path(__file__).parent / "fixtures" / "exposure" / "leaky.env", exposure_dir / "leaky.env")
    output_dir = tmp_path / "reports"
    email_file = Path(__file__).parent / "fixtures" / "email" / "phish.eml"
    password_file = Path(__file__).parent / "fixtures" / "exposure" / "passwords.txt"

    exit_code = run_cli(
        [
            "scan",
            "--path",
            str(exposure_dir),
            "--email-file",
            str(email_file),
            "--password-file",
            str(password_file),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    assert list(output_dir.glob("*.json"))
    assert list(output_dir.glob("*.html"))


def test_scan_command_fail_on_severity_returns_policy_exit_code(tmp_path, monkeypatch, capsys):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    exposure_dir = tmp_path / "scan-target"
    exposure_dir.mkdir()
    shutil.copy(Path(__file__).parent / "fixtures" / "exposure" / "leaky.env", exposure_dir / "leaky.env")
    output_dir = tmp_path / "reports"

    exit_code = run_cli(
        [
            "scan",
            "--path",
            str(exposure_dir),
            "--output-dir",
            str(output_dir),
            "--fail-on-severity",
            "high",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 6
    assert "policy: Detected" in captured.err
    assert list(output_dir.glob("*.json"))


def test_scan_command_fail_on_score_returns_policy_exit_code(tmp_path, monkeypatch, capsys):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    exposure_dir = tmp_path / "scan-target"
    exposure_dir.mkdir()
    shutil.copy(Path(__file__).parent / "fixtures" / "exposure" / "leaky.env", exposure_dir / "leaky.env")
    output_dir = tmp_path / "reports"

    exit_code = run_cli(
        [
            "scan",
            "--path",
            str(exposure_dir),
            "--output-dir",
            str(output_dir),
            "--fail-on-score",
            "50",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 6
    assert "Overall risk score" in captured.err
    assert list(output_dir.glob("*.json"))


def test_scan_command_accepts_windows_style_paths_on_posix(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    docs = profile / "Documents"
    docs.mkdir(parents=True)
    (docs / "leaky.env").write_text("email=alice@example.com\n", encoding="utf-8")
    output_root = tmp_path / "artifacts"
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("REPORTROOT", str(output_root))

    exit_code = run_cli(
        [
            "scan",
            "--path",
            r"%USERPROFILE%\Documents",
            "--output-dir",
            r"%REPORTROOT%\reports",
        ]
    )

    assert exit_code == 0
    assert list((output_root / "reports").glob("*.json"))
    assert list((output_root / "reports").glob("*.html"))


def test_cli_version_flag_prints_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(["--version"])

    captured = capsys.readouterr()

    assert exc.value.code == 0
    assert captured.out.strip() == f"dips {__version__}"


def test_show_config_merges_overrides(tmp_path, capsys):
    config_path = tmp_path / "override.json"
    config_path.write_text(
        json.dumps({"reporting": {"output_dir": "custom-reports"}, "browser": {"max_extension_count": 5}}),
        encoding="utf-8",
    )

    exit_code = run_cli(["show-config", "--config", str(config_path), "--path", "/tmp/example"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert '"output_dir": "custom-reports"' in captured.out
    assert '"max_extension_count": 5' in captured.out
    assert '"/tmp/example"' in captured.out


def test_show_config_accepts_breach_overrides(capsys):
    dataset = Path(__file__).parent / "fixtures" / "breach" / "offline_dataset.json"

    exit_code = run_cli(
        [
            "show-config",
            "--identifier",
            "security.user@example.com",
            "--breach-dataset",
            str(dataset),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert '"identifiers": [' in captured.out
    assert '"security.user@example.com"' in captured.out
    assert str(dataset) in captured.out


def test_show_config_accepts_threat_feed_overrides(capsys):
    feed = Path(__file__).parent / "fixtures" / "threat" / "malicious_feed.json"

    exit_code = run_cli(
        [
            "show-config",
            "--threat-feed",
            str(feed),
            "--online-threat-intel",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert str(feed) in captured.out
    assert '"allow_online": true' in captured.out


def test_doctor_command_reports_runtime_health(tmp_path, capsys):
    output_dir = tmp_path / "reports"

    exit_code = run_cli(["doctor", "--output-dir", str(output_dir)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "DIPS Doctor" in captured.out
    assert "Overall Status" in captured.out
    assert "report_output_dir" in captured.out


def test_doctor_command_supports_json_output(tmp_path, capsys):
    output_dir = tmp_path / "reports"

    exit_code = run_cli(["doctor", "--output-dir", str(output_dir), "--doctor-format", "json"])
    captured = capsys.readouterr()

    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["overall_status"] in {"pass", "warn"}
    assert any(check["name"] == "report_output_dir" for check in payload["checks"])


def test_watch_command_runs_single_cycle(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    exposure_dir = tmp_path / "watch-target"
    exposure_dir.mkdir()
    shutil.copy(Path(__file__).parent / "fixtures" / "exposure" / "leaky.env", exposure_dir / "leaky.env")
    output_dir = tmp_path / "watch-reports"

    exit_code = run_cli(
        [
            "watch",
            "--path",
            str(exposure_dir),
            "--output-dir",
            str(output_dir),
            "--cycles",
            "1",
            "--interval",
            "0",
        ]
    )

    assert exit_code == 0
    assert list(output_dir.glob("*.json"))


def test_scan_command_generates_breach_findings(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    output_dir = tmp_path / "reports"
    dataset = Path(__file__).parent / "fixtures" / "breach" / "offline_dataset.json"

    exit_code = run_cli(
        [
            "scan",
            "--identifier",
            "security.user@example.com",
            "--breach-dataset",
            str(dataset),
            "--output-dir",
            str(output_dir),
        ]
    )

    payload = json.loads(next(output_dir.glob("*.json")).read_text(encoding="utf-8"))
    breach_module = next(item for item in payload["modules"] if item["module"] == "breach_intelligence")

    assert exit_code == 0
    assert breach_module["findings"]
    assert breach_module["findings"][0]["evidence"]["breach_count"] == 3


def test_scan_command_generates_threat_intel_findings(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    output_dir = tmp_path / "reports"
    feed = Path(__file__).parent / "fixtures" / "threat" / "malicious_feed.json"
    email_file = Path(__file__).parent / "fixtures" / "email" / "phish.eml"

    exit_code = run_cli(
        [
            "scan",
            "--threat-feed",
            str(feed),
            "--email-file",
            str(email_file),
            "--output-dir",
            str(output_dir),
        ]
    )

    payload = json.loads(next(output_dir.glob("*.json")).read_text(encoding="utf-8"))
    threat_module = next(item for item in payload["modules"] if item["module"] == "threat_intelligence")

    assert exit_code == 0
    assert threat_module["findings"]
    assert any(finding["evidence"]["reputation"] == "malicious" for finding in threat_module["findings"])


def test_scan_command_generates_ai_analysis(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("HOME", str(profile))
    monkeypatch.setenv("USERPROFILE", str(profile))

    output_dir = tmp_path / "reports"
    dataset = Path(__file__).parent / "fixtures" / "breach" / "offline_dataset.json"
    password_file = Path(__file__).parent / "fixtures" / "exposure" / "passwords.txt"

    exit_code = run_cli(
        [
            "scan",
            "--identifier",
            "security.user@example.com",
            "--breach-dataset",
            str(dataset),
            "--password-file",
            str(password_file),
            "--output-dir",
            str(output_dir),
        ]
    )

    payload = json.loads(next(output_dir.glob("*.json")).read_text(encoding="utf-8"))
    ai_module = next(item for item in payload["modules"] if item["module"] == "ai_security_analysis")

    assert exit_code == 0
    assert ai_module["metadata"]["summary"]
    assert ai_module["metadata"]["recommended_actions"]


def test_cli_handles_invalid_log_path_gracefully(tmp_path, capsys):
    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("not-a-directory", encoding="utf-8")

    exit_code = run_cli(
        [
            "show-config",
            "--log-file",
            str(blocked_parent / "scan.jsonl"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Failed to initialize log file" in captured.err
    assert "Traceback" not in captured.err


def test_demo_command_generates_synthetic_reports(tmp_path, capsys):
    output_dir = tmp_path / "demo-reports"

    exit_code = run_cli(["demo", "--output-dir", str(output_dir)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Generated demo reports:" in captured.out
    assert list(output_dir.glob("*.json"))
    assert list(output_dir.glob("*.html"))


def test_dashboard_command_accepts_demo_mode(tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    output_dir = tmp_path / "demo-reports"
    screenshot = tmp_path / "demo.png"

    exit_code = run_cli(
        [
            "dashboard",
            "--demo",
            "--output-dir",
            str(output_dir),
            "--page",
            "overview",
            "--screenshot",
            str(screenshot),
        ]
    )

    assert exit_code == 0
    assert screenshot.exists()
    assert list(output_dir.glob("*.json"))
