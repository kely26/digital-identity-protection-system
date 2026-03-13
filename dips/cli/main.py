"""Command-line interface for DIPS."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from dips import __version__
from dips.core.config import dump_config, load_config
from dips.core.doctor import build_doctor_report, render_doctor_text
from dips.core.exceptions import DipsError, HealthCheckError, PolicyViolationError
from dips.demo_mode import DEFAULT_DEMO_OUTPUT_DIR, write_demo_reports
from dips.core.engine import render_terminal_summary, run_scan, watch_scans
from dips.core.logging import configure_logging
from dips.core.models import SEVERITY_ORDER
from dips.core.policy import evaluate_scan_policy


def _error_text(prefix: str, exc: Exception) -> str:
    detail = str(exc).strip()
    return f"{prefix}: {detail}" if detail else prefix


def _add_scope_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="Path to a JSON config file.")
    parser.add_argument("--path", action="append", dest="paths", default=[], help="Extra scan path.")
    parser.add_argument("--email-file", action="append", dest="email_files", default=[], help="Email file to analyze.")
    parser.add_argument("--password-file", help="Password file for hygiene analysis.")
    parser.add_argument("--password", action="append", dest="passwords", default=[], help="Inline password candidate.")
    parser.add_argument(
        "--identifier",
        action="append",
        dest="identifiers",
        default=[],
        help="Email address or username to check with the breach intelligence module.",
    )
    parser.add_argument(
        "--breach-dataset",
        action="append",
        dest="breach_datasets",
        default=[],
        help="Offline breach dataset JSON file.",
    )
    parser.add_argument(
        "--threat-feed",
        action="append",
        dest="threat_feeds",
        default=[],
        help="Offline threat intelligence feed JSON file.",
    )
    parser.add_argument(
        "--online-threat-intel",
        action="store_true",
        help="Allow online threat intelligence provider lookups.",
    )
    parser.add_argument("--output-dir", help="Report output directory.")
    parser.add_argument(
        "--format",
        action="append",
        choices=("json", "html"),
        dest="formats",
        default=[],
        help="Report format to write.",
    )


def _add_logging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default="text",
        help="Console log format.",
    )
    parser.add_argument("--log-file", help="Optional path to a JSON log file.")


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on-severity",
        choices=SEVERITY_ORDER,
        help="Return a non-zero exit code when a finding meets or exceeds this severity.",
    )
    parser.add_argument(
        "--fail-on-score",
        type=int,
        help="Return a non-zero exit code when the overall risk score meets or exceeds this value.",
    )


def _build_cli_overrides(args: argparse.Namespace) -> dict:
    overrides: dict = {}
    if getattr(args, "paths", None):
        overrides.setdefault("scan", {})["paths"] = args.paths
    if getattr(args, "email_files", None):
        overrides.setdefault("email", {})["inputs"] = args.email_files
    if getattr(args, "password_file", None):
        overrides.setdefault("credential", {})["password_file"] = args.password_file
    if getattr(args, "passwords", None):
        overrides.setdefault("credential", {})["passwords"] = args.passwords
    if getattr(args, "identifiers", None):
        overrides.setdefault("breach_intelligence", {})["identifiers"] = args.identifiers
    if getattr(args, "breach_datasets", None):
        overrides.setdefault("breach_intelligence", {})["offline_datasets"] = args.breach_datasets
    if getattr(args, "threat_feeds", None):
        overrides.setdefault("threat_intelligence", {})["feed_paths"] = args.threat_feeds
    if getattr(args, "online_threat_intel", False):
        overrides.setdefault("threat_intelligence", {})["allow_online"] = True
    if getattr(args, "output_dir", None):
        overrides.setdefault("reporting", {})["output_dir"] = args.output_dir
    if getattr(args, "formats", None):
        overrides.setdefault("reporting", {})["formats"] = args.formats
    if getattr(args, "interval", None) is not None:
        overrides.setdefault("watch", {})["interval_seconds"] = args.interval
    return overrides


def _add_dashboard_args(parser: argparse.ArgumentParser) -> None:
    _add_scope_args(parser)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for background scans.")
    parser.add_argument("--log-file", help="Optional path to a JSON log file for GUI-triggered scans.")
    parser.add_argument("--load-report", help="Load an existing JSON report into the dashboard.")
    parser.add_argument("--demo", action="store_true", help="Load synthetic demo data instead of a real scan report.")
    parser.add_argument("--screenshot", help="Capture the window to the given PNG path.")
    parser.add_argument("--page", default="overview", help="Initial dashboard page.")
    parser.add_argument("--auto-scan", action="store_true", help="Start a scan immediately.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dips", description="Digital Identity Protection System")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a full identity protection scan.")
    _add_scope_args(scan_parser)
    _add_logging_args(scan_parser)
    _add_policy_args(scan_parser)

    watch_parser = subparsers.add_parser("watch", help="Run repeated scans in the foreground.")
    _add_scope_args(watch_parser)
    _add_logging_args(watch_parser)
    watch_parser.add_argument("--interval", type=int, default=None, help="Watch interval in seconds.")
    watch_parser.add_argument("--cycles", type=int, default=None, help="Optional number of watch cycles.")

    config_parser = subparsers.add_parser("show-config", help="Print the merged effective config.")
    _add_scope_args(config_parser)
    _add_logging_args(config_parser)

    doctor_parser = subparsers.add_parser("doctor", help="Run runtime diagnostics and environment checks.")
    _add_scope_args(doctor_parser)
    _add_logging_args(doctor_parser)
    doctor_parser.add_argument(
        "--doctor-format",
        choices=("text", "json"),
        default="text",
        dest="doctor_format",
        help="Doctor output format.",
    )

    gui_parser = subparsers.add_parser("gui", help="Launch the PySide6 desktop dashboard.")
    _add_dashboard_args(gui_parser)

    dashboard_parser = subparsers.add_parser("dashboard", help="Launch the PySide6 desktop dashboard.")
    _add_dashboard_args(dashboard_parser)

    demo_parser = subparsers.add_parser("demo", help="Generate safe synthetic demo reports for screenshots and walkthroughs.")
    demo_parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_DEMO_OUTPUT_DIR),
        help="Directory where demo JSON and HTML reports should be written.",
    )
    demo_parser.add_argument("--dashboard", action="store_true", help="Launch the dashboard with the newest demo report.")
    demo_parser.add_argument("--page", default="overview", help="Initial dashboard page when --dashboard is used.")
    demo_parser.add_argument("--screenshot", help="Capture a dashboard screenshot when --dashboard is used.")
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = logging.getLogger("dips")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    try:
        logger = configure_logging(
            debug=getattr(args, "debug", False),
            log_format=getattr(args, "log_format", "text"),
            log_file=getattr(args, "log_file", None),
        )
        config = load_config(getattr(args, "config", None), _build_cli_overrides(args))
        if hasattr(args, "fail_on_score") and args.fail_on_score is not None:
            if args.fail_on_score < 0 or args.fail_on_score > 100:
                raise DipsError("--fail-on-score must be between 0 and 100.")
    except DipsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code

    if args.command == "show-config":
        print(dump_config(config))
        return 0

    if args.command == "doctor":
        report = build_doctor_report(config)
        if args.doctor_format == "json":
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            print(render_doctor_text(report))
        return 0 if report.overall_status != "fail" else HealthCheckError.exit_code

    if args.command == "demo":
        artifacts = write_demo_reports(args.output_dir)
        latest_outputs = artifacts.latest_outputs
        print("Generated demo reports:")
        for report in artifacts.reports:
            outputs = artifacts.outputs_by_scan[report.scan_id]
            print(f"- {report.scan_id}: json={outputs['json']} html={outputs['html']}")
        print("Launch the dashboard with:")
        print(f"- dips dashboard --load-report {latest_outputs['json']}")
        print("- dips dashboard --demo")
        if args.dashboard:
            from dips.ui_dashboard.main_dashboard import launch_dashboard

            dashboard_args = ["--load-report", str(latest_outputs["json"]), "--page", args.page]
            if args.screenshot:
                dashboard_args.extend(["--screenshot", args.screenshot])
            return launch_dashboard(dashboard_args)
        return 0

    try:
        if args.command in {"gui", "dashboard"}:
            from dips.ui_dashboard.main_dashboard import launch_dashboard

            gui_args = []
            if getattr(args, "config", None):
                gui_args.extend(["--config", args.config])
            for path in getattr(args, "paths", []):
                gui_args.extend(["--path", path])
            for email_file in getattr(args, "email_files", []):
                gui_args.extend(["--email-file", email_file])
            if getattr(args, "password_file", None):
                gui_args.extend(["--password-file", args.password_file])
            for password in getattr(args, "passwords", []):
                gui_args.extend(["--password", password])
            for identifier in getattr(args, "identifiers", []):
                gui_args.extend(["--identifier", identifier])
            for dataset in getattr(args, "breach_datasets", []):
                gui_args.extend(["--breach-dataset", dataset])
            for feed in getattr(args, "threat_feeds", []):
                gui_args.extend(["--threat-feed", feed])
            if getattr(args, "online_threat_intel", False):
                gui_args.append("--online-threat-intel")
            if getattr(args, "output_dir", None):
                gui_args.extend(["--output-dir", args.output_dir])
            for report_format in getattr(args, "formats", []):
                gui_args.extend(["--format", report_format])
            if getattr(args, "debug", False):
                gui_args.append("--debug")
            if getattr(args, "log_file", None):
                gui_args.extend(["--log-file", args.log_file])
            if getattr(args, "load_report", None):
                gui_args.extend(["--load-report", args.load_report])
            if getattr(args, "demo", False):
                gui_args.append("--demo")
            if getattr(args, "screenshot", None):
                gui_args.extend(["--screenshot", args.screenshot])
            if getattr(args, "page", None):
                gui_args.extend(["--page", args.page])
            if getattr(args, "auto_scan", False):
                gui_args.append("--auto-scan")
            return launch_dashboard(gui_args)

        if args.command == "scan":
            artifacts = run_scan(config, logger)
            print(render_terminal_summary(artifacts.report, artifacts.outputs))
            violations = evaluate_scan_policy(
                artifacts.report,
                fail_on_severity=getattr(args, "fail_on_severity", None),
                fail_on_score=getattr(args, "fail_on_score", None),
            )
            if violations:
                for violation in violations:
                    print(f"policy: {violation.message}", file=sys.stderr)
                return PolicyViolationError.exit_code
            return 0

        if args.command == "watch":
            return watch_scans(config, logger, cycles=args.cycles)
    except KeyboardInterrupt:
        logger.warning("scan interrupted by user")
        return 130
    except DipsError as exc:
        logger.error(str(exc))
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001
        logger.exception("unexpected CLI failure")
        print(_error_text("error: Unexpected internal error while running the command", exc), file=sys.stderr)
        return 1

    parser.error("Unsupported command")
    return 2


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
