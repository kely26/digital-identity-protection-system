"""Entrypoint for the DIPS PySide6 desktop dashboard."""

from __future__ import annotations

import argparse
import sys

from dips import __version__
from dips.core.config import load_config
from dips.core.exceptions import DipsError
from dips.demo_mode import DEFAULT_DEMO_OUTPUT_DIR, write_demo_reports
from dips.gui.state import load_latest_payload, load_report_payload


def _lazy_qt():
    try:
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:  # pragma: no cover - exercised manually
        raise DipsError(
            "PySide6 is not installed. Install the desktop extras with 'pip install -e .[gui]'."
        ) from exc
    return QApplication, QFont


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dips-dashboard",
        description="Digital Identity Protection System desktop dashboard",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    parser.add_argument("--format", action="append", dest="formats", default=[], choices=("json", "html"))
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for GUI-triggered scans.")
    parser.add_argument("--log-file", help="Optional JSON log file for desktop-triggered scans.")
    parser.add_argument("--load-report", help="Load an existing JSON report into the dashboard.")
    parser.add_argument("--demo", action="store_true", help="Load synthetic demo data instead of a real scan report.")
    parser.add_argument("--screenshot", help="Capture a dashboard screenshot to the given PNG path.")
    parser.add_argument("--page", default="overview", help="Initial page to display.")
    parser.add_argument("--auto-scan", action="store_true", help="Start a scan as soon as the dashboard opens.")
    return parser


def _cli_overrides(args: argparse.Namespace) -> dict:
    overrides: dict = {}
    if args.paths:
        overrides.setdefault("scan", {})["paths"] = args.paths
    if args.email_files:
        overrides.setdefault("email", {})["inputs"] = args.email_files
    if args.password_file:
        overrides.setdefault("credential", {})["password_file"] = args.password_file
    if args.passwords:
        overrides.setdefault("credential", {})["passwords"] = args.passwords
    if args.identifiers:
        overrides.setdefault("breach_intelligence", {})["identifiers"] = args.identifiers
    if args.breach_datasets:
        overrides.setdefault("breach_intelligence", {})["offline_datasets"] = args.breach_datasets
    if args.threat_feeds:
        overrides.setdefault("threat_intelligence", {})["feed_paths"] = args.threat_feeds
    if args.online_threat_intel:
        overrides.setdefault("threat_intelligence", {})["allow_online"] = True
    if args.output_dir:
        overrides.setdefault("reporting", {})["output_dir"] = args.output_dir
    if args.formats:
        overrides.setdefault("reporting", {})["formats"] = args.formats
    return overrides


def launch_dashboard(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, _cli_overrides(args))
        QApplication, QFont = _lazy_qt()
        from dips.gui.theme import dashboard_stylesheet
        from dips.gui.window import DashboardLaunchOptions, DashboardWindow

        payload = None
        outputs: dict[str, str] = {}
        if args.demo:
            if args.load_report:
                raise DipsError("Demo mode cannot be combined with --load-report.")
            if args.auto_scan:
                raise DipsError("Demo mode cannot be combined with --auto-scan.")
            demo_output_dir = args.output_dir or str(DEFAULT_DEMO_OUTPUT_DIR)
            demo_artifacts = write_demo_reports(demo_output_dir)
            latest_outputs = demo_artifacts.latest_outputs
            payload = load_report_payload(latest_outputs["json"])
            outputs = {name: str(path) for name, path in latest_outputs.items()}
        elif args.load_report:
            payload = load_report_payload(args.load_report)
            outputs["json"] = args.load_report
            html_candidate = args.load_report.rsplit(".", 1)[0] + ".html"
            if html_candidate != args.load_report:
                outputs["html"] = html_candidate
        elif not args.auto_scan:
            payload, outputs = load_latest_payload(config.reporting.output_dir)
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv if argv is None else ["dips-dashboard", *argv])
        font = QFont()
        font.setFamilies(["Inter", "Segoe UI Variable", "Segoe UI", "Noto Sans", "Ubuntu Sans", "Sans Serif"])
        font.setPointSizeF(10.5)
        app.setFont(font)
        app.setStyleSheet(dashboard_stylesheet())
        window = DashboardWindow(
            config,
            initial_payload=payload,
            initial_outputs=outputs,
            options=DashboardLaunchOptions(
                screenshot_path=args.screenshot or "",
                start_page=args.page,
                auto_scan=args.auto_scan,
                debug=args.debug,
                log_file=args.log_file or "",
            ),
        )
        window.show()
        return app.exec()
    except DipsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001
        detail = str(exc).strip()
        message = "Dashboard failed to launch"
        if detail:
            message = f"{message}: {detail}"
        print(f"error: {message}", file=sys.stderr)
        return 1


def main() -> None:
    raise SystemExit(launch_dashboard())
