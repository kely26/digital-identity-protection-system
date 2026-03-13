"""Main desktop window for the DIPS dashboard."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from dips.core.config import AppConfig
from dips.core.engine import ScanHooks, run_scan
from dips.core.logging import JsonFormatter
from dips.gui.pages import ModulePage, OverviewPage, ReportsPage, SettingsPage
from dips.gui.state import (
    alert_correlation_clusters,
    MODULE_META,
    MODULE_ORDER,
    build_payload,
    empty_payload,
    flatten_findings,
    load_latest_payload,
    overall_protection_score,
    prioritized_alerts,
    threat_intel_summary,
)
from dips.gui.widgets import AnimatedProgressBar, AnimatedStackedWidget, apply_soft_shadow
from dips.utils.paths import path_from_input
from dips.utils.secure_io import set_private_file_permissions


@dataclass(slots=True)
class DashboardLaunchOptions:
    screenshot_path: str = ""
    start_page: str = "overview"
    auto_scan: bool = False
    debug: bool = False
    log_file: str = ""


class SidebarButton(QPushButton):
    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(label, parent)
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(52)


class ScanWorker(QObject):
    progress_changed = Signal(int, str)
    scan_completed = Signal(object, object)
    scan_failed = Signal(str)

    def __init__(self, config: AppConfig, *, log_file: str = "", debug: bool = False) -> None:
        super().__init__()
        self.config = config
        self.log_file = log_file
        self.debug = debug

    def _build_logger(self) -> logging.Logger:
        logger = logging.getLogger("dips.gui.scan")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        logger.handlers.clear()
        if self.log_file:
            log_path = path_from_input(self.log_file)
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                set_private_file_permissions(log_path)
            except OSError as exc:
                raise RuntimeError(f"Failed to initialize dashboard log file {log_path}: {exc}") from exc
            file_handler.setFormatter(JsonFormatter(include_traceback=True))
            logger.addHandler(file_handler)
        else:
            logger.addHandler(logging.NullHandler())
        logger.propagate = False
        return logger

    def run(self) -> None:
        logger = self._build_logger()

        def on_started(context, total: int) -> None:
            del context
            self.progress_changed.emit(2, f"Preparing scan pipeline for {total} module(s)")

        def on_module_started(module_name: str, index: int, total: int) -> None:
            progress = int(((index - 1) / max(1, total)) * 100)
            title = MODULE_META.get(module_name, {}).get("title", module_name)
            self.progress_changed.emit(max(4, progress), f"Running {title}")

        def on_module_finished(result, index: int, total: int) -> None:
            progress = int((index / max(1, total)) * 100)
            title = MODULE_META.get(result.module, {}).get("title", result.module)
            self.progress_changed.emit(progress, f"Completed {title}")

        try:
            artifacts = run_scan(
                self.config,
                logger,
                hooks=ScanHooks(
                    on_scan_started=on_started,
                    on_module_started=on_module_started,
                    on_module_finished=on_module_finished,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            self.scan_failed.emit(str(exc))
            return

        payload = build_payload(artifacts.report, redact=self.config.reporting.redact_evidence)
        outputs = {name: str(path) for name, path in artifacts.outputs.items()}
        self.progress_changed.emit(100, "Scan complete")
        self.scan_completed.emit(payload, outputs)


class DashboardWindow(QMainWindow):
    def __init__(
        self,
        config: AppConfig,
        *,
        initial_payload: dict[str, Any] | None = None,
        initial_outputs: dict[str, str] | None = None,
        options: DashboardLaunchOptions | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.config = config
        self.outputs = initial_outputs or {}
        self.payload = initial_payload or empty_payload()
        self.options = options or DashboardLaunchOptions()
        self.scan_thread: QThread | None = None
        self.scan_worker: ScanWorker | None = None

        self.setWindowTitle("Digital Identity Protection System")
        self.resize(1560, 960)
        self.setMinimumSize(1320, 860)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(22, 22, 22, 22)
        root_layout.setSpacing(22)

        sidebar = self._build_sidebar()
        root_layout.addWidget(sidebar, 0)

        content = QVBoxLayout()
        content.setSpacing(20)
        root_layout.addLayout(content, 1)

        content.addWidget(self._build_topbar(), 0)
        self.stack = AnimatedStackedWidget()
        content.addWidget(self.stack, 1)

        self.overview_page = OverviewPage()
        self.reports_page = ReportsPage(self.open_output, self.refresh_latest_report)
        self.settings_page = SettingsPage(config)
        self.module_pages = {module_name: ModulePage(module_name) for module_name in MODULE_ORDER}

        module_page_rows = [
            (
                module_name,
                MODULE_META[module_name]["title"],
                MODULE_META[module_name]["subtitle"],
                self.module_pages[module_name],
            )
            for module_name in MODULE_ORDER
        ]
        self.pages: list[tuple[str, str, str, QWidget]] = [
            ("overview", "Overview", "SOC overview, correlated alerts, and identity posture.", self.overview_page),
            *module_page_rows,
            ("reports", "Reports", "Open exported JSON and HTML reports.", self.reports_page),
            ("settings", "Settings", "Desktop scan controls and privacy options.", self.settings_page),
        ]

        self.nav_buttons: dict[str, SidebarButton] = {}
        for index, (page_id, _title, _subtitle, widget) in enumerate(self.pages):
            self.stack.addWidget(widget)
            if index == 0:
                continue

        self._rebuild_sidebar_nav()
        self.apply_payload(self.payload, self.outputs)
        self.set_page(self.options.start_page if self.options.start_page in {item[0] for item in self.pages} else "overview")

        if self.options.auto_scan:
            QTimer.singleShot(200, self.start_scan)
        elif self.options.screenshot_path:
            QTimer.singleShot(500, self.capture_screenshot)

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setMinimumWidth(260)
        sidebar.setMaximumWidth(292)
        sidebar.setAttribute(Qt.WA_StyledBackground, True)
        apply_soft_shadow(sidebar, blur=44, y_offset=14, alpha=95)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(22, 24, 22, 24)
        layout.setSpacing(16)

        title = QLabel("DIPS")
        title.setObjectName("BrandTitle")
        layout.addWidget(title)

        brand_chip = QLabel("LOCAL-FIRST DEFENSE")
        brand_chip.setObjectName("BrandChip")
        layout.addWidget(brand_chip, 0, Qt.AlignLeft)

        subtitle = QLabel("Digital Identity Protection System")
        subtitle.setObjectName("BrandSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        metric_panel = QFrame()
        metric_panel.setObjectName("SidebarMetric")
        metric_layout = QVBoxLayout(metric_panel)
        metric_layout.setContentsMargins(18, 18, 18, 18)
        metric_layout.setSpacing(6)
        metric_title = QLabel("Protection Score")
        metric_title.setObjectName("SidebarMetricLabel")
        metric_layout.addWidget(metric_title)
        self.sidebar_metric_value = QLabel("0")
        self.sidebar_metric_value.setObjectName("SidebarMetricValue")
        metric_layout.addWidget(self.sidebar_metric_value)
        self.sidebar_metric_label = QLabel("Awaiting scan data")
        self.sidebar_metric_label.setObjectName("MutedText")
        self.sidebar_metric_label.setWordWrap(True)
        metric_layout.addWidget(self.sidebar_metric_label)
        self.sidebar_alerts_label = QLabel("Alerts: 0")
        self.sidebar_alerts_label.setObjectName("SidebarMetricLabel")
        metric_layout.addWidget(self.sidebar_alerts_label)
        self.sidebar_intel_label = QLabel("Threat hits: 0 | Correlations: 0")
        self.sidebar_intel_label.setObjectName("MutedText")
        self.sidebar_intel_label.setWordWrap(True)
        metric_layout.addWidget(self.sidebar_intel_label)
        layout.addWidget(metric_panel)

        self.sidebar_nav = QVBoxLayout()
        self.sidebar_nav.setSpacing(10)
        layout.addSpacing(4)
        layout.addLayout(self.sidebar_nav)
        layout.addStretch(1)

        footer = QLabel("Local-first SOC workflow for identity defense on Windows and Linux.")
        footer.setObjectName("MutedText")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        return sidebar

    def _rebuild_sidebar_nav(self) -> None:
        while self.sidebar_nav.count():
            item = self.sidebar_nav.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.nav_buttons.clear()
        groups = [
            ("Command View", ["overview"]),
            ("Detection Modules", MODULE_ORDER),
            ("Operations", ["reports", "settings"]),
        ]
        title_lookup = {page_id: title for page_id, title, _subtitle, _widget in self.pages}
        for section_title, page_ids in groups:
            label = QLabel(section_title)
            label.setObjectName("SidebarSectionTitle")
            self.sidebar_nav.addWidget(label, 0, Qt.AlignLeft)
            for page_id in page_ids:
                title = title_lookup[page_id]
                button = SidebarButton(title)
                button.clicked.connect(lambda checked=False, page=page_id: self.set_page(page))  # noqa: B023
                self.sidebar_nav.addWidget(button)
                self.nav_buttons[page_id] = button
            self.sidebar_nav.addSpacing(8)

    def _build_topbar(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Topbar")
        panel.setAttribute(Qt.WA_StyledBackground, True)
        apply_soft_shadow(panel, blur=38, y_offset=12, alpha=90)
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(18)

        title_column = QVBoxLayout()
        title_column.setSpacing(6)
        self.page_title = QLabel("Overview")
        self.page_title.setObjectName("PageTitle")
        title_column.addWidget(self.page_title)
        self.page_subtitle = QLabel("SOC overview and prioritized activity.")
        self.page_subtitle.setObjectName("PageSubtitle")
        title_column.addWidget(self.page_subtitle)
        layout.addLayout(title_column, 1)

        status_column = QVBoxLayout()
        status_column.setSpacing(8)
        self.status_badge = QLabel("Ready")
        self.status_badge.setObjectName("StatusBadge")
        status_column.addWidget(self.status_badge, 0, Qt.AlignRight)
        self.progress_bar = AnimatedProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(240)
        status_column.addWidget(self.progress_bar, 0, Qt.AlignRight)
        layout.addLayout(status_column, 0)

        self.scan_button = QPushButton("Run Scan")
        self.scan_button.setObjectName("PrimaryButton")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button, 0, Qt.AlignVCenter)

        self.open_reports_button = QPushButton("Open Reports")
        self.open_reports_button.setObjectName("SecondaryButton")
        self.open_reports_button.clicked.connect(lambda: self.set_page("reports"))
        layout.addWidget(self.open_reports_button, 0, Qt.AlignVCenter)
        return panel

    def set_page(self, page_id: str) -> None:
        for index, (candidate, title, subtitle, widget) in enumerate(self.pages):
            is_active = candidate == page_id
            button = self.nav_buttons.get(candidate)
            if button is not None:
                button.setChecked(is_active)
            if is_active:
                self.stack.set_current_with_fade(widget)
                self.page_title.setText(title)
                self.page_subtitle.setText(subtitle)

    def _set_busy(self, busy: bool, *, status: str) -> None:
        self.scan_button.setEnabled(not busy)
        self.settings_page.setEnabled(not busy)
        self.status_badge.setText(status)

    def apply_payload(self, payload: dict[str, Any], outputs: dict[str, str]) -> None:
        self.payload = payload
        self.outputs = outputs
        protection = overall_protection_score(payload)
        alert_count = len(flatten_findings(payload))
        priority_alerts = prioritized_alerts(payload, limit=200)
        threat_hits = threat_intel_summary(payload)["total"]
        correlations = len(alert_correlation_clusters(payload, limit=20))
        self.sidebar_metric_value.setText(str(protection))
        self.sidebar_metric_label.setText(
            f"{payload.get('summary', {}).get('overall_label', 'minimal').capitalize()} posture across the active scan."
        )
        self.sidebar_alerts_label.setText(
            f"P1/P2 alerts: {sum(1 for item in priority_alerts if item.get('priority_label') in {'P1', 'P2'})} | Total: {alert_count}"
        )
        self.sidebar_intel_label.setText(f"Threat hits: {threat_hits} | Correlations: {correlations}")
        self.overview_page.set_payload(payload, outputs)
        for module_name, page in self.module_pages.items():
            page.set_payload(payload)
        self.reports_page.set_payload(payload, outputs)
        self.progress_bar.animate_to(0)
        self.status_badge.setText(f"Ready | Last scan {payload.get('scan_id', 'pending')}")

    def refresh_latest_report(self) -> None:
        try:
            output_dir = self.settings_page.build_config().reporting.output_dir
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Invalid configuration", str(exc))
            return
        payload, outputs = load_latest_payload(output_dir)
        if payload is None:
            QMessageBox.information(self, "Reports", "No JSON reports were found in the configured output directory.")
            return
        self.apply_payload(payload, outputs)

    def start_scan(self) -> None:
        try:
            self.config = self.settings_page.build_config()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Invalid configuration", str(exc))
            return

        self._set_busy(True, status="Launching scan")
        self.progress_bar.animate_to(0)
        self.scan_thread = QThread(self)
        log_path = self.options.log_file or str(path_from_input(self.config.reporting.output_dir) / "dashboard.log")
        self.scan_worker = ScanWorker(self.config, log_file=log_path, debug=self.options.debug)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress_changed.connect(self._on_scan_progress)
        self.scan_worker.scan_completed.connect(self._on_scan_completed)
        self.scan_worker.scan_failed.connect(self._on_scan_failed)
        self.scan_worker.scan_completed.connect(self.scan_thread.quit)
        self.scan_worker.scan_failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    def _on_scan_progress(self, value: int, message: str) -> None:
        self.progress_bar.animate_to(value)
        self.status_badge.setText(message)

    def _on_scan_completed(self, payload: dict[str, Any], outputs: dict[str, str]) -> None:
        self._set_busy(False, status="Scan complete")
        self.apply_payload(payload, outputs)
        if self.options.screenshot_path:
            QTimer.singleShot(600, self.capture_screenshot)

    def _on_scan_failed(self, message: str) -> None:
        self._set_busy(False, status="Scan failed")
        QMessageBox.critical(self, "Scan failed", message)

    def open_output(self, path: str) -> None:
        target = path_from_input(path)
        if not target.exists():
            QMessageBox.warning(self, "Report unavailable", f"Report file was not found: {target}")
            return
        opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))
        if not opened:
            QMessageBox.warning(self, "Open failed", f"Could not open the report file: {target}")

    def capture_screenshot(self) -> None:
        if not self.options.screenshot_path:
            return
        target = path_from_input(self.options.screenshot_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.grab().save(str(target))
        self.options.screenshot_path = ""
        app = QApplication.instance()
        if app is not None:
            app.quit()
