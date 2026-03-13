"""Dashboard pages for the DIPS desktop UI."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from dips.core.config import AppConfig
from dips.gui.state import (
    alert_correlation_clusters,
    MODULE_META,
    MODULE_ORDER,
    identity_exposure_map_nodes,
    flatten_findings,
    module_metrics,
    module_payload,
    module_status_text,
    overview_cards,
    overall_protection_score,
    prioritized_alerts,
    recommendation_list,
    risk_trend_summary,
    scan_history_points,
    severity_heatmap_rows,
    threat_intel_rows,
    threat_intel_summary,
    contributing_findings,
    timeline_events,
)
from dips.gui.widgets import (
    MetadataPanel,
    PriorityAlertsPanel,
    RecommendationList,
    SecurityTimelinePanel,
    SectionFrame,
    SeverityBadge,
    StatCard,
    ThreatIntelPanel,
)
from dips.ui_dashboard.charts import (
    AlertCorrelationChart,
    ExposureTimelineChart,
    IdentityExposureMapChart,
    SeverityHeatmapChart,
)
from dips.ui_dashboard.findings_table import FindingsTableWidget
from dips.ui_dashboard.risk_score_widget import RiskScoreWidget
from dips.utils.secure_io import atomic_write_json


def _scroll_page() -> tuple[QScrollArea, QWidget, QVBoxLayout]:
    area = QScrollArea()
    area.setWidgetResizable(True)
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(18)
    area.setWidget(container)
    return area, container, layout


class OverviewPage(QScrollArea):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        container = QWidget()
        self.layout_root = QVBoxLayout(container)
        self.layout_root.setContentsMargins(0, 0, 0, 0)
        self.layout_root.setSpacing(22)
        self.setWidget(container)

        cards_frame = QFrame()
        cards_layout = QGridLayout(cards_frame)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setHorizontalSpacing(18)
        cards_layout.setVerticalSpacing(18)
        self.cards: list[StatCard] = []
        for index in range(4):
            card = StatCard()
            self.cards.append(card)
            cards_layout.addWidget(card, 0, index)
            cards_layout.setColumnStretch(index, 1)
        self.layout_root.addWidget(cards_frame)

        command_row = QHBoxLayout()
        command_row.setSpacing(18)

        self.gauge_section = SectionFrame("Identity Protection Command", "Weighted posture and operating readiness.")
        self.gauge = RiskScoreWidget()
        self.gauge_section.content.addWidget(self.gauge)
        command_row.addWidget(self.gauge_section, 3)

        self.trend_section = SectionFrame("Risk Trend Graph", "Recent score movement across retained scan reports.")
        self.history_chart = ExposureTimelineChart()
        self.trend_section.content.addWidget(self.history_chart)
        command_row.addWidget(self.trend_section, 4)

        self.heatmap_section = SectionFrame("Severity Heatmap", "Module-to-severity concentration across the current scan.")
        self.heatmap_chart = SeverityHeatmapChart()
        self.heatmap_section.content.addWidget(self.heatmap_chart)
        command_row.addWidget(self.heatmap_section, 3)
        self.layout_root.addLayout(command_row)

        intel_row = QHBoxLayout()
        intel_row.setSpacing(18)

        threat_section = SectionFrame("Threat Intelligence Panel", "Indicator reputation, malicious matches, and enrichment confidence.")
        self.threat_panel = ThreatIntelPanel()
        threat_section.content.addWidget(self.threat_panel)
        intel_row.addWidget(threat_section, 4)

        map_section = SectionFrame("Identity Exposure Map", "Identity surface zones linked to the current alert inventory.")
        self.identity_map = IdentityExposureMapChart()
        map_section.content.addWidget(self.identity_map)
        intel_row.addWidget(map_section, 3)

        correlation_section = SectionFrame("Alert Correlation View", "Cross-module patterns linking timeline, phishing, breach, and intel signals.")
        self.correlation_chart = AlertCorrelationChart()
        correlation_section.content.addWidget(self.correlation_chart)
        intel_row.addWidget(correlation_section, 3)
        self.layout_root.addLayout(intel_row)

        operations_row = QHBoxLayout()
        operations_row.setSpacing(18)

        self.timeline_section = SectionFrame("Security Event Timeline", "Chronological events with severity and module filtering for the active scan.")
        self.timeline_panel = SecurityTimelinePanel()
        self.timeline_section.content.addWidget(self.timeline_panel)
        operations_row.addWidget(self.timeline_section, 3)

        priority_section = SectionFrame("Prioritized Alert Queue", "Immediate analyst queue ordered by urgency and confidence.")
        self.priority_alerts = PriorityAlertsPanel()
        priority_section.content.addWidget(self.priority_alerts)
        operations_row.addWidget(priority_section, 2)
        self.layout_root.addLayout(operations_row)

        lower_row = QHBoxLayout()
        lower_row.setSpacing(18)

        rec_section = SectionFrame("Top Remediation Queue", "Priority actions surfaced by the scoring engine.")
        self.recommendations = RecommendationList()
        rec_section.content.addWidget(self.recommendations)
        lower_row.addWidget(rec_section, 2)

        self.metadata_panel = MetadataPanel()
        lower_row.addWidget(self.metadata_panel, 1)
        self.layout_root.addLayout(lower_row)
        self.layout_root.addStretch(1)

    def set_payload(self, payload: dict, outputs: dict[str, str]) -> None:
        for card, content in zip(self.cards, overview_cards(payload), strict=False):
            card.set_content(**content)
        trend = risk_trend_summary(payload, outputs)
        self.gauge.set_score(
            overall_protection_score(payload),
            label="Protection Score",
            subtitle=f"Overall risk label: {payload.get('summary', {}).get('overall_label', 'minimal')}",
        )
        self.trend_section.set_subtitle(
            f"Current risk {trend['current']} | delta {trend['delta']:+d} | posture {str(trend['label']).upper()}"
        )
        self.history_chart.set_points(scan_history_points(payload, outputs))
        self.heatmap_chart.set_rows(severity_heatmap_rows(payload))
        self.threat_panel.set_content(threat_intel_rows(payload), threat_intel_summary(payload))
        self.identity_map.set_nodes(identity_exposure_map_nodes(payload))
        self.correlation_chart.set_clusters(alert_correlation_clusters(payload))
        self.timeline_panel.set_events(timeline_events(payload, limit=80))
        self.priority_alerts.set_alerts(prioritized_alerts(payload))
        self.recommendations.set_recommendations(
            recommendation_list(payload),
            empty_text="No remediation queue is available until a scan produces findings.",
        )
        self.metadata_panel.set_payload(payload)


class ModulePage(QScrollArea):
    def __init__(self, module_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.module_name = module_name
        self.setWidgetResizable(True)
        container = QWidget()
        self.layout_root = QVBoxLayout(container)
        self.layout_root.setContentsMargins(0, 0, 0, 0)
        self.layout_root.setSpacing(22)
        self.setWidget(container)

        cards_frame = QFrame()
        cards_layout = QGridLayout(cards_frame)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setHorizontalSpacing(18)
        cards_layout.setVerticalSpacing(18)
        self.cards: list[StatCard] = []
        for index in range(4):
            card = StatCard()
            self.cards.append(card)
            cards_layout.addWidget(card, 0, index)
            cards_layout.setColumnStretch(index, 1)
        self.layout_root.addWidget(cards_frame)

        status_section = SectionFrame("Module Posture", MODULE_META[module_name]["subtitle"])
        status_row = QHBoxLayout()
        self.status_badge = SeverityBadge("info", "IDLE")
        self.status_text = QLabel(MODULE_META[module_name]["empty"])
        self.status_text.setObjectName("MutedText")
        self.status_text.setWordWrap(True)
        status_row.addWidget(self.status_badge, 0, Qt.AlignTop)
        status_row.addWidget(self.status_text, 1)
        status_section.content.addLayout(status_row)
        self.layout_root.addWidget(status_section)

        recommendation_section = SectionFrame("Remediation Suggestions", "Most relevant next actions for this module.")
        self.recommendations = RecommendationList()
        recommendation_section.content.addWidget(self.recommendations)
        self.layout_root.addWidget(recommendation_section)

        findings_section = SectionFrame("Detailed Findings", "Sortable evidence-driven findings for this module.")
        self.findings_table = FindingsTableWidget()
        self.findings_table.setMinimumHeight(380)
        findings_section.content.addWidget(self.findings_table)
        self.layout_root.addWidget(findings_section)
        self.layout_root.addStretch(1)

    def set_payload(self, payload: dict) -> None:
        module = module_payload(payload, self.module_name)
        findings = flatten_findings(payload, self.module_name)
        metadata = module.get("metadata", {})
        for card, content in zip(self.cards, module_metrics(payload, self.module_name), strict=False):
            card.set_content(**content)
        status = str(module.get("status", "idle")).lower()
        badge_severity = "critical" if status == "error" else "medium" if status == "skipped" else "low"
        self.status_badge.set_severity(badge_severity, text=status.upper())
        warnings = module.get("warnings", [])
        if warnings:
            self.status_text.setText("\n".join(str(item) for item in warnings))
        elif self.module_name == "ai_security_analysis" and (
            metadata.get("summary") or metadata.get("risk_explanation")
        ):
            summary = str(metadata.get("summary", "")).strip()
            explanation = str(metadata.get("risk_explanation", "")).strip()
            self.status_text.setText("\n\n".join(item for item in [summary, explanation] if item))
        elif findings:
            self.status_text.setText(module_status_text(payload, self.module_name))
        else:
            self.status_text.setText(MODULE_META[self.module_name]["empty"])
        self.recommendations.set_recommendations(
            recommendation_list(payload, self.module_name),
            empty_text="No module-specific remediation suggestions are available yet.",
        )
        self.findings_table.set_findings(findings)


class ReportsPage(QScrollArea):
    def __init__(
        self,
        on_open_output: Callable[[str], None],
        on_refresh_latest: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.on_open_output = on_open_output
        self.on_refresh_latest = on_refresh_latest
        self.outputs: dict[str, str] = {}
        self.setWidgetResizable(True)
        container = QWidget()
        self.layout_root = QVBoxLayout(container)
        self.layout_root.setContentsMargins(0, 0, 0, 0)
        self.layout_root.setSpacing(22)
        self.setWidget(container)

        cards_frame = QFrame()
        cards_layout = QGridLayout(cards_frame)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setHorizontalSpacing(18)
        cards_layout.setVerticalSpacing(18)
        self.cards: list[StatCard] = []
        for index in range(4):
            card = StatCard()
            self.cards.append(card)
            cards_layout.addWidget(card, 0, index)
            cards_layout.setColumnStretch(index, 1)
        self.layout_root.addWidget(cards_frame)

        actions_section = SectionFrame("Export Actions", "Open the latest generated artifacts directly from the dashboard.")
        action_row = QHBoxLayout()
        self.open_json_button = QPushButton("Open JSON Report")
        self.open_json_button.setObjectName("SecondaryButton")
        self.open_json_button.clicked.connect(lambda: self._open_key("json"))
        action_row.addWidget(self.open_json_button)

        self.open_html_button = QPushButton("Open HTML Report")
        self.open_html_button.setObjectName("SecondaryButton")
        self.open_html_button.clicked.connect(lambda: self._open_key("html"))
        action_row.addWidget(self.open_html_button)

        self.refresh_button = QPushButton("Refresh Latest")
        self.refresh_button.setObjectName("InlineButton")
        self.refresh_button.clicked.connect(self.on_refresh_latest)
        action_row.addWidget(self.refresh_button)
        action_row.addStretch(1)
        actions_section.content.addLayout(action_row)

        self.layout_root.addWidget(actions_section)

        self.report_paths = SectionFrame("Report Paths", "Latest output file locations.")
        self.paths_list = QListWidget()
        self.paths_list.setMinimumHeight(180)
        self.report_paths.content.addWidget(self.paths_list)
        self.layout_root.addWidget(self.report_paths)

        self.recommendation_section = SectionFrame("Executive Summary", "Primary remediations exported with the last scan.")
        self.recommendations = RecommendationList()
        self.recommendation_section.content.addWidget(self.recommendations)
        self.layout_root.addWidget(self.recommendation_section)

        self.contributing_section = SectionFrame("Top Risk Drivers", "Findings that contributed most to the digital identity risk score.")
        self.contributors = RecommendationList()
        self.contributing_section.content.addWidget(self.contributors)
        self.layout_root.addWidget(self.contributing_section)
        self.layout_root.addStretch(1)

    def _open_key(self, key: str) -> None:
        path = self.outputs.get(key)
        if path:
            self.on_open_output(path)

    def set_payload(self, payload: dict, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        items = [
            {
                "title": "Scan ID",
                "value": str(payload.get("scan_id", "pending")),
                "subtitle": "Most recent report snapshot.",
                "tone": "primary",
            },
            {
                "title": "Duration",
                "value": f"{int(payload.get('duration_ms', 0))} ms",
                "subtitle": "End-to-end scan execution time.",
                "tone": "neutral",
            },
            {
                "title": "Risk Model",
                "value": str(payload.get("summary", {}).get("risk_model", "digital_identity_weighted_sum")).replace("_", " "),
                "subtitle": "Scoring profile used for the latest assessment.",
                "tone": "warning",
            },
            {
                "title": "Formats",
                "value": ", ".join(sorted(outputs)) if outputs else "none",
                "subtitle": "Artifacts written in the last run.",
                "tone": "alert",
            },
        ]
        for card, content in zip(self.cards, items, strict=False):
            card.set_content(**content)

        self.paths_list.clear()
        if not outputs:
            self.paths_list.addItem("No report artifacts are available yet.")
        else:
            for key, path in sorted(outputs.items()):
                self.paths_list.addItem(f"{key.upper()}: {path}")

        self.open_json_button.setEnabled("json" in outputs)
        self.open_html_button.setEnabled("html" in outputs)
        self.recommendations.set_recommendations(
            recommendation_list(payload),
            empty_text="Run a scan to populate the executive remediation summary.",
        )
        self.contributors.set_recommendations(
            contributing_findings(payload),
            empty_text="Run a scan to populate the top risk drivers.",
        )


class SettingsPage(QScrollArea):
    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._config = deepcopy(config)
        self.setWidgetResizable(True)
        container = QWidget()
        self.layout_root = QVBoxLayout(container)
        self.layout_root.setContentsMargins(0, 0, 0, 0)
        self.layout_root.setSpacing(22)
        self.setWidget(container)

        self.scan_section = SectionFrame("Scan Configuration", "Control performance, scan scope, and export behavior.")
        self.layout_root.addWidget(self.scan_section)
        form = QFormLayout()
        form.setSpacing(14)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.scan_section.content.addLayout(form)

        self.output_dir_edit = QLineEdit()
        self.output_dir_button = QPushButton("Browse")
        self.output_dir_button.setObjectName("InlineButton")
        self.output_dir_button.clicked.connect(self._choose_output_dir)
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_dir_edit, 1)
        output_row.addWidget(self.output_dir_button)
        form.addRow("Output directory", self._wrap_layout(output_row))

        self.max_file_size = QSpinBox()
        self.max_file_size.setRange(1, 1024)
        form.addRow("Max file size (MB)", self.max_file_size)

        self.max_files = QSpinBox()
        self.max_files.setRange(1, 1_000_000)
        form.addRow("Max files", self.max_files)

        self.max_workers = QSpinBox()
        self.max_workers.setRange(1, 64)
        form.addRow("Max workers", self.max_workers)

        self.max_extensions = QSpinBox()
        self.max_extensions.setRange(0, 500)
        form.addRow("Browser extension threshold", self.max_extensions)

        self.watch_interval = QSpinBox()
        self.watch_interval.setRange(0, 86_400)
        form.addRow("Watch interval (seconds)", self.watch_interval)

        self.redact_checkbox = QCheckBox("Redact evidence in exported reports")
        form.addRow("Privacy", self.redact_checkbox)

        self.allow_external_breach = QCheckBox("Allow approved hashed provider lookups")
        form.addRow("Breach lookups", self.allow_external_breach)

        self.allow_online_threat = QCheckBox("Allow online threat intelligence lookups")
        form.addRow("Threat intel", self.allow_online_threat)

        format_row = QHBoxLayout()
        self.json_checkbox = QCheckBox("JSON")
        self.html_checkbox = QCheckBox("HTML")
        format_row.addWidget(self.json_checkbox)
        format_row.addWidget(self.html_checkbox)
        format_row.addStretch(1)
        form.addRow("Report formats", self._wrap_layout(format_row))

        modules_section = SectionFrame("Enabled Modules", "Toggle individual scanners without changing core code.")
        self.layout_root.addWidget(modules_section)
        module_row = QHBoxLayout()
        self.module_checkboxes: dict[str, QCheckBox] = {}
        for module_name in MODULE_ORDER:
            checkbox = QCheckBox(MODULE_META[module_name]["title"])
            self.module_checkboxes[module_name] = checkbox
            module_row.addWidget(checkbox)
        module_row.addStretch(1)
        modules_section.content.addLayout(module_row)

        path_section = SectionFrame("Paths And Inputs", "Manage scan roots, password sources, and phishing samples.")
        self.layout_root.addWidget(path_section)

        paths_layout = QGridLayout()
        path_section.content.addLayout(paths_layout)

        self.paths_list = QListWidget()
        self.paths_list.setObjectName("SettingsList")
        self.paths_list.setMinimumHeight(150)
        paths_layout.addWidget(QLabel("Scan paths"), 0, 0)
        paths_layout.addWidget(self.paths_list, 1, 0)
        path_buttons = QVBoxLayout()
        add_path = QPushButton("Add Path")
        add_path.setObjectName("InlineButton")
        add_path.clicked.connect(self._add_scan_path)
        path_buttons.addWidget(add_path)
        remove_path = QPushButton("Remove Path")
        remove_path.setObjectName("InlineButton")
        remove_path.clicked.connect(lambda: self._remove_selected(self.paths_list))
        path_buttons.addWidget(remove_path)
        path_buttons.addStretch(1)
        paths_layout.addLayout(path_buttons, 1, 1)

        self.email_list = QListWidget()
        self.email_list.setObjectName("SettingsList")
        self.email_list.setMinimumHeight(150)
        paths_layout.addWidget(QLabel("Email samples"), 2, 0)
        paths_layout.addWidget(self.email_list, 3, 0)
        email_buttons = QVBoxLayout()
        add_email = QPushButton("Add Email File")
        add_email.setObjectName("InlineButton")
        add_email.clicked.connect(self._add_email_file)
        email_buttons.addWidget(add_email)
        remove_email = QPushButton("Remove Email")
        remove_email.setObjectName("InlineButton")
        remove_email.clicked.connect(lambda: self._remove_selected(self.email_list))
        email_buttons.addWidget(remove_email)
        email_buttons.addStretch(1)
        paths_layout.addLayout(email_buttons, 3, 1)

        self.identifier_list = QListWidget()
        self.identifier_list.setObjectName("SettingsList")
        self.identifier_list.setMinimumHeight(140)
        paths_layout.addWidget(QLabel("Identity targets"), 4, 0)
        paths_layout.addWidget(self.identifier_list, 5, 0)
        identifier_buttons = QVBoxLayout()
        add_identifier = QPushButton("Add Identifier")
        add_identifier.setObjectName("InlineButton")
        add_identifier.clicked.connect(self._add_identifier)
        identifier_buttons.addWidget(add_identifier)
        remove_identifier = QPushButton("Remove Identifier")
        remove_identifier.setObjectName("InlineButton")
        remove_identifier.clicked.connect(lambda: self._remove_selected(self.identifier_list))
        identifier_buttons.addWidget(remove_identifier)
        identifier_buttons.addStretch(1)
        paths_layout.addLayout(identifier_buttons, 5, 1)

        self.dataset_list = QListWidget()
        self.dataset_list.setObjectName("SettingsList")
        self.dataset_list.setMinimumHeight(140)
        paths_layout.addWidget(QLabel("Offline breach datasets"), 6, 0)
        paths_layout.addWidget(self.dataset_list, 7, 0)
        dataset_buttons = QVBoxLayout()
        add_dataset = QPushButton("Add Dataset")
        add_dataset.setObjectName("InlineButton")
        add_dataset.clicked.connect(self._add_breach_dataset)
        dataset_buttons.addWidget(add_dataset)
        remove_dataset = QPushButton("Remove Dataset")
        remove_dataset.setObjectName("InlineButton")
        remove_dataset.clicked.connect(lambda: self._remove_selected(self.dataset_list))
        dataset_buttons.addWidget(remove_dataset)
        dataset_buttons.addStretch(1)
        paths_layout.addLayout(dataset_buttons, 7, 1)

        self.threat_feed_list = QListWidget()
        self.threat_feed_list.setObjectName("SettingsList")
        self.threat_feed_list.setMinimumHeight(140)
        paths_layout.addWidget(QLabel("Threat intelligence feeds"), 8, 0)
        paths_layout.addWidget(self.threat_feed_list, 9, 0)
        threat_feed_buttons = QVBoxLayout()
        add_threat_feed = QPushButton("Add Threat Feed")
        add_threat_feed.setObjectName("InlineButton")
        add_threat_feed.clicked.connect(self._add_threat_feed)
        threat_feed_buttons.addWidget(add_threat_feed)
        remove_threat_feed = QPushButton("Remove Threat Feed")
        remove_threat_feed.setObjectName("InlineButton")
        remove_threat_feed.clicked.connect(lambda: self._remove_selected(self.threat_feed_list))
        threat_feed_buttons.addWidget(remove_threat_feed)
        threat_feed_buttons.addStretch(1)
        paths_layout.addLayout(threat_feed_buttons, 9, 1)

        password_row = QHBoxLayout()
        self.password_file_edit = QLineEdit()
        browse_password = QPushButton("Browse")
        browse_password.setObjectName("InlineButton")
        browse_password.clicked.connect(self._choose_password_file)
        password_row.addWidget(self.password_file_edit, 1)
        password_row.addWidget(browse_password)
        path_section.content.addWidget(QLabel("Password file"))
        path_section.content.addLayout(password_row)

        save_section = SectionFrame("Configuration Files", "Persist the current desktop settings to JSON.")
        self.layout_root.addWidget(save_section)
        action_row = QHBoxLayout()
        self.save_button = QPushButton("Save Config As")
        self.save_button.setObjectName("SecondaryButton")
        self.save_button.clicked.connect(self._save_config)
        action_row.addWidget(self.save_button)
        self.reload_button = QPushButton("Reload Defaults")
        self.reload_button.setObjectName("InlineButton")
        self.reload_button.clicked.connect(lambda: self.load_config(config))
        action_row.addWidget(self.reload_button)
        action_row.addStretch(1)
        save_section.content.addLayout(action_row)
        self.layout_root.addStretch(1)

        self.load_config(config)

    @staticmethod
    def _wrap_layout(layout: QHBoxLayout) -> QWidget:
        container = QWidget()
        container.setLayout(layout)
        return container

    def _choose_output_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select report output directory")
        if directory:
            self.output_dir_edit.setText(directory)

    def _add_scan_path(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Add scan path")
        if directory:
            self.paths_list.addItem(directory)

    def _add_email_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select email sample")
        if file_path:
            self.email_list.addItem(file_path)

    def _add_identifier(self) -> None:
        value, accepted = QInputDialog.getText(
            self,
            "Add identity target",
            "Email address or username",
        )
        if accepted and value.strip():
            self.identifier_list.addItem(value.strip())

    def _add_breach_dataset(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select breach dataset", filter="JSON Files (*.json)")
        if file_path:
            self.dataset_list.addItem(file_path)

    def _add_threat_feed(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select threat intelligence feed", filter="JSON Files (*.json)")
        if file_path:
            self.threat_feed_list.addItem(file_path)

    def _choose_password_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select password file")
        if file_path:
            self.password_file_edit.setText(file_path)

    @staticmethod
    def _remove_selected(widget: QListWidget) -> None:
        for item in widget.selectedItems():
            widget.takeItem(widget.row(item))

    def _save_config(self) -> None:
        try:
            config = self.build_config()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Invalid configuration", str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save configuration", filter="JSON Files (*.json)")
        if not path:
            return
        try:
            atomic_write_json(Path(path), config.to_dict(), private=True)
        except OSError as exc:
            QMessageBox.critical(self, "Save failed", f"Configuration could not be saved: {exc}")

    def load_config(self, config: AppConfig) -> None:
        self._config = deepcopy(config)
        self.output_dir_edit.setText(self._config.reporting.output_dir)
        self.max_file_size.setValue(self._config.scan.max_file_size_mb)
        self.max_files.setValue(self._config.scan.max_files)
        self.max_workers.setValue(self._config.scan.max_workers)
        self.max_extensions.setValue(self._config.browser.max_extension_count)
        self.watch_interval.setValue(self._config.watch.interval_seconds)
        self.redact_checkbox.setChecked(self._config.reporting.redact_evidence)
        self.allow_external_breach.setChecked(self._config.breach_intelligence.allow_external)
        self.allow_online_threat.setChecked(self._config.threat_intelligence.allow_online)
        self.json_checkbox.setChecked("json" in self._config.reporting.formats)
        self.html_checkbox.setChecked("html" in self._config.reporting.formats)
        self.password_file_edit.setText(self._config.credential.password_file)

        self.paths_list.clear()
        for item in self._config.scan.paths:
            self.paths_list.addItem(item)
        self.email_list.clear()
        for item in self._config.email.inputs:
            self.email_list.addItem(item)
        self.identifier_list.clear()
        for item in self._config.breach_intelligence.identifiers:
            self.identifier_list.addItem(item)
        self.dataset_list.clear()
        for item in self._config.breach_intelligence.offline_datasets:
            self.dataset_list.addItem(item)
        self.threat_feed_list.clear()
        for item in self._config.threat_intelligence.feed_paths:
            self.threat_feed_list.addItem(item)
        for module_name, checkbox in self.module_checkboxes.items():
            checkbox.setChecked(module_name in self._config.modules.enabled)

    def build_config(self) -> AppConfig:
        config = deepcopy(self._config)
        config.reporting.output_dir = self.output_dir_edit.text().strip() or "reports"
        config.scan.max_file_size_mb = self.max_file_size.value()
        config.scan.max_files = self.max_files.value()
        config.scan.max_workers = self.max_workers.value()
        config.browser.max_extension_count = self.max_extensions.value()
        config.watch.interval_seconds = self.watch_interval.value()
        config.reporting.redact_evidence = self.redact_checkbox.isChecked()
        config.breach_intelligence.allow_external = self.allow_external_breach.isChecked()
        config.threat_intelligence.allow_online = self.allow_online_threat.isChecked()
        config.reporting.formats = [
            fmt
            for fmt, checkbox in [("json", self.json_checkbox), ("html", self.html_checkbox)]
            if checkbox.isChecked()
        ]
        config.scan.paths = [self.paths_list.item(index).text() for index in range(self.paths_list.count())]
        config.email.inputs = [self.email_list.item(index).text() for index in range(self.email_list.count())]
        config.breach_intelligence.identifiers = [
            self.identifier_list.item(index).text() for index in range(self.identifier_list.count())
        ]
        config.breach_intelligence.offline_datasets = [
            self.dataset_list.item(index).text() for index in range(self.dataset_list.count())
        ]
        config.threat_intelligence.feed_paths = [
            self.threat_feed_list.item(index).text() for index in range(self.threat_feed_list.count())
        ]
        config.credential.password_file = self.password_file_edit.text().strip()
        config.modules.enabled = [
            module_name for module_name, checkbox in self.module_checkboxes.items() if checkbox.isChecked()
        ]
        config.validate()
        return config
