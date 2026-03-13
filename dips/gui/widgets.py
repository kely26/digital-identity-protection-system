"""Reusable Qt widgets for the DIPS dashboard."""

from __future__ import annotations

from math import cos, radians, sin
from typing import Iterable

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dips.gui.state import MODULE_META, SEVERITY_COLORS, SEVERITY_RANK


def _accent_color(tone: str) -> str:
    return {
        "primary": "#22bfd8",
        "warning": "#f8b84a",
        "alert": "#ff5d78",
        "neutral": "#87a0b8",
    }.get(tone, "#0f9fb7")


def apply_soft_shadow(widget: QWidget, *, blur: int = 32, y_offset: int = 10, alpha: int = 110) -> None:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, y_offset)
    effect.setColor(QColor(2, 8, 15, alpha))
    widget.setGraphicsEffect(effect)


class AnimatedProgressBar(QProgressBar):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._animation = QPropertyAnimation(self, b"value", self)
        self._animation.setDuration(240)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)

    def animate_to(self, value: int) -> None:
        target = max(self.minimum(), min(self.maximum(), int(value)))
        self._animation.stop()
        self._animation.setStartValue(self.value())
        self._animation.setEndValue(target)
        self._animation.start()


class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._animation: QPropertyAnimation | None = None

    def set_current_with_fade(self, widget: QWidget) -> None:
        if self.currentWidget() is widget:
            return
        super().setCurrentWidget(widget)
        effect = QGraphicsOpacityEffect(widget)
        effect.setOpacity(0.0)
        widget.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(220)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.OutCubic)

        def _cleanup() -> None:
            widget.setGraphicsEffect(None)

        animation.finished.connect(_cleanup)
        self._animation = animation
        animation.start()


class StatCard(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setProperty("tone", "primary")
        apply_soft_shadow(self, blur=36, y_offset=12, alpha=95)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(10)

        self.title_label = QLabel()
        self.title_label.setObjectName("CardTitle")
        header_row.addWidget(self.title_label)
        header_row.addStretch(1)

        self.tone_badge = QLabel()
        self.tone_badge.setObjectName("CardToneBadge")
        header_row.addWidget(self.tone_badge, 0, Qt.AlignRight)
        layout.addLayout(header_row)

        self.value_label = QLabel()
        self.value_label.setObjectName("CardValue")
        layout.addWidget(self.value_label)

        self.subtitle_label = QLabel()
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setObjectName("CardSubtitle")
        layout.addWidget(self.subtitle_label)

        self.accent = QLabel()
        self.accent.setObjectName("CardAccent")
        layout.addWidget(self.accent)
        layout.addStretch(1)

    def set_content(self, *, title: str, value: str, subtitle: str, tone: str = "primary") -> None:
        self.title_label.setText(title)
        self.value_label.setText(value)
        self.subtitle_label.setText(subtitle)
        self.setProperty("tone", tone)
        self.tone_badge.setText(tone.upper())
        self.tone_badge.setStyleSheet(
            "padding: 4px 10px; border-radius: 999px; "
            f"background: {_accent_color(tone)}22; border: 1px solid {_accent_color(tone)}66; "
            f"color: {_accent_color(tone)}; font-weight: 700;"
        )
        self.accent.setStyleSheet(f"background: {_accent_color(tone)};")
        self.style().unpolish(self)
        self.style().polish(self)


class SectionFrame(QFrame):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Section")
        self.setAttribute(Qt.WA_StyledBackground, True)
        apply_soft_shadow(self, blur=30, y_offset=12, alpha=80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(16)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("SectionTitle")
        layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("SectionSubtitle")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        layout.addWidget(self.subtitle_label)

        self.content = QVBoxLayout()
        self.content.setSpacing(12)
        layout.addLayout(self.content)

    def set_subtitle(self, text: str) -> None:
        self.subtitle_label.setText(text)
        self.subtitle_label.setVisible(bool(text))


class SeverityBadge(QLabel):
    def __init__(self, severity: str = "info", text: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SeverityBadge")
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(30)
        self.set_severity(severity, text=text)

    def set_severity(self, severity: str, *, text: str | None = None) -> None:
        self.setProperty("severity", severity)
        self.setText((text or severity).upper())
        self.style().unpolish(self)
        self.style().polish(self)


class PriorityBadge(QLabel):
    def __init__(self, priority: str = "P4", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("PriorityBadge")
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(30)
        self.set_priority(priority)

    def set_priority(self, priority: str) -> None:
        normalized = str(priority or "P4").upper()
        self.setProperty("priority", normalized.lower())
        self.setText(normalized)
        self.style().unpolish(self)
        self.style().polish(self)


class SeverityTableItem(QTableWidgetItem):
    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = int(self.data(Qt.UserRole) or 0)
        right = int(other.data(Qt.UserRole) or 0)
        return left < right


class PriorityTableItem(QTableWidgetItem):
    ORDER = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}

    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = int(self.data(Qt.UserRole) or 0)
        right = int(other.data(Qt.UserRole) or 0)
        return left < right


class FindingsTable(QTableWidget):
    HEADERS = ["Severity", "Module", "Title", "Summary", "Location", "Recommendation", "Tags"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setShowGrid(False)
        self.setWordWrap(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(82)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)

    def set_findings(self, findings: Iterable[dict]) -> None:
        self.setSortingEnabled(False)
        self.clearContents()
        rows = list(findings)
        self.setRowCount(len(rows))
        for row_index, finding in enumerate(rows):
            severity = str(finding.get("severity", "info"))
            severity_item = SeverityTableItem(severity.upper())
            severity_item.setData(Qt.UserRole, SEVERITY_RANK.get(severity, 0))
            self.setItem(row_index, 0, severity_item)
            badge = SeverityBadge(severity, severity)
            badge_wrapper = QWidget()
            badge_layout = QHBoxLayout(badge_wrapper)
            badge_layout.setContentsMargins(8, 8, 8, 8)
            badge_layout.addWidget(badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 0, badge_wrapper)
            self.setItem(row_index, 1, QTableWidgetItem(str(finding.get("module_title", finding.get("module", "")))))
            self.setItem(row_index, 2, QTableWidgetItem(str(finding.get("title", ""))))
            self.setItem(row_index, 3, QTableWidgetItem(str(finding.get("summary", ""))))
            self.setItem(row_index, 4, QTableWidgetItem(str(finding.get("location", ""))))
            self.setItem(row_index, 5, QTableWidgetItem(str(finding.get("recommendation", ""))))
            self.setItem(row_index, 6, QTableWidgetItem(", ".join(finding.get("tags", []))))
            self.setRowHeight(row_index, 84)
        self.setSortingEnabled(True)
        if rows:
            self.sortItems(0, Qt.DescendingOrder)


class TimelineTable(QTableWidget):
    HEADERS = ["Time", "Severity", "Event", "Module"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setShowGrid(False)
        self.setWordWrap(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSortingEnabled(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(74)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

    @staticmethod
    def _display_time(value: str) -> str:
        if not value:
            return "--:--"
        try:
            stamp = value.replace("T", " ")
            return stamp[11:16]
        except IndexError:
            return value[:16]

    def set_events(self, events: Iterable[dict]) -> None:
        self.clearContents()
        rows = list(events)
        self.setRowCount(len(rows))
        for row_index, event in enumerate(rows):
            severity = str(event.get("severity", "info"))
            self.setItem(row_index, 0, QTableWidgetItem(self._display_time(str(event.get("timestamp", "")))))
            severity_item = SeverityTableItem(severity.upper())
            severity_item.setData(Qt.UserRole, SEVERITY_RANK.get(severity, 0))
            self.setItem(row_index, 1, severity_item)
            badge = SeverityBadge(severity, severity)
            badge_wrapper = QWidget()
            badge_layout = QHBoxLayout(badge_wrapper)
            badge_layout.setContentsMargins(8, 8, 8, 8)
            badge_layout.addWidget(badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 1, badge_wrapper)
            title = str(event.get("title", ""))
            correlations = [str(item) for item in event.get("correlations", []) if isinstance(item, str)]
            if correlations:
                title = f"{title} | Correlated: {correlations[0]}"
            event_item = QTableWidgetItem(title)
            event_item.setToolTip(str(event.get("summary", "")))
            self.setItem(row_index, 2, event_item)
            module_name = str(event.get("module", ""))
            module_title = MODULE_META.get(module_name, {}).get("title", module_name.replace("_", " "))
            self.setItem(row_index, 3, QTableWidgetItem(module_title))
            self.setRowHeight(row_index, 76)


class SecurityTimelinePanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.setAttribute(Qt.WA_StyledBackground, True)
        apply_soft_shadow(self, blur=28, y_offset=10, alpha=80)
        self._events: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities", "all")
        self.severity_filter.addItem("Critical", "critical")
        self.severity_filter.addItem("High", "high")
        self.severity_filter.addItem("Medium", "medium")
        self.severity_filter.addItem("Low", "low")
        self.severity_filter.addItem("Info", "info")
        self.severity_filter.currentTextChanged.connect(self._refresh)
        filter_row.addWidget(self.severity_filter, 0)
        self.module_filter = QComboBox()
        self.module_filter.addItem("All Modules", "all")
        self.module_filter.currentTextChanged.connect(self._refresh)
        filter_row.addWidget(self.module_filter, 0)
        filter_row.addStretch(1)
        layout.addLayout(filter_row)

        self.table = TimelineTable()
        self.table.setMinimumHeight(260)
        layout.addWidget(self.table)

    def set_events(self, events: list[dict]) -> None:
        self._events = list(events)
        current_module = str(self.module_filter.currentData() or "all")
        modules = sorted({str(event.get("module", "")).lower() for event in self._events if event.get("module")})
        self.module_filter.blockSignals(True)
        self.module_filter.clear()
        self.module_filter.addItem("All Modules", "all")
        for module_name in modules:
            title = MODULE_META.get(module_name, {}).get("title", module_name.replace("_", " ").title())
            self.module_filter.addItem(title, module_name)
        if current_module in {"all", *modules}:
            index = self.module_filter.findData(current_module)
            if index >= 0:
                self.module_filter.setCurrentIndex(index)
        self.module_filter.blockSignals(False)
        self._refresh()

    def _refresh(self) -> None:
        severity = str(self.severity_filter.currentData() or "all")
        module_name = str(self.module_filter.currentData() or "all")
        rows = self._events
        if severity != "all":
            rows = [event for event in rows if str(event.get("severity", "")).lower() == severity]
        if module_name != "all":
            rows = [event for event in rows if str(event.get("module", "")).lower() == module_name]
        self.table.set_events(rows)


def _inline_metric(label: str) -> tuple[QFrame, QLabel]:
    frame = QFrame()
    frame.setObjectName("InlineMetric")
    frame.setAttribute(Qt.WA_StyledBackground, True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(4)

    label_widget = QLabel(label)
    label_widget.setObjectName("InlineMetricLabel")
    layout.addWidget(label_widget)

    value_widget = QLabel("0")
    value_widget.setObjectName("InlineMetricValue")
    layout.addWidget(value_widget)
    return frame, value_widget


def _severity_for_reputation(reputation: str) -> str:
    return {
        "malicious": "critical",
        "suspicious": "medium",
        "unknown": "info",
    }.get(str(reputation).lower(), "low")


class ThreatIntelTable(QTableWidget):
    HEADERS = ["Priority", "Reputation", "Indicator", "Type", "Confidence", "Sources"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setShowGrid(False)
        self.setWordWrap(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(74)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

    def set_rows(self, rows: list[dict]) -> None:
        self.setSortingEnabled(False)
        self.clearContents()
        self.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            priority = str(row.get("priority_label", "P4")).upper()
            priority_item = PriorityTableItem(priority)
            priority_item.setData(Qt.UserRole, PriorityTableItem.ORDER.get(priority, 0))
            self.setItem(row_index, 0, priority_item)
            priority_badge = PriorityBadge(priority)
            priority_wrapper = QWidget()
            priority_layout = QHBoxLayout(priority_wrapper)
            priority_layout.setContentsMargins(8, 8, 8, 8)
            priority_layout.addWidget(priority_badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 0, priority_wrapper)

            reputation = str(row.get("reputation", "unknown")).lower()
            severity_item = SeverityTableItem(reputation.upper())
            severity_item.setData(Qt.UserRole, SEVERITY_RANK.get(_severity_for_reputation(reputation), 0))
            self.setItem(row_index, 1, severity_item)
            badge = SeverityBadge(_severity_for_reputation(reputation), reputation)
            badge_wrapper = QWidget()
            badge_layout = QHBoxLayout(badge_wrapper)
            badge_layout.setContentsMargins(8, 8, 8, 8)
            badge_layout.addWidget(badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 1, badge_wrapper)

            self.setItem(row_index, 2, QTableWidgetItem(str(row.get("indicator", ""))))
            self.setItem(row_index, 3, QTableWidgetItem(str(row.get("indicator_type", "")).upper()))
            confidence = int(round(float(row.get("confidence", 0.0)) * 100))
            confidence_item = QTableWidgetItem(f"{confidence}%")
            confidence_item.setData(Qt.UserRole, confidence)
            self.setItem(row_index, 4, confidence_item)
            self.setItem(row_index, 5, QTableWidgetItem(str(len(row.get("sources", [])))))
            self.setRowHeight(row_index, 76)
        self.setSortingEnabled(True)
        if rows:
            self.sortItems(0, Qt.DescendingOrder)


class ThreatIntelPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        metric_row = QHBoxLayout()
        metric_row.setSpacing(10)
        self._metric_values: dict[str, QLabel] = {}
        for key, label in [
            ("malicious", "Malicious"),
            ("suspicious", "Suspicious"),
            ("domains", "Domains"),
            ("ips", "IPs"),
        ]:
            metric, value = _inline_metric(label)
            self._metric_values[key] = value
            metric_row.addWidget(metric, 1)
        layout.addLayout(metric_row)

        self.table = ThreatIntelTable()
        self.table.setMinimumHeight(270)
        layout.addWidget(self.table)

    def set_content(self, rows: list[dict], summary: dict[str, int]) -> None:
        for key, label in self._metric_values.items():
            label.setText(str(summary.get(key, 0)))
        self.table.set_rows(rows)


class PriorityAlertsTable(QTableWidget):
    HEADERS = ["Priority", "Severity", "Module", "Alert", "Location", "Response"]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setShowGrid(False)
        self.setWordWrap(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSortingEnabled(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(84)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)

    def set_alerts(self, alerts: list[dict]) -> None:
        self.setSortingEnabled(False)
        self.clearContents()
        self.setRowCount(len(alerts))
        for row_index, finding in enumerate(alerts):
            priority = str(finding.get("priority_label", "P4")).upper()
            priority_item = PriorityTableItem(priority)
            priority_item.setData(Qt.UserRole, PriorityTableItem.ORDER.get(priority, 0))
            self.setItem(row_index, 0, priority_item)
            priority_badge = PriorityBadge(priority)
            priority_wrapper = QWidget()
            priority_layout = QHBoxLayout(priority_wrapper)
            priority_layout.setContentsMargins(8, 8, 8, 8)
            priority_layout.addWidget(priority_badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 0, priority_wrapper)

            severity = str(finding.get("severity", "info")).lower()
            severity_item = SeverityTableItem(severity.upper())
            severity_item.setData(Qt.UserRole, SEVERITY_RANK.get(severity, 0))
            self.setItem(row_index, 1, severity_item)
            badge = SeverityBadge(severity, severity)
            badge_wrapper = QWidget()
            badge_layout = QHBoxLayout(badge_wrapper)
            badge_layout.setContentsMargins(8, 8, 8, 8)
            badge_layout.addWidget(badge, 0, Qt.AlignCenter)
            self.setCellWidget(row_index, 1, badge_wrapper)

            self.setItem(row_index, 2, QTableWidgetItem(str(finding.get("module_title", finding.get("module", "")))))
            self.setItem(row_index, 3, QTableWidgetItem(str(finding.get("title", ""))))
            self.setItem(row_index, 4, QTableWidgetItem(str(finding.get("location", ""))))
            self.setItem(row_index, 5, QTableWidgetItem(str(finding.get("recommendation", ""))))
            self.setRowHeight(row_index, 86)
        self.setSortingEnabled(True)
        if alerts:
            self.sortItems(0, Qt.DescendingOrder)


class PriorityAlertsPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        metric_row = QHBoxLayout()
        metric_row.setSpacing(10)
        self._metric_values: dict[str, QLabel] = {}
        for key, label in [("p1", "P1"), ("p2", "P2"), ("total", "Queue")]:
            metric, value = _inline_metric(label)
            self._metric_values[key] = value
            metric_row.addWidget(metric, 1)
        layout.addLayout(metric_row)

        self.table = PriorityAlertsTable()
        self.table.setMinimumHeight(320)
        layout.addWidget(self.table)

    def set_alerts(self, alerts: list[dict]) -> None:
        self._metric_values["p1"].setText(str(sum(1 for item in alerts if item.get("priority_label") == "P1")))
        self._metric_values["p2"].setText(str(sum(1 for item in alerts if item.get("priority_label") == "P2")))
        self._metric_values["total"].setText(str(len(alerts)))
        self.table.set_alerts(alerts)


class RecommendationList(QListWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSpacing(8)
        self.setAlternatingRowColors(False)
        self.setSelectionMode(QAbstractItemView.NoSelection)

    def set_recommendations(self, items: Iterable[str], *, empty_text: str) -> None:
        self.clear()
        rows = list(items)
        if not rows:
            rows = [empty_text]
        for index, item in enumerate(rows, start=1):
            prefix = f"{index:02d}   " if item != empty_text else ""
            list_item = QListWidgetItem(f"{prefix}{item}")
            list_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            list_item.setSizeHint(QSize(0, 52))
            self.addItem(list_item)


class RiskGauge(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 0
        self._label = "Protection"
        self._subtitle = "Awaiting scan data"
        self.setMinimumHeight(270)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_score(self, score: int, *, label: str, subtitle: str) -> None:
        self._score = max(0, min(100, int(score)))
        self._label = label
        self._subtitle = subtitle
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(28, 18, -28, -18)
        side = min(rect.width(), rect.height()) - 28
        gauge_rect = QRectF(
            rect.center().x() - side / 2,
            rect.center().y() - side / 2 - 8,
            side,
            side,
        )

        painter.setPen(QPen(QColor("#163145"), 18))
        painter.drawArc(gauge_rect, 120 * 16, -300 * 16)

        score_color = QColor("#35d1a3" if self._score >= 75 else "#1fbad0" if self._score >= 50 else "#f5b44c" if self._score >= 30 else "#ff5d78")
        painter.setPen(QPen(score_color, 18, Qt.SolidLine, Qt.RoundCap))
        start_angle = 120 * 16
        span_angle = int(-300 * 16 * (self._score / 100))
        painter.drawArc(gauge_rect, start_angle, span_angle)

        tick_pen = QPen(QColor("#29455d"), 2)
        painter.setPen(tick_pen)
        radius_outer = gauge_rect.width() / 2 + 12
        radius_inner = radius_outer - 10
        center = gauge_rect.center()
        for index in range(11):
            angle = radians(210 - (300 / 10) * index)
            start_x = center.x() + cos(angle) * radius_inner
            start_y = center.y() - sin(angle) * radius_inner
            end_x = center.x() + cos(angle) * radius_outer
            end_y = center.y() - sin(angle) * radius_outer
            painter.drawLine(int(start_x), int(start_y), int(end_x), int(end_y))

        painter.setPen(QColor("#20384d"))
        painter.setBrush(QColor(10, 20, 31, 210))
        painter.drawEllipse(gauge_rect.adjusted(42, 42, -42, -42))

        painter.setPen(QColor("#f6fbff"))
        score_font = QFont(self.font())
        score_font.setPointSize(30)
        score_font.setBold(True)
        painter.setFont(score_font)
        painter.drawText(gauge_rect.adjusted(0, -6, 0, 0), Qt.AlignCenter, str(self._score))

        label_font = QFont(self.font())
        label_font.setPointSize(11)
        painter.setFont(label_font)
        painter.setPen(QColor("#8fa4bc"))
        painter.drawText(
            gauge_rect.adjusted(0, 62, 0, 0),
            Qt.AlignHCenter | Qt.AlignTop,
            self._label,
        )
        painter.drawText(
            self.rect().adjusted(0, self.height() - 42, 0, -14),
            Qt.AlignHCenter | Qt.AlignBottom,
            self._subtitle,
        )

        mini_font = QFont(self.font())
        mini_font.setPointSize(9)
        painter.setFont(mini_font)
        painter.drawText(self.rect().adjusted(32, self.height() - 52, -32, -14), Qt.AlignLeft | Qt.AlignBottom, "0")
        painter.drawText(self.rect().adjusted(32, self.height() - 52, -32, -14), Qt.AlignCenter | Qt.AlignBottom, "50")
        painter.drawText(self.rect().adjusted(32, self.height() - 52, -32, -14), Qt.AlignRight | Qt.AlignBottom, "100")


class SeverityChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._counts: list[tuple[str, int]] = []
        self.setMinimumHeight(220)

    def set_counts(self, rows: list[tuple[str, int]]) -> None:
        self._counts = rows
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(22, 18, -22, -28)
        painter.fillRect(self.rect(), Qt.transparent)
        max_value = max((value for _, value in self._counts), default=1) or 1
        width = max(18, rect.width() // max(1, len(self._counts) * 2))

        painter.setPen(QPen(QColor("#22374c"), 1))
        for fraction in (0.25, 0.5, 0.75, 1.0):
            y = rect.bottom() - int(rect.height() * fraction)
            painter.drawLine(rect.left(), y, rect.right(), y)

        for index, (label, value) in enumerate(self._counts):
            bar_height = int(rect.height() * (value / max_value)) if max_value else 0
            x = rect.left() + index * width * 2 + width // 2
            y = rect.bottom() - bar_height
            color = QColor(SEVERITY_COLORS.get(label, "#6f89a2"))
            base_rect = QRectF(x, rect.top(), width, rect.height())
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#152536"))
            painter.drawRoundedRect(base_rect, 12, 12)

            bar_rect = QRectF(x, y, width, bar_height)
            painter.setBrush(color)
            painter.drawRoundedRect(bar_rect, 12, 12)
            glow = QPainterPath()
            glow.addRoundedRect(bar_rect.adjusted(-1, -1, 1, 1), 12, 12)
            painter.fillPath(glow, QColor(color.red(), color.green(), color.blue(), 40))

            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(x - 6, rect.bottom() + 14, width + 12, 18, Qt.AlignCenter, label.upper())
            painter.setPen(QColor("#f4f8fd"))
            painter.drawText(x - 6, y - 24, width + 12, 18, Qt.AlignCenter, str(value))


class ModuleScoreChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[str, int]] = []
        self.setMinimumHeight(260)

    def set_rows(self, rows: list[tuple[str, int]]) -> None:
        self._rows = rows
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(18, 24, -18, -18)
        row_height = max(38, rect.height() // max(1, len(self._rows)))

        guide_pen = QPen(QColor("#21364c"), 1)
        painter.setPen(guide_pen)
        chart_left = rect.left() + 170
        chart_right = rect.right() - 48
        for marker in range(0, 101, 25):
            x = chart_left + int((chart_right - chart_left) * (marker / 100))
            painter.drawLine(x, rect.top(), x, rect.bottom())
            painter.drawText(x - 10, rect.top() - 6, 20, 14, Qt.AlignCenter, str(marker))

        for index, (label, risk_score) in enumerate(self._rows):
            protection = max(0, 100 - risk_score)
            y = rect.top() + index * row_height
            bar_rect = QRectF(chart_left, y + 10, chart_right - chart_left, 16)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#17283c"))
            painter.drawRoundedRect(bar_rect, 7, 7)

            color = QColor("#35d1a3" if protection >= 75 else "#1fbad0" if protection >= 50 else "#f5b44c" if protection >= 30 else "#ff5d78")
            fill_width = bar_rect.width() * (protection / 100)
            painter.setBrush(color)
            painter.drawRoundedRect(QRectF(bar_rect.left(), bar_rect.top(), fill_width, bar_rect.height()), 7, 7)

            painter.setPen(QColor("#dfe7f0"))
            painter.drawText(rect.left(), y + 4, 150, 24, Qt.AlignLeft | Qt.AlignVCenter, label)
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(rect.right() - 40, y + 4, 40, 24, Qt.AlignRight | Qt.AlignVCenter, str(protection))


class DetailList(QListWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSelectionMode(QAbstractItemView.NoSelection)

    def set_details(self, rows: Iterable[tuple[str, str]]) -> None:
        self.clear()
        for label, value in rows:
            item = QListWidgetItem(f"{label}: {value}")
            item.setSizeHint(QSize(0, 42))
            self.addItem(item)


class MetadataPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.setAttribute(Qt.WA_StyledBackground, True)
        apply_soft_shadow(self, blur=28, y_offset=10, alpha=80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        self.title = QLabel("Scan Context")
        self.title.setObjectName("SectionTitle")
        layout.addWidget(self.title)
        self.list_widget = DetailList()
        layout.addWidget(self.list_widget)

    def set_payload(self, payload: dict) -> None:
        notes = payload.get("notes", [])
        rows = [
            ("Scan ID", str(payload.get("scan_id", ""))),
            ("Platform", str(payload.get("platform_name", ""))),
            ("User", str(payload.get("username", ""))),
            ("Profile", str(payload.get("user_profile", ""))),
            ("Target paths", str(len(payload.get("target_paths", [])))),
            ("Notes", ", ".join(notes[:2]) if notes else "None"),
        ]
        self.list_widget.set_details(rows)
