"""Dashboard chart widgets."""

from __future__ import annotations

from datetime import datetime
from math import cos, pi, sin

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from dips.gui.state import MODULE_META, SEVERITY_COLORS
from dips.gui.widgets import ModuleScoreChart, SeverityChart


def _severity_color(name: str, *, alpha: int = 255) -> QColor:
    color = QColor(SEVERITY_COLORS.get(name, "#6f89a2"))
    color.setAlpha(max(0, min(255, alpha)))
    return color


def _mix(a: float, b: float, factor: float) -> float:
    return a + ((b - a) * factor)


class AnimatedChartWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._progress = 1.0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(420)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.valueChanged.connect(self._on_animation)

    def animate_refresh(self) -> None:
        self._animation.stop()
        self._progress = 0.0
        self._animation.start()

    def _on_animation(self, value: object) -> None:
        try:
            self._progress = float(value)
        except (TypeError, ValueError):
            self._progress = 1.0
        self.update()


class SeverityDistributionChart(SeverityChart):
    """Named wrapper for the dashboard severity distribution chart."""


class RiskDistributionChart(ModuleScoreChart):
    """Named wrapper for the module risk distribution chart."""


class ExposureTimelineChart(AnimatedChartWidget):
    """Timeline chart for recent scan history and risk movement."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._points: list[dict[str, str | int]] = []
        self.setMinimumHeight(250)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_points(self, points: list[dict[str, str | int]]) -> None:
        self._points = list(points)
        self.animate_refresh()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(20, 22, -20, -28)
        painter.fillRect(self.rect(), Qt.transparent)
        if not self._points:
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(rect, Qt.AlignCenter, "Run multiple scans to populate the risk trend graph.")
            return

        chart_left = rect.left() + 28
        chart_right = rect.right() - 28
        chart_top = rect.top() + 18
        chart_bottom = rect.bottom() - 34
        chart_width = max(1, chart_right - chart_left)
        chart_height = max(1, chart_bottom - chart_top)

        painter.setPen(QPen(QColor("#213548"), 1))
        for marker in range(0, 101, 25):
            y = chart_bottom - int(chart_height * (marker / 100))
            painter.drawLine(chart_left, y, chart_right, y)
            painter.setPen(QColor("#71859b"))
            painter.drawText(chart_left - 22, y - 8, 18, 16, Qt.AlignRight | Qt.AlignVCenter, str(marker))
            painter.setPen(QPen(QColor("#213548"), 1))

        if len(self._points) == 1:
            positions = [chart_left + (chart_width // 2)]
        else:
            step = chart_width / max(1, len(self._points) - 1)
            positions = [int(chart_left + (index * step)) for index in range(len(self._points))]

        path = QPainterPath()
        fill_path = QPainterPath()
        accent = QColor("#22bfd8")
        fill = QColor(34, 191, 216, 42)

        for index, point in enumerate(self._points):
            score = max(0, min(100, int(point.get("overall_score", 0))))
            x = positions[index]
            target_y = chart_bottom - int(chart_height * (score / 100))
            animated_y = _mix(chart_bottom, target_y, self._progress)
            if index == 0:
                path.moveTo(x, animated_y)
                fill_path.moveTo(x, chart_bottom)
                fill_path.lineTo(x, animated_y)
            else:
                path.lineTo(x, animated_y)
                fill_path.lineTo(x, animated_y)

        fill_path.lineTo(positions[-1], chart_bottom)
        fill_path.closeSubpath()
        painter.fillPath(fill_path, fill)

        painter.setPen(QPen(accent, 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(path)

        latest_score = int(self._points[-1].get("overall_score", 0))
        previous_score = int(self._points[-2].get("overall_score", latest_score)) if len(self._points) > 1 else latest_score
        delta = latest_score - previous_score
        delta_color = QColor("#ff6b3d" if delta > 0 else "#35d1a3" if delta < 0 else "#8fa4bc")
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(13, 26, 39, 214))
        painter.drawRoundedRect(QRectF(rect.right() - 168, rect.top(), 148, 34), 16, 16)
        painter.setPen(QColor("#dce6f2"))
        painter.drawText(rect.right() - 154, rect.top() + 23, f"Current {latest_score}")
        painter.setPen(delta_color)
        painter.drawText(rect.right() - 72, rect.top() + 23, f"{delta:+d}")

        for index, point in enumerate(self._points):
            score = max(0, min(100, int(point.get("overall_score", 0))))
            x = positions[index]
            target_y = chart_bottom - int(chart_height * (score / 100))
            y = _mix(chart_bottom, target_y, self._progress)
            point_color = QColor("#ff5d78" if score >= 70 else "#f5b44c" if score >= 40 else "#35d1a3")
            painter.setPen(Qt.NoPen)
            painter.setBrush(point_color)
            painter.drawEllipse(QRectF(x - 5, y - 5, 10, 10))
            if self._progress > 0.55:
                painter.setPen(QColor("#f4f8fd"))
                painter.drawText(x - 18, int(y) - 28, 36, 16, Qt.AlignCenter, str(score))

            label = str(point.get("label", point.get("scan_id", "")))
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(x - 42, chart_bottom + 10, 84, 18, Qt.AlignCenter, label)

    @staticmethod
    def compact_label(timestamp: str, scan_id: str) -> str:
        if timestamp:
            try:
                return datetime.fromisoformat(timestamp).strftime("%m-%d")
            except ValueError:
                pass
        return scan_id[:6]


class SeverityHeatmapChart(AnimatedChartWidget):
    """SOC-style severity heatmap across active modules."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, object]] = []
        self.setMinimumHeight(250)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_rows(self, rows: list[dict[str, object]]) -> None:
        self._rows = list(rows)
        self.animate_refresh()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(18, 18, -18, -20)
        if not self._rows:
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(rect, Qt.AlignCenter, "No module findings are available for the severity heatmap.")
            return

        visible_rows = self._rows[:8]
        max_value = max((max(row.get("values", [0]) or [0]) for row in visible_rows), default=1) or 1
        label_width = 138
        total_width = 40
        header_height = 28
        cell_gap = 8
        row_height = max(24, min(34, (rect.height() - header_height) // max(1, len(visible_rows))))
        cell_width = max(28, int((rect.width() - label_width - total_width - (cell_gap * 6)) / 5))

        severities = ["info", "low", "medium", "high", "critical"]
        for column, severity in enumerate(severities):
            x = rect.left() + label_width + (column * (cell_width + cell_gap))
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(x, rect.top(), cell_width, header_height, Qt.AlignCenter, severity.upper())

        painter.setPen(QColor("#8fa4bc"))
        painter.drawText(rect.right() - total_width, rect.top(), total_width, header_height, Qt.AlignCenter, "TOT")

        for row_index, row in enumerate(visible_rows):
            top = rect.top() + header_height + (row_index * row_height)
            label = str(row.get("label", ""))
            painter.setPen(QColor("#dbe5ef"))
            painter.drawText(rect.left(), top, label_width - 8, row_height - 6, Qt.AlignLeft | Qt.AlignVCenter, label)

            values = [int(value) for value in row.get("values", [])]
            for column, severity in enumerate(severities):
                x = rect.left() + label_width + (column * (cell_width + cell_gap))
                value = values[column] if column < len(values) else 0
                cell_rect = QRectF(x, top, cell_width, row_height - 6)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor("#142434"))
                painter.drawRoundedRect(cell_rect, 10, 10)
                if value > 0:
                    intensity = min(1.0, value / max_value)
                    color = _severity_color(severity, alpha=int(_mix(48, 220, intensity * self._progress)))
                    painter.setBrush(color)
                    painter.drawRoundedRect(cell_rect.adjusted(1.5, 1.5, -1.5, -1.5), 9, 9)
                    painter.setPen(QColor("#f6fbff"))
                    painter.drawText(cell_rect.toRect(), Qt.AlignCenter, str(value))
                else:
                    painter.setPen(QColor("#4c657d"))
                    painter.drawText(cell_rect.toRect(), Qt.AlignCenter, "0")

            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(
                rect.right() - total_width,
                top,
                total_width,
                row_height - 6,
                Qt.AlignCenter,
                str(int(row.get("total", 0))),
            )


class IdentityExposureMapChart(AnimatedChartWidget):
    """Maps identity exposure signals to the main identity surface zones."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._nodes: list[dict[str, object]] = []
        self.setMinimumHeight(310)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_nodes(self, nodes: list[dict[str, object]]) -> None:
        self._nodes = list(nodes)
        self.animate_refresh()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(18, 18, -18, -18)
        if not self._nodes:
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(rect, Qt.AlignCenter, "Run a scan to populate the identity exposure map.")
            return

        center = QPointF(rect.center())
        zone_positions = {
            "breach": QPointF(rect.left() + rect.width() * 0.22, rect.top() + rect.height() * 0.2),
            "storage": QPointF(rect.left() + rect.width() * 0.19, rect.top() + rect.height() * 0.58),
            "credential": QPointF(rect.left() + rect.width() * 0.48, rect.top() + rect.height() * 0.16),
            "browser": QPointF(rect.left() + rect.width() * 0.77, rect.top() + rect.height() * 0.28),
            "messaging": QPointF(rect.left() + rect.width() * 0.78, rect.top() + rect.height() * 0.6),
            "network": QPointF(rect.left() + rect.width() * 0.5, rect.top() + rect.height() * 0.82),
        }
        zone_labels = {
            "breach": "BREACH",
            "storage": "LOCAL",
            "credential": "CREDENTIALS",
            "browser": "BROWSER",
            "messaging": "PHISHING",
            "network": "NETWORK",
        }

        painter.setPen(QPen(QColor("#15364a"), 1.5))
        for point in zone_positions.values():
            painter.drawLine(center, point)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(14, 26, 39, 228))
        painter.drawEllipse(QRectF(center.x() - 52, center.y() - 52, 104, 104))
        painter.setPen(QColor("#e8f1fa"))
        core_font = QFont(self.font())
        core_font.setPointSize(11)
        core_font.setBold(True)
        painter.setFont(core_font)
        painter.drawText(QRectF(center.x() - 60, center.y() - 24, 120, 48), Qt.AlignCenter, "IDENTITY\nCORE")

        grouped: dict[str, list[dict[str, object]]] = {}
        for node in self._nodes:
            zone = str(node.get("zone", "storage"))
            grouped.setdefault(zone, []).append(node)

        label_font = QFont(self.font())
        label_font.setPointSize(8)
        for zone, point in zone_positions.items():
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(16, 33, 49, 204))
            painter.drawEllipse(QRectF(point.x() - 28, point.y() - 28, 56, 56))
            painter.setPen(QColor("#89a7c3"))
            painter.setFont(label_font)
            painter.drawText(QRectF(point.x() - 42, point.y() - 10, 84, 22), Qt.AlignCenter, zone_labels[zone])

            nodes = grouped.get(zone, [])
            if not nodes:
                continue
            ring = 48
            for index, node in enumerate(nodes):
                angle = (-pi / 2) + ((2 * pi) * (index / max(1, len(nodes))))
                radius = ring + (index % 2) * 16
                animated_radius = radius * self._progress
                node_center = QPointF(
                    point.x() + (cos(angle) * animated_radius),
                    point.y() + (sin(angle) * animated_radius),
                )
                severity = str(node.get("severity", "info"))
                weight = max(16, min(26, int(node.get("weight", 24)) // 4))
                node_rect = QRectF(
                    node_center.x() - weight,
                    node_center.y() - weight,
                    weight * 2,
                    weight * 2,
                )
                painter.setPen(QPen(_severity_color(severity, alpha=180), 1.4))
                painter.drawLine(point, node_center)
                painter.setPen(Qt.NoPen)
                painter.setBrush(_severity_color(severity, alpha=215))
                painter.drawEllipse(node_rect)
                painter.setPen(QColor("#f5fbff"))
                painter.drawText(
                    QRectF(node_center.x() - 48, node_center.y() + weight + 4, 96, 28),
                    Qt.AlignHCenter | Qt.AlignTop,
                    str(node.get("label", "")),
                )


class AlertCorrelationChart(AnimatedChartWidget):
    """Visual correlation map across detected alert clusters and modules."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._clusters: list[dict[str, object]] = []
        self.setMinimumHeight(310)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_clusters(self, clusters: list[dict[str, object]]) -> None:
        self._clusters = list(clusters)
        self.animate_refresh()

    def paintEvent(self, event) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(18, 18, -18, -18)
        if not self._clusters:
            painter.setPen(QColor("#8fa4bc"))
            painter.drawText(rect, Qt.AlignCenter, "Correlation becomes active when multiple modules align on a pattern.")
            return

        clusters = self._clusters[:6]
        modules = sorted(
            {
                module
                for cluster in clusters
                for module in cluster.get("modules", [])
                if isinstance(module, str) and module.strip()
            }
        )
        left = rect.left() + 10
        right = rect.right() - 10
        cluster_x = left
        module_x = right - 122
        usable_height = rect.height() - 20

        module_positions: dict[str, QPointF] = {}
        for index, module_name in enumerate(modules):
            y = rect.top() + 18 + (usable_height * ((index + 0.5) / max(1, len(modules))))
            position = QPointF(module_x + 64, y)
            module_positions[module_name] = position
            pill_rect = QRectF(module_x, y - 16, 122, 32)
            painter.setPen(QPen(QColor("#2a445a"), 1.2))
            painter.setBrush(QColor(14, 28, 42, 230))
            painter.drawRoundedRect(pill_rect, 15, 15)
            painter.setPen(QColor("#d6e3f0"))
            title = MODULE_META.get(module_name, {}).get("title", module_name.replace("_", " ").title())
            painter.drawText(pill_rect.toRect().adjusted(12, 0, -12, 0), Qt.AlignVCenter, title)

        for index, cluster in enumerate(clusters):
            y = rect.top() + 18 + (usable_height * ((index + 0.5) / max(1, len(clusters))))
            width = 218
            height = 58
            card_rect = QRectF(cluster_x, y - height / 2, width, height)
            severity = str(cluster.get("severity", "medium"))
            severity_color = _severity_color(severity, alpha=255)
            painter.setPen(QPen(severity_color, 1.5))
            painter.setBrush(QColor(11, 23, 35, 238))
            painter.drawRoundedRect(card_rect, 18, 18)

            painter.setPen(QColor("#f4f8fd"))
            title_font = QFont(self.font())
            title_font.setPointSize(9)
            title_font.setBold(True)
            painter.setFont(title_font)
            painter.drawText(card_rect.adjusted(14, 10, -54, -28).toRect(), Qt.AlignLeft | Qt.AlignVCenter, str(cluster.get("label", "")))

            painter.setPen(QColor("#89a7c3"))
            meta_font = QFont(self.font())
            meta_font.setPointSize(8)
            painter.setFont(meta_font)
            painter.drawText(
                card_rect.adjusted(14, 30, -54, -10).toRect(),
                Qt.AlignLeft | Qt.AlignVCenter,
                f"{int(cluster.get('event_count', 0))} correlated events",
            )

            score_rect = QRectF(card_rect.right() - 42, card_rect.top() + 10, 28, 28)
            painter.setPen(Qt.NoPen)
            painter.setBrush(severity_color)
            painter.drawEllipse(score_rect)
            painter.setPen(QColor("#05121a"))
            painter.drawText(score_rect.toRect(), Qt.AlignCenter, str(int(cluster.get("event_count", 0))))

            start_point = QPointF(card_rect.right(), card_rect.center().y())
            modules_for_cluster = [
                module for module in cluster.get("modules", []) if isinstance(module, str) and module in module_positions
            ]
            for module_name in modules_for_cluster:
                end_point = module_positions[module_name]
                animated_end = QPointF(
                    _mix(start_point.x(), end_point.x(), self._progress),
                    _mix(start_point.y(), end_point.y(), self._progress),
                )
                path = QPainterPath(start_point)
                mid_x = _mix(start_point.x(), animated_end.x(), 0.5)
                path.cubicTo(
                    QPointF(mid_x, start_point.y()),
                    QPointF(mid_x, animated_end.y()),
                    animated_end,
                )
                painter.setPen(QPen(_severity_color(severity, alpha=130), 2))
                painter.drawPath(path)


__all__ = [
    "AlertCorrelationChart",
    "ExposureTimelineChart",
    "IdentityExposureMapChart",
    "RiskDistributionChart",
    "SeverityDistributionChart",
    "SeverityHeatmapChart",
]
