"""Dark desktop theme for the DIPS dashboard."""

from __future__ import annotations


def dashboard_stylesheet() -> str:
    return """
    QWidget {
        background: #09111c;
        color: #e6edf6;
        selection-background-color: #18a9c0;
        selection-color: #03131d;
    }
    QScrollArea {
        background: transparent;
        border: none;
    }
    QMainWindow, QWidget#Root {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 #071018,
            stop: 0.38 #0b1421,
            stop: 0.72 #101a29,
            stop: 1 #111c2c
        );
    }
    QFrame#Sidebar {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 0, y2: 1,
            stop: 0 rgba(8, 15, 24, 0.97),
            stop: 1 rgba(11, 19, 29, 0.97)
        );
        border: 1px solid #1b2738;
        border-radius: 26px;
    }
    QFrame#Topbar, QFrame#Panel, QFrame#Card, QFrame#Section {
        background: qlineargradient(
            x1: 0, y1: 0, x2: 1, y2: 1,
            stop: 0 rgba(13, 23, 36, 0.98),
            stop: 0.56 rgba(10, 18, 29, 0.96),
            stop: 1 rgba(8, 15, 24, 0.97)
        );
        border: 1px solid #203044;
        border-radius: 22px;
    }
    QFrame#Topbar {
        border-radius: 24px;
    }
    QFrame#Card[tone="primary"] {
        border-color: rgba(34, 191, 216, 0.35);
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(13, 28, 41, 0.98), stop:1 rgba(9, 21, 30, 0.95));
    }
    QFrame#Card[tone="warning"] {
        border-color: rgba(248, 184, 74, 0.25);
    }
    QFrame#Card[tone="alert"] {
        border-color: rgba(255, 93, 120, 0.28);
    }
    QFrame#Card[tone="neutral"] {
        border-color: rgba(135, 160, 184, 0.22);
    }
    QLabel#BrandTitle {
        font-size: 30px;
        font-weight: 700;
        color: #f4f8fd;
        letter-spacing: 0.04em;
    }
    QLabel#BrandSubtitle, QLabel#PageSubtitle, QLabel#MutedText {
        color: #8fa4bc;
        line-height: 1.35;
    }
    QLabel#BrandChip, QLabel#SidebarSectionTitle {
        color: #80dbe9;
        background: rgba(24, 169, 192, 0.12);
        border: 1px solid rgba(24, 169, 192, 0.28);
        border-radius: 999px;
        padding: 4px 10px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }
    QFrame#SidebarMetric {
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 rgba(16, 31, 46, 0.98),
            stop:1 rgba(12, 21, 32, 0.96)
        );
        border: 1px solid rgba(34, 191, 216, 0.2);
        border-radius: 20px;
    }
    QFrame#InlineMetric {
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:1,
            stop:0 rgba(11, 23, 34, 0.98),
            stop:1 rgba(8, 17, 27, 0.94)
        );
        border: 1px solid #1e3246;
        border-radius: 16px;
    }
    QLabel#SidebarMetricValue {
        font-size: 36px;
        font-weight: 700;
        color: #f6fbff;
    }
    QLabel#SidebarMetricLabel {
        color: #8fa4bc;
        font-size: 12px;
        font-weight: 600;
    }
    QLabel#PageTitle {
        font-size: 30px;
        font-weight: 700;
        color: #f4f8fd;
        letter-spacing: 0.02em;
    }
    QPushButton#NavButton {
        text-align: left;
        padding: 16px 18px;
        border-radius: 18px;
        border: 1px solid transparent;
        background: rgba(10, 18, 28, 0.4);
        color: #d5deeb;
        font-size: 14px;
        font-weight: 600;
    }
    QPushButton#NavButton:hover {
        background: rgba(21, 36, 53, 0.98);
        border-color: #274058;
    }
    QPushButton#NavButton:checked {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(19, 108, 126, 0.42), stop:1 rgba(13, 31, 44, 0.96));
        border-color: rgba(35, 196, 220, 0.52);
        color: #f6fbff;
    }
    QPushButton#PrimaryButton, QPushButton#SecondaryButton, QPushButton#InlineButton {
        min-height: 44px;
        border-radius: 14px;
        padding: 0 18px;
        font-weight: 600;
        border: 1px solid #22374c;
    }
    QPushButton#PrimaryButton {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1aa9c2, stop:1 #35d1a3);
        color: #04141d;
        border-color: #46d8ec;
    }
    QPushButton#PrimaryButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #24b4ce, stop:1 #43ddb0);
    }
    QPushButton#SecondaryButton, QPushButton#InlineButton {
        background: rgba(15, 25, 39, 0.98);
        color: #dbe5f0;
    }
    QPushButton#SecondaryButton:hover, QPushButton#InlineButton:hover {
        background: rgba(23, 38, 58, 0.98);
    }
    QLabel#CardTitle {
        color: #8fa4bc;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.12em;
        text-transform: uppercase;
    }
    QLabel#CardToneBadge {
        font-size: 10px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
    }
    QLabel#CardValue {
        font-size: 34px;
        font-weight: 700;
        color: #f4f8fd;
    }
    QLabel#CardSubtitle {
        color: #90a4ba;
        font-size: 12px;
        line-height: 1.35;
    }
    QLabel#InlineMetricLabel {
        color: #85a2be;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }
    QLabel#InlineMetricValue {
        color: #f6fbff;
        font-size: 22px;
        font-weight: 700;
    }
    QLabel#CardAccent {
        min-height: 5px;
        max-height: 5px;
        border-radius: 3px;
    }
    QLabel#SectionTitle {
        font-size: 18px;
        font-weight: 700;
        color: #f3f7fc;
    }
    QLabel#SectionSubtitle {
        color: #90a4ba;
        font-size: 12px;
        line-height: 1.35;
    }
    QLabel#StatusBadge {
        padding: 7px 12px;
        border-radius: 999px;
        background: rgba(24, 169, 192, 0.14);
        border: 1px solid rgba(24, 169, 192, 0.32);
        color: #9ee7f2;
        font-weight: 600;
    }
    QLabel#SeverityBadge {
        padding: 5px 12px;
        border-radius: 999px;
        font-weight: 700;
        color: #06131c;
        font-size: 11px;
        letter-spacing: 0.08em;
    }
    QLabel#SeverityBadge[severity="info"] { background: rgba(79, 135, 255, 0.18); border: 1px solid rgba(79, 135, 255, 0.42); color: #c8d9ff; }
    QLabel#SeverityBadge[severity="low"] { background: rgba(47, 191, 113, 0.18); border: 1px solid rgba(47, 191, 113, 0.36); color: #abefc6; }
    QLabel#SeverityBadge[severity="medium"] { background: rgba(245, 165, 36, 0.18); border: 1px solid rgba(245, 165, 36, 0.36); color: #ffd89b; }
    QLabel#SeverityBadge[severity="high"] { background: rgba(255, 107, 61, 0.18); border: 1px solid rgba(255, 107, 61, 0.34); color: #ffc4b3; }
    QLabel#SeverityBadge[severity="critical"] { background: rgba(255, 77, 109, 0.18); border: 1px solid rgba(255, 77, 109, 0.38); color: #ffbdc9; }
    QLabel#PriorityBadge {
        padding: 5px 12px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.08em;
    }
    QLabel#PriorityBadge[priority="p1"] { background: rgba(255, 77, 109, 0.18); border: 1px solid rgba(255, 77, 109, 0.4); color: #ffbdc9; }
    QLabel#PriorityBadge[priority="p2"] { background: rgba(255, 107, 61, 0.18); border: 1px solid rgba(255, 107, 61, 0.34); color: #ffc4b3; }
    QLabel#PriorityBadge[priority="p3"] { background: rgba(245, 165, 36, 0.18); border: 1px solid rgba(245, 165, 36, 0.34); color: #ffd89b; }
    QLabel#PriorityBadge[priority="p4"] { background: rgba(79, 135, 255, 0.18); border: 1px solid rgba(79, 135, 255, 0.34); color: #d1ddff; }
    QProgressBar {
        border: 1px solid #23384c;
        border-radius: 9px;
        background: rgba(7, 14, 23, 0.95);
        min-height: 14px;
        max-height: 14px;
    }
    QProgressBar::chunk {
        border-radius: 8px;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #18a9c0, stop:0.55 #28bfd1, stop:1 #35d1a3);
    }
    QTableWidget, QListWidget, QTreeWidget, QTextEdit, QPlainTextEdit, QListView {
        background: rgba(8, 17, 27, 0.96);
        alternate-background-color: rgba(12, 22, 34, 0.96);
        border: 1px solid #1c2c3f;
        border-radius: 16px;
        gridline-color: transparent;
        color: #e1e8f1;
    }
    QTableWidget::item {
        padding: 12px;
        border-bottom: 1px solid rgba(32, 50, 69, 0.65);
    }
    QTableWidget::item:selected, QListWidget::item:selected {
        background: rgba(24, 169, 192, 0.14);
        color: #f5fbff;
    }
    QHeaderView::section {
        background: rgba(12, 22, 35, 0.98);
        color: #95a8bc;
        border: none;
        border-bottom: 1px solid #21364a;
        padding: 12px;
        font-weight: 700;
    }
    QTableCornerButton::section {
        background: rgba(12, 22, 35, 0.98);
        border: none;
        border-bottom: 1px solid #21364a;
    }
    QListWidget::item {
        padding: 12px 14px;
        margin: 4px 6px;
        border-radius: 12px;
    }
    QLineEdit, QSpinBox, QListWidget#SettingsList, QAbstractSpinBox, QComboBox {
        background: rgba(9, 18, 30, 0.92);
        border: 1px solid #203043;
        border-radius: 14px;
        padding: 10px 12px;
        color: #e6edf6;
    }
    QLineEdit:focus, QSpinBox:focus, QAbstractSpinBox:focus, QComboBox:focus {
        border-color: #18a9c0;
    }
    QComboBox::drop-down {
        border: none;
        width: 26px;
    }
    QComboBox QAbstractItemView {
        background: rgba(8, 17, 27, 0.98);
        color: #e6edf6;
        border: 1px solid #203043;
        selection-background-color: rgba(24, 169, 192, 0.18);
    }
    QCheckBox {
        border: none;
        padding: 6px 0;
        spacing: 8px;
        color: #d7e2ee;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 6px;
        border: 1px solid #294159;
        background: rgba(10, 18, 29, 0.98);
    }
    QCheckBox::indicator:checked {
        background: #18a9c0;
        border-color: #18a9c0;
    }
    QScrollArea {
        border: none;
    }
    QScrollBar:vertical {
        background: transparent;
        width: 10px;
        margin: 4px;
    }
    QScrollBar::handle:vertical {
        background: #274058;
        border-radius: 5px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: transparent;
        border: none;
    }
    """
