"""WirelessBOSS entry point.

Assumes Kismet is already running (see setup/README.md) with the Alfa
AWUS036AXML configured as a source in monitor mode. This process is just
the GUI - it never touches the wireless interface directly except in the
Tools tab, which shells out to aireplay-ng, and the Start/Stop Capture
control, which starts/stops the Kismet process itself.
"""
from __future__ import annotations

import sys

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

from .config import load_config
from .gui.main_window import MainWindow


def _apply_dark_theme(app: QApplication) -> None:
    """Matches the dashboard's dark palette so native Qt widgets (table,
    toolbar, tabs) don't clash against the embedded web views."""
    app.setStyle("Fusion")
    palette = QPalette()
    bg = QColor("#0d1420")
    base = QColor("#16202e")
    alt_base = QColor("#1a2536")
    text = QColor("#e6edf3")
    muted = QColor("#8fa3bb")
    accent = QColor("#4fc3f7")
    border = QColor("#223047")

    palette.setColor(QPalette.ColorRole.Window, bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, alt_base)
    palette.setColor(QPalette.ColorRole.ToolTipBase, base)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, base)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#e53935"))
    palette.setColor(QPalette.ColorRole.Link, accent)
    palette.setColor(QPalette.ColorRole.Highlight, accent)
    palette.setColor(QPalette.ColorRole.HighlightedText, bg)
    palette.setColor(QPalette.ColorRole.PlaceholderText, muted)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, muted)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, muted)
    app.setPalette(palette)

    app.setStyleSheet(f"""
        QToolBar {{ background: {base.name()}; border: none; padding: 4px; spacing: 6px; }}
        QHeaderView::section {{
            background: {base.name()}; color: {muted.name()}; padding: 6px;
            border: none; border-bottom: 1px solid {border.name()};
        }}
        QTableView {{ gridline-color: {border.name()}; selection-background-color: {accent.name()}; }}
        QTabWidget::pane {{ border: 1px solid {border.name()}; }}
        QTabBar::tab {{ background: {base.name()}; padding: 8px 16px; }}
        QTabBar::tab:selected {{ background: {alt_base.name()}; color: {accent.name()}; }}
        QPushButton {{ background: {alt_base.name()}; border: 1px solid {border.name()};
                       border-radius: 4px; padding: 5px 12px; }}
        QPushButton:hover {{ border-color: {accent.name()}; }}
        QStatusBar {{ background: {base.name()}; }}
    """)


def main() -> int:
    cfg = load_config()
    app = QApplication(sys.argv)
    app.setApplicationName("WirelessBOSS")
    _apply_dark_theme(app)
    window = MainWindow(cfg)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
