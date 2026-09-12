"""Kismet alerts feed (rogue APs, deauth floods, known-attack signatures, etc.)."""
from __future__ import annotations

from datetime import datetime

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QListWidgetItem


class AlertsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.list = QListWidget()
        layout.addWidget(self.list)
        self._seen_keys: set[str] = set()

    def add_alerts(self, alerts: list[dict]) -> None:
        for alert in alerts:
            ts = alert.get("kismet.alert.timestamp")
            header = alert.get("kismet.alert.header", "ALERT")
            text = alert.get("kismet.alert.text", "")
            key = f"{ts}:{header}:{text}"
            if key in self._seen_keys:
                continue
            self._seen_keys.add(key)

            when = ""
            if ts:
                try:
                    when = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                except (OSError, OverflowError, ValueError):
                    pass
            item = QListWidgetItem(f"[{when}] {header}: {text}")
            self.list.insertItem(0, item)

        while self.list.count() > 500:
            self.list.takeItem(self.list.count() - 1)

    def clear(self) -> None:
        self.list.clear()
        self._seen_keys.clear()
