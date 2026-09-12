"""Minimal BLE panel for the optional legacy PyQt interface.

The full WCH capture, device analysis, RSSI graph, and packet inspector live
in the primary web UI. This panel remains an extension point for users who
still launch the legacy desktop application.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView

from ..ble.provider import BleProvider, NullBleProvider
from ..models import BleDevice

COLUMNS = ["Name", "Address", "Type", "RSSI", "Manufacturer", "Last Seen"]


class BlePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.provider: BleProvider = NullBleProvider()
        self._devices: dict[str, BleDevice] = {}

        layout = QVBoxLayout(self)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)

        self._refresh_status()

    def set_provider(self, provider: BleProvider) -> None:
        if self.provider.is_running:
            self.provider.stop()
        self.provider = provider
        self._refresh_status()

    def _refresh_status(self) -> None:
        if isinstance(self.provider, NullBleProvider):
            self.status_label.setText(
                "No BLE provider is configured in this legacy view.\n\n"
                "Launch the WirelessBOSS web interface for WCH BLE Analyzer Pro "
                "capture, device statistics, RSSI history, and packet analysis."
            )
        else:
            state = "running" if self.provider.is_running else "stopped"
            self.status_label.setText(f"BLE source: {self.provider.display_name} ({state})")

    def on_ble_device(self, dev: BleDevice) -> None:
        self._devices[dev.address] = dev
        self._render()

    def _render(self) -> None:
        devices = list(self._devices.values())
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            values = [
                dev.name or "(unknown)",
                dev.address,
                dev.address_type or "-",
                str(dev.rssi) if dev.rssi is not None else "-",
                dev.manuf or "-",
                "" if not dev.last_seen else str(dev.last_seen),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)
