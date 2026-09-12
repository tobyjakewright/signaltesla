"""Detail pane for the currently selected device: friendly summary + raw Kismet JSON,
plus one-click wireless actions (deauth / handshake capture) for the selected device -
these just emit signals; MainWindow wires them to ToolsPanel so there's a single
authorization gate and a single place that actually shells out to aireplay-ng."""
from __future__ import annotations

import json

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QFormLayout,
    QGroupBox, QPushButton,
)

from ..models import DeviceKind, WifiDevice


class InspectorPanel(QWidget):
    # (bssid, client_mac) - client_mac is "" when the target is an AP itself
    # (broadcast/all-clients), and set when the target is a specific client.
    deauth_requested = pyqtSignal(str, str)
    handshake_requested = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        self.title = QLabel("No device selected")
        font = self.title.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 2)
        self.title.setFont(font)
        layout.addWidget(self.title)

        self.actions_box = QGroupBox("Wireless Actions (this device)")
        actions_layout = QHBoxLayout(self.actions_box)
        self.deauth_btn = QPushButton("Deauth")
        self.deauth_btn.setToolTip(
            "Requires authorization to be ticked once in the Tools tab - after that "
            "this runs immediately, no further prompt."
        )
        self.deauth_btn.clicked.connect(self._on_deauth_clicked)
        self.handshake_btn = QPushButton("Capture Handshake")
        self.handshake_btn.setToolTip(
            "Sends a deauth to force a reconnect, so the WPA handshake lands in the "
            "pcap if Start Capture is running. Same authorization gate as Deauth."
        )
        self.handshake_btn.clicked.connect(self._on_handshake_clicked)
        actions_layout.addWidget(self.deauth_btn)
        actions_layout.addWidget(self.handshake_btn)
        layout.addWidget(self.actions_box)
        self.actions_box.setVisible(False)
        self._current_dev: WifiDevice | None = None

        summary_box = QGroupBox("Summary")
        form = QFormLayout(summary_box)
        self._fields: dict[str, QLabel] = {}
        for label in [
            "MAC", "Type", "Standard", "Band / Channel", "Frequency",
            "Encryption", "Manufacturer", "RSSI (last / max)",
            "Client count", "Associated BSSID", "Packets", "Data",
            "First seen", "Last seen", "Location",
        ]:
            value_label = QLabel("-")
            value_label.setWordWrap(True)
            self._fields[label] = value_label
            form.addRow(label + ":", value_label)
        layout.addWidget(summary_box)

        layout.addWidget(QLabel("Raw Kismet record:"))
        self.raw_view = QTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setFontFamily("monospace")
        layout.addWidget(self.raw_view, stretch=1)

    def show_device(self, dev: WifiDevice | None) -> None:
        self._current_dev = dev

        if dev is None:
            self.title.setText("No device selected")
            for lbl in self._fields.values():
                lbl.setText("-")
            self.raw_view.clear()
            self.actions_box.setVisible(False)
            return

        self.title.setText(dev.name)
        f = self._fields
        f["MAC"].setText(dev.mac)
        f["Type"].setText(dev.kind.value)
        f["Standard"].setText(dev.standard.value)
        f["Band / Channel"].setText(f"{dev.band or '-'} / ch {dev.channel or '-'}")
        f["Frequency"].setText(f"{dev.frequency_mhz} MHz" if dev.frequency_mhz else "-")
        f["Encryption"].setText(dev.encryption or "-")
        f["Manufacturer"].setText(dev.manuf or "-")
        last = dev.signal_dbm if dev.signal_dbm is not None else "-"
        mx = dev.signal_max_dbm if dev.signal_max_dbm is not None else "-"
        f["RSSI (last / max)"].setText(f"{last} dBm / {mx} dBm")
        f["Client count"].setText(str(dev.client_count))
        f["Associated BSSID"].setText(dev.bssid or "-")
        f["Packets"].setText(str(dev.packets))
        f["Data"].setText(_fmt_bytes(dev.data_bytes))
        f["First seen"].setText(_fmt_ts(dev.first_seen))
        f["Last seen"].setText(_fmt_ts(dev.last_seen))
        if dev.has_location:
            f["Location"].setText(f"{dev.latitude:.6f}, {dev.longitude:.6f}")
        else:
            f["Location"].setText("No GPS fix recorded")

        self.raw_view.setPlainText(json.dumps(dev.raw, indent=2, default=str))

        if dev.kind == DeviceKind.ACCESS_POINT:
            self.actions_box.setVisible(True)
            self.deauth_btn.setText("Deauth All Clients")
            self.deauth_btn.setEnabled(True)
            self.handshake_btn.setEnabled(True)
        elif dev.kind == DeviceKind.CLIENT and dev.bssid:
            self.actions_box.setVisible(True)
            self.deauth_btn.setText("Deauth This Client")
            self.deauth_btn.setEnabled(True)
            self.handshake_btn.setEnabled(True)
        else:
            self.actions_box.setVisible(True)
            self.deauth_btn.setText("Deauth")
            self.deauth_btn.setEnabled(False)
            self.handshake_btn.setEnabled(False)

    def _target(self) -> tuple[str, str] | None:
        dev = self._current_dev
        if dev is None:
            return None
        if dev.kind == DeviceKind.ACCESS_POINT:
            return dev.mac, ""
        if dev.kind == DeviceKind.CLIENT and dev.bssid:
            return dev.bssid, dev.mac
        return None

    def _on_deauth_clicked(self) -> None:
        target = self._target()
        if target:
            self.deauth_requested.emit(*target)

    def _on_handshake_clicked(self) -> None:
        target = self._target()
        if target:
            self.handshake_requested.emit(*target)


def _fmt_bytes(n: int) -> str:
    if not n:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_ts(ts) -> str:
    if not ts:
        return "-"
    from datetime import datetime
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "-"
