"""Injection tools: thin GUI wrapper around aireplay-ng (already in Kali, well-audited)
rather than a custom raw-frame injector.

Gated behind a single session-level authorization checkbox - this only runs
against networks/interfaces you point it at, and it's your responsibility
to only use it where you own the network or hold explicit written
authorization to test it. The checkbox is checked once per session; after
that, one-click actions triggered from the device table/inspector (see
MainWindow._quick_deauth / _quick_handshake) run immediately without a
second per-click prompt, so "one button" from the main page is genuinely
one click - the authorization step is the deliberate friction, not a
confirmation dialog on every action.
"""
from __future__ import annotations

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QSpinBox, QTextEdit, QCheckBox, QGroupBox, QFormLayout, QMessageBox,
)

from ..config import AppConfig

CAPABILITIES_HTML = """
<b>What this card (Alfa AWUS036AXML, MediaTek MT7921AU) can do here:</b>
<ul style="margin-top:4px;">
<li><b>Passive recon</b> - the Devices and Dashboard tabs, and the Map tab for
  wardriving. No injection involved, always safe to leave running.</li>
<li><b>Full packet capture for Wireshark</b> - the main toolbar's Start Capture
  button records a standard .pcapng alongside Kismet's own database
  (see the Dashboard's Storage section for size/location).</li>
<li><b>Injection test</b> - verifies the card can actually inject frames
  (aireplay-ng -9) before you rely on it for anything below.</li>
<li><b>Deauthentication</b> - knocks a client (or all clients) off an AP you
  select, to test how your own network/devices react and reconnect.</li>
<li><b>Handshake capture workflow</b> - deauths a client to force a
  reconnect while capture is running, so the WPA 4-way handshake lands in
  the pcap for offline analysis (e.g. testing your own passphrase strength).</li>
</ul>
<p>The card is tri-band (2.4GHz / 5GHz / 6GHz, Wi-Fi 6E) - whichever band
Kismet has it tuned to is what these actions operate on.</p>
"""


class ToolsPanel(QWidget):
    def __init__(self, cfg: AppConfig, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.process: QProcess | None = None

        layout = QVBoxLayout(self)

        capabilities = QLabel(CAPABILITIES_HTML)
        capabilities.setWordWrap(True)
        capabilities.setStyleSheet("padding: 6px;")
        layout.addWidget(capabilities)

        warning = QLabel(
            "<b>Authorized testing only.</b> Only run these against networks you own "
            "or have explicit written authorization to test. If Kismet is actively "
            "channel-hopping on the same monitor interface used here, injection will "
            "conflict with it - prefer a dedicated interface/adapter for injection, "
            "or pause the Kismet source first."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #e57373; padding: 6px;")
        layout.addWidget(warning)

        form_box = QGroupBox("Target")
        form = QFormLayout(form_box)
        self.iface_edit = QLineEdit(cfg.monitor_interface)
        self.bssid_edit = QLineEdit()
        self.bssid_edit.setPlaceholderText("AP BSSID, e.g. AA:BB:CC:DD:EE:FF")
        self.client_edit = QLineEdit()
        self.client_edit.setPlaceholderText("optional - specific client MAC")
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 1000)
        self.count_spin.setValue(5)
        form.addRow("Monitor interface:", self.iface_edit)
        form.addRow("Target BSSID:", self.bssid_edit)
        form.addRow("Target client (optional):", self.client_edit)
        form.addRow("Deauth packet count:", self.count_spin)
        layout.addWidget(form_box)

        self.authorize_check = QCheckBox(
            "I own this network or have explicit written authorization to test it. "
            "(checked once per session - one-click actions elsewhere in the app rely on this)"
        )
        layout.addWidget(self.authorize_check)

        btn_row = QHBoxLayout()
        self.deauth_btn = QPushButton("Run Deauth")
        self.deauth_btn.clicked.connect(self.run_deauth_now)
        self.handshake_btn = QPushButton("Capture Handshake (deauth + guidance)")
        self.handshake_btn.clicked.connect(self.run_handshake_capture_now)
        self.injtest_btn = QPushButton("Injection Test (-9)")
        self.injtest_btn.clicked.connect(self.run_injection_test_now)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.deauth_btn)
        btn_row.addWidget(self.handshake_btn)
        btn_row.addWidget(self.injtest_btn)
        btn_row.addWidget(self.stop_btn)
        layout.addLayout(btn_row)

        layout.addWidget(QLabel("Output:"))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFontFamily("monospace")
        layout.addWidget(self.output, stretch=1)

    # ---- shared state, used by MainWindow's one-click actions -------------

    def is_authorized(self) -> bool:
        return self.authorize_check.isChecked()

    def set_target(self, bssid: str, client_mac: str = "") -> None:
        self.bssid_edit.setText(bssid)
        self.client_edit.setText(client_mac)

    def _check_authorized(self) -> bool:
        if self.authorize_check.isChecked():
            return True
        QMessageBox.warning(
            self, "Authorization required",
            "Tick the authorization checkbox in the Tools tab first - it only needs "
            "to be done once per session, then one-click actions elsewhere run "
            "immediately without asking again."
        )
        return False

    # ---- process management -------------------------------------------

    def _run_process(self, program: str, args: list[str]) -> bool:
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            QMessageBox.information(self, "Busy", "A tool is already running. Stop it first.")
            return False
        self.output.append(f"$ {program} {' '.join(args)}\n")
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._on_output)
        self.process.finished.connect(self._on_finished)
        self.process.start(program, args)
        self.stop_btn.setEnabled(True)
        return True

    def _on_output(self) -> None:
        if self.process:
            data = bytes(self.process.readAllStandardOutput()).decode(errors="replace")
            self.output.insertPlainText(data)

    def _on_finished(self) -> None:
        self.output.append("\n[process finished]\n")
        self.stop_btn.setEnabled(False)

    def _stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.stop_btn.setEnabled(False)

    # ---- actions - callable directly (buttons) or programmatically --------

    def run_deauth_now(self) -> bool:
        if not self._check_authorized():
            return False
        bssid = self.bssid_edit.text().strip()
        if not bssid:
            QMessageBox.warning(self, "Missing BSSID", "Enter a target BSSID first.")
            return False
        iface = self.iface_edit.text().strip()
        args = ["--deauth", str(self.count_spin.value()), "-a", bssid]
        client = self.client_edit.text().strip()
        if client:
            args += ["-c", client]
        args.append(iface)
        return self._run_process("aireplay-ng", args)

    def run_injection_test_now(self) -> bool:
        if not self._check_authorized():
            return False
        iface = self.iface_edit.text().strip()
        return self._run_process("aireplay-ng", ["-9", iface])

    def run_handshake_capture_now(self) -> bool:
        if not self._check_authorized():
            return False
        if not self.bssid_edit.text().strip():
            QMessageBox.warning(self, "Missing BSSID", "Enter a target BSSID first.")
            return False
        self.output.append(
            "\n--- Handshake capture workflow ---\n"
            "Sending a short deauth burst to force a reconnect. If Start Capture "
            "(pcap recording) is running, the reconnect lands in the .pcapng "
            "automatically - open it in Wireshark afterward and filter on 'eapol' "
            "to check for a complete 4-way handshake.\n"
        )
        return self.run_deauth_now()
