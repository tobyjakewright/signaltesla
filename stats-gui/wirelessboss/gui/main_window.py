from __future__ import annotations

import subprocess
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QSplitter, QTableView,
    QLineEdit, QComboBox, QLabel, QTabWidget, QStatusBar, QHeaderView,
    QToolBar, QSpinBox, QCheckBox, QPushButton, QMessageBox,
)

from .. import capture_control
from ..config import AppConfig
from ..export import export_csv
from ..kismet_client import KismetClient
from ..models import DeviceKind, GpsFix, WifiDevice
from ..stats import compute_stats, sorted_manufacturers
from ..storage_stats import StorageMonitor, StorageStats
from ..tile_server import TileServer
from .device_table import DeviceTableModel, DeviceFilterProxy
from .map_view import MapView
from .dashboard_view import DashboardView
from .inspector_panel import InspectorPanel
from .ble_panel import BlePanel
from .alerts_panel import AlertsPanel
from .tools_panel import ToolsPanel


class PollWorker(QThread):
    """Runs Kismet REST polling + local capture/storage checks off the GUI
    thread so the UI never stalls on a slow request or a subprocess call."""
    devices_ready = pyqtSignal(list)
    gps_ready = pyqtSignal(object)
    alerts_ready = pyqtSignal(list)
    connection_state = pyqtSignal(bool)
    storage_ready = pyqtSignal(bool, object)  # (capture_running, StorageStats)

    def __init__(self, client: KismetClient, storage_monitor: StorageMonitor, interval_sec: float, parent=None):
        super().__init__(parent)
        self.client = client
        self.storage_monitor = storage_monitor
        self.interval_sec = interval_sec
        self._running = True

    def run(self) -> None:
        while self._running:
            reachable = self.client.is_reachable()
            self.connection_state.emit(reachable)
            if reachable:
                self.devices_ready.emit(self.client.get_devices())
                self.gps_ready.emit(self.client.get_gps())
                self.alerts_ready.emit(self.client.get_alerts())

            self.storage_ready.emit(capture_control.is_running(), self.storage_monitor.sample())
            self.msleep(int(self.interval_sec * 1000))

    def stop(self) -> None:
        self._running = False


class MainWindow(QMainWindow):
    def __init__(self, cfg: AppConfig):
        super().__init__()
        self.cfg = cfg
        self.setWindowTitle("WirelessBOSS")
        self.resize(1500, 950)

        self.client = KismetClient(cfg)
        self.storage_monitor = StorageMonitor(
            Path(cfg.storage.capture_dir), cfg.storage.history_window_sec
        )

        self.tile_server = TileServer(Path(cfg.map.tiles_dir), cfg.map.tile_port)
        self.tile_server.start()

        self._known_manufs: set[str] = set()
        self._last_devices: list[WifiDevice] = []
        self._last_kismet_connected = False
        self._last_capture_running = False
        self._last_storage = StorageStats(0, 0, 0, 0, 0, 0, 0, None, None)
        self._last_gps: GpsFix | None = None
        self._paused = False

        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        self.worker = PollWorker(self.client, self.storage_monitor, cfg.poll_interval_sec, self)
        self.worker.devices_ready.connect(self._on_devices)
        self.worker.gps_ready.connect(self._on_gps)
        self.worker.alerts_ready.connect(self._on_alerts)
        self.worker.connection_state.connect(self._on_connection_state)
        self.worker.storage_ready.connect(self._on_storage)
        self.worker.start()

    # ---- UI construction -------------------------------------------------

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.capture_btn = QPushButton("Start Capture")
        self.capture_btn.setToolTip("Starts/stops Kismet itself - controls kismetdb + pcap recording together.")
        self.capture_btn.clicked.connect(self._toggle_capture)
        toolbar.addWidget(self.capture_btn)

        self.pause_btn = QPushButton("Pause View")
        self.pause_btn.setToolTip(
            "Freezes the table/dashboard so you can inspect what's captured so far.\n"
            "Kismet keeps capturing in the background regardless - this only pauses the display."
        )
        self.pause_btn.setCheckable(True)
        self.pause_btn.clicked.connect(self._toggle_pause)
        toolbar.addWidget(self.pause_btn)

        self.clear_btn = QPushButton("Clear View")
        self.clear_btn.setToolTip(
            "Clears the device table/map/alerts/dashboard in WirelessBOSS only.\n"
            "Does not delete kismetdb/pcap files or reset Kismet's own device cache."
        )
        self.clear_btn.clicked.connect(self._clear_view)
        toolbar.addWidget(self.clear_btn)

        toolbar.addSeparator()

        self.export_btn = QPushButton("Export CSV")
        self.export_btn.setToolTip("Writes all_devices.csv / access_points.csv / clients.csv for what's currently shown.")
        self.export_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(self.export_btn)

        self.open_folder_btn = QPushButton("Open Capture Folder")
        self.open_folder_btn.setToolTip("Opens the folder containing kismetdb, pcap, and CSV export files.")
        self.open_folder_btn.clicked.connect(self._open_capture_folder)
        toolbar.addWidget(self.open_folder_btn)

        toolbar.addSeparator()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search name / MAC / manufacturer / encryption...")
        self.search_edit.setMinimumWidth(240)
        self.search_edit.textChanged.connect(self._apply_filters)
        toolbar.addWidget(QLabel(" Search: "))
        toolbar.addWidget(self.search_edit)

        self.kind_combo = QComboBox()
        self.kind_combo.addItem("All types", None)
        for kind in DeviceKind:
            self.kind_combo.addItem(kind.value, kind)
        self.kind_combo.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(QLabel("  Type: "))
        toolbar.addWidget(self.kind_combo)

        self.manuf_combo = QComboBox()
        self.manuf_combo.addItem("All manufacturers", None)
        self.manuf_combo.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(QLabel("  Manufacturer: "))
        toolbar.addWidget(self.manuf_combo)

        self.band_combo = QComboBox()
        self.band_combo.addItem("All bands", None)
        for band in ["2.4GHz", "5GHz", "6GHz"]:
            self.band_combo.addItem(band, band)
        self.band_combo.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(QLabel("  Band: "))
        toolbar.addWidget(self.band_combo)

        self.min_rssi_spin = QSpinBox()
        self.min_rssi_spin.setRange(-100, 0)
        self.min_rssi_spin.setValue(-100)
        self.min_rssi_spin.valueChanged.connect(self._apply_filters)
        toolbar.addWidget(QLabel("  Min RSSI: "))
        toolbar.addWidget(self.min_rssi_spin)

        self.open_only_check = QCheckBox("Open networks only")
        self.open_only_check.stateChanged.connect(self._apply_filters)
        toolbar.addWidget(self.open_only_check)

        self.named_only_check = QCheckBox("Named devices only")
        self.named_only_check.setToolTip(
            "Hides devices with no readable SSID/hostname (shown as their bare MAC address) - "
            "e.g. cloaked/hidden APs and clients Kismet hasn't identified."
        )
        self.named_only_check.stateChanged.connect(self._apply_filters)
        toolbar.addWidget(self.named_only_check)

    def _build_central(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        outer.addWidget(splitter)

        self.tabs = QTabWidget()

        self.dashboard = DashboardView()
        self.tabs.addTab(self.dashboard, "Dashboard")

        self.table_model = DeviceTableModel()
        self.proxy_model = DeviceFilterProxy()
        self.proxy_model.setSourceModel(self.table_model)

        self.table_view = QTableView()
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSortingEnabled(True)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table_view.verticalHeader().setDefaultSectionSize(28)
        self.table_view.verticalHeader().setVisible(False)
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setMinimumSectionSize(70)
        header.setStretchLastSection(True)
        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._set_default_column_widths()
        self.tabs.addTab(self.table_view, "Devices")

        self.map_view = MapView(self.cfg)
        self.tabs.addTab(self.map_view, "Map")

        self.ble_panel = BlePanel()
        self.tabs.addTab(self.ble_panel, "BLE")

        self.alerts_panel = AlertsPanel()
        self.tabs.addTab(self.alerts_panel, "Alerts")

        self.tools_panel = ToolsPanel(self.cfg)
        self.tabs.addTab(self.tools_panel, "Tools")

        splitter.addWidget(self.tabs)

        self.inspector = InspectorPanel()
        self.inspector.deauth_requested.connect(self._quick_deauth)
        self.inspector.handshake_requested.connect(self._quick_handshake)
        splitter.addWidget(self.inspector)
        splitter.setSizes([1100, 400])

    def _set_default_column_widths(self) -> None:
        # Generous widths for the columns that felt cramped (name, manufacturer),
        # narrower for short fixed-format ones (channel, RSSI, counts).
        widths = {
            "Name / SSID": 190, "MAC": 140, "Type": 90, "Standard": 150,
            "Band": 70, "Channel": 70, "Encryption": 110, "RSSI (dBm)": 90,
            "Clients": 70, "Manufacturer": 190, "Packets": 80,
            "First Seen": 90, "Last Seen": 90,
        }
        from .device_table import COLUMNS
        for col, (label, _attr) in enumerate(COLUMNS):
            if label in widths:
                self.table_view.setColumnWidth(col, widths[label])

    def _build_statusbar(self) -> None:
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.conn_label = QLabel("Kismet: connecting...")
        self.capture_label = QLabel("Capture: stopped")
        self.pause_label = QLabel("")
        self.gps_label = QLabel("GPS: no fix")
        self.count_label = QLabel("0 devices")
        self.status.addWidget(self.conn_label)
        self.status.addWidget(self.capture_label)
        self.status.addWidget(self.pause_label)
        self.status.addWidget(self.gps_label)
        self.status.addPermanentWidget(self.count_label)

    # ---- one-click wireless actions (from the Inspector panel) ------------

    def _quick_deauth(self, bssid: str, client_mac: str) -> None:
        """The device table/inspector's "1 button" deauth: fills the Tools tab's
        target fields, switches to it so the live aireplay-ng output is visible,
        and runs immediately if the session's already authorized (if not,
        ToolsPanel.run_deauth_now() prompts for the one-time authorization tick)."""
        self.tools_panel.set_target(bssid, client_mac)
        self.tabs.setCurrentWidget(self.tools_panel)
        self.tools_panel.run_deauth_now()

    def _quick_handshake(self, bssid: str, client_mac: str) -> None:
        self.tools_panel.set_target(bssid, client_mac)
        self.tabs.setCurrentWidget(self.tools_panel)
        self.tools_panel.run_handshake_capture_now()

    # ---- capture control -------------------------------------------------

    def _toggle_capture(self) -> None:
        if self._last_capture_running:
            ok, msg = capture_control.stop()
        else:
            log_path = Path.home() / ".local/share/wirelessboss/kismet.log"
            ok, msg = capture_control.start(Path(self.cfg.storage.capture_dir), log_path)
        self.status.showMessage(msg, 5000)

    def _toggle_pause(self) -> None:
        self._paused = self.pause_btn.isChecked()
        self.pause_btn.setText("Resume View" if self._paused else "Pause View")
        self.pause_label.setText("VIEW PAUSED (capture continues in background)" if self._paused else "")

    def _clear_view(self) -> None:
        reply = QMessageBox.question(
            self, "Clear view",
            "Clear the device table, map, alerts, and dashboard in WirelessBOSS?\n\n"
            "This does not delete any kismetdb/pcap files on disk, and does not reset\n"
            "Kismet's own device cache - Kismet may re-report already-seen devices on\n"
            "the next poll.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._do_clear_view()

    def _do_clear_view(self) -> None:
        """The actual reset, split out from _clear_view so it's callable
        without going through the confirmation dialog (tests, future undo, etc.)."""
        self.table_model.clear()
        self.map_view.clear()
        self.alerts_panel.clear()
        self._known_manufs.clear()
        self.manuf_combo.clear()
        self.manuf_combo.addItem("All manufacturers", None)
        self._last_devices = []
        self.count_label.setText("0 devices")
        self._refresh_dashboard()
        self.status.showMessage("View cleared.", 4000)

    def _export_csv(self) -> None:
        devices = self.table_model.all_devices()
        if not devices:
            QMessageBox.information(self, "Nothing to export", "No devices captured yet.")
            return
        export_root = Path(self.cfg.storage.capture_dir) / "wirelessboss-exports"
        paths = export_csv(devices, export_root)
        self.status.showMessage(f"Exported {len(devices)} devices to {paths['all_devices'].parent}", 8000)
        QMessageBox.information(
            self, "Export complete",
            f"Wrote {len(devices)} devices to:\n{paths['all_devices'].parent}\n\n"
            "all_devices.csv, access_points.csv, clients.csv"
        )

    def _open_capture_folder(self) -> None:
        capture_dir = Path(self.cfg.storage.capture_dir)
        capture_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["xdg-open", str(capture_dir)])
        except OSError as exc:
            QMessageBox.warning(self, "Couldn't open folder", f"{capture_dir}\n\n{exc}")

    # ---- data updates -------------------------------------------------

    def _apply_filters(self) -> None:
        self.proxy_model.set_text_filter(self.search_edit.text())
        self.proxy_model.set_kind_filter(self.kind_combo.currentData())
        self.proxy_model.set_manuf_filter(self.manuf_combo.currentData())
        self.proxy_model.set_band_filter(self.band_combo.currentData())
        rssi = self.min_rssi_spin.value()
        self.proxy_model.set_min_rssi(None if rssi <= -100 else rssi)
        self.proxy_model.set_only_open(self.open_only_check.isChecked())
        self.proxy_model.set_named_only(self.named_only_check.isChecked())

    def _update_manuf_filter_options(self, devices: list[WifiDevice]) -> None:
        current = sorted_manufacturers(devices)
        new_ones = [m for m in current if m not in self._known_manufs]
        if not new_ones:
            return
        for m in new_ones:
            self.manuf_combo.addItem(m, m)
            self._known_manufs.add(m)

    def _on_devices(self, devices: list) -> None:
        if self._paused:
            return

        selected_mac = None
        dev = self._current_device()
        if dev is not None:
            selected_mac = dev.mac

        self.table_model.set_devices(devices)
        self._update_manuf_filter_options(devices)
        self.count_label.setText(f"{len(devices)} devices")
        self.map_view.update_devices(devices)
        self._last_devices = devices

        if selected_mac:
            for row, d in enumerate(devices):
                if d.mac == selected_mac:
                    src_index = self.table_model.index(row, 0)
                    proxy_index = self.proxy_model.mapFromSource(src_index)
                    self.table_view.selectRow(proxy_index.row())
                    break

        self._refresh_dashboard()

    def _on_gps(self, fix: GpsFix | None) -> None:
        if self._paused:
            return
        self._last_gps = fix
        if fix is None or fix.fix_quality == 0 or fix.latitude is None:
            self.gps_label.setText("GPS: no fix")
        else:
            self.gps_label.setText(
                f"GPS: {fix.latitude:.5f}, {fix.longitude:.5f} "
                f"({'3D' if fix.fix_quality == 3 else '2D'} fix, {fix.satellites} sats)"
            )
            self.map_view.update_self_location(fix.latitude, fix.longitude)
        self._refresh_dashboard()

    def _on_alerts(self, alerts: list) -> None:
        if self._paused:
            return
        self.alerts_panel.add_alerts(alerts)
        self._refresh_dashboard()

    def _on_connection_state(self, reachable: bool) -> None:
        self._last_kismet_connected = reachable
        if reachable:
            self.conn_label.setText(f"Kismet: connected ({self.cfg.kismet.url})")
        else:
            self.conn_label.setText(f"Kismet: UNREACHABLE ({self.cfg.kismet.url})")
        if not self._paused:
            self._refresh_dashboard()

    def _on_storage(self, capture_running: bool, storage: StorageStats) -> None:
        self._last_capture_running = capture_running
        self._last_storage = storage
        self.capture_label.setText("Capture: recording" if capture_running else "Capture: stopped")
        self.capture_btn.setText("Stop Capture" if capture_running else "Start Capture")
        if not self._paused:
            self._refresh_dashboard()

    def _refresh_dashboard(self) -> None:
        stats = compute_stats(self._last_devices)
        gps = self._last_gps
        gps_fix = bool(gps and gps.fix_quality and gps.latitude is not None)
        gps_fix_type = "3D Fix" if (gps and gps.fix_quality == 3) else ("2D Fix" if gps_fix else "")
        gps_sub = f"{gps.satellites} satellites" if (gps and gps_fix) else ""
        self.dashboard.update_stats(
            stats=stats,
            storage=self._last_storage,
            kismet_connected=self._last_kismet_connected,
            capture_running=self._last_capture_running,
            gps_fix=gps_fix,
            gps_fix_type=gps_fix_type,
            gps_sub=gps_sub,
            alerts_count=self.alerts_panel.list.count(),
        )

    def _current_device(self):
        indexes = self.table_view.selectionModel().selectedRows() if self.table_view.selectionModel() else []
        if not indexes:
            return None
        source_index = self.proxy_model.mapToSource(indexes[0])
        return self.table_model.device_at(source_index.row())

    def _on_selection_changed(self, *_args) -> None:
        self.inspector.show_device(self._current_device())

    def closeEvent(self, event) -> None:
        self.worker.stop()
        self.worker.wait(2000)
        self.tile_server.stop()
        super().closeEvent(event)
