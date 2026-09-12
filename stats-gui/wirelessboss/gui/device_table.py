"""Sortable, filterable device table: the main "identify and list packets/devices" view."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

from ..models import DeviceKind, WifiDevice

COLUMNS = [
    ("Name / SSID", "name"),
    ("MAC", "mac"),
    ("Type", "kind"),
    ("Standard", "standard"),
    ("Band", "band"),
    ("Channel", "channel"),
    ("Encryption", "encryption"),
    ("RSSI (dBm)", "signal_dbm"),
    ("Clients", "client_count"),
    ("Manufacturer", "manuf"),
    ("Packets", "packets"),
    ("First Seen", "first_seen"),
    ("Last Seen", "last_seen"),
]


def _fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


class DeviceTableModel(QAbstractTableModel):
    """Updates in place (insert/remove/dataChanged) instead of a full reset on every
    poll - a beginResetModel()/endResetModel() cycle drops the view's scroll position,
    selection, and sort stability, which is what made the table visibly jump back to
    the left column every couple of seconds."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices: list[WifiDevice] = []
        self._by_mac: dict[str, int] = {}

    def set_devices(self, devices: list[WifiDevice]) -> None:
        new_by_mac = {d.mac: d for d in devices}
        old_macs = set(self._by_mac.keys())
        new_macs = set(new_by_mac.keys())

        # Update rows that still exist, in place.
        changed_rows = [self._by_mac[mac] for mac in (old_macs & new_macs)]
        for mac in old_macs & new_macs:
            self._devices[self._by_mac[mac]] = new_by_mac[mac]
        if changed_rows:
            top = self.index(min(changed_rows), 0)
            bottom = self.index(max(changed_rows), len(COLUMNS) - 1)
            self.dataChanged.emit(top, bottom)

        # Remove rows Kismet no longer reports (rare, but handle it), highest index first.
        removed_macs = old_macs - new_macs
        if removed_macs:
            for row in sorted((self._by_mac[m] for m in removed_macs), reverse=True):
                self.beginRemoveRows(QModelIndex(), row, row)
                del self._devices[row]
                self.endRemoveRows()

        # Append newly-seen devices.
        added_macs = new_macs - old_macs
        if added_macs:
            added = [new_by_mac[m] for m in added_macs]
            start = len(self._devices)
            self.beginInsertRows(QModelIndex(), start, start + len(added) - 1)
            self._devices.extend(added)
            self.endInsertRows()

        if removed_macs or added_macs:
            self._by_mac = {d.mac: i for i, d in enumerate(self._devices)}

    def device_at(self, row: int) -> Optional[WifiDevice]:
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None

    def all_devices(self) -> list[WifiDevice]:
        return list(self._devices)

    def clear(self) -> None:
        """Explicit user-initiated reset (the Clear View button) - unlike
        set_devices()'s incremental updates, a full reset here is fine
        since it's a deliberate one-off action, not every poll tick."""
        self.beginResetModel()
        self._devices = []
        self._by_mac = {}
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._devices)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section][0]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        dev = self._devices[index.row()]
        _, attr = COLUMNS[index.column()]
        value = getattr(dev, attr)

        if role == Qt.ItemDataRole.DisplayRole:
            if attr == "kind":
                return value.value
            if attr == "standard":
                return value.value
            if attr in ("first_seen", "last_seen"):
                return _fmt_time(value)
            if attr == "signal_dbm":
                return "" if value is None else str(value)
            if attr == "band":
                return value or "-"
            if attr == "manuf":
                return value or "-"
            return "" if value is None else str(value)

        if role == Qt.ItemDataRole.ToolTipRole and attr == "manuf":
            return value or None

        if role == Qt.ItemDataRole.UserRole:
            # Raw value, used for correct numeric/type sorting in the proxy.
            if attr in ("kind", "standard"):
                return value.value
            return value

        if role == Qt.ItemDataRole.ForegroundRole and attr == "signal_dbm" and value is not None:
            from PyQt6.QtGui import QColor
            if value >= -50:
                return QColor("#2e7d32")   # strong
            if value >= -70:
                return QColor("#f9a825")   # medium
            return QColor("#c62828")       # weak

        return None


class DeviceFilterProxy(QSortFilterProxyModel):
    """Free-text search + kind/manufacturer/band/min-RSSI/named-only filters
    over the device table."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(Qt.ItemDataRole.UserRole)
        self.setDynamicSortFilter(True)
        self._text = ""
        self._kind: Optional[DeviceKind] = None
        self._manuf: Optional[str] = None
        self._band: Optional[str] = None
        self._min_rssi: Optional[int] = None
        self._only_open = False
        self._named_only = False

    def set_text_filter(self, text: str) -> None:
        self._text = text.lower().strip()
        self.invalidateFilter()

    def set_kind_filter(self, kind: Optional[DeviceKind]) -> None:
        self._kind = kind
        self.invalidateFilter()

    def set_manuf_filter(self, manuf: Optional[str]) -> None:
        self._manuf = manuf
        self.invalidateFilter()

    def set_band_filter(self, band: Optional[str]) -> None:
        self._band = band
        self.invalidateFilter()

    def set_min_rssi(self, rssi: Optional[int]) -> None:
        self._min_rssi = rssi
        self.invalidateFilter()

    def set_only_open(self, only_open: bool) -> None:
        self._only_open = only_open
        self.invalidateFilter()

    def set_named_only(self, named_only: bool) -> None:
        self._named_only = named_only
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: DeviceTableModel = self.sourceModel()
        dev = model.device_at(source_row)
        if dev is None:
            return False

        if self._kind is not None and dev.kind != self._kind:
            return False

        if self._manuf is not None and dev.manuf != self._manuf:
            return False

        if self._band is not None and dev.band != self._band:
            return False

        if self._min_rssi is not None:
            if dev.signal_dbm is None or dev.signal_dbm < self._min_rssi:
                return False

        if self._only_open and dev.kind == DeviceKind.ACCESS_POINT and dev.encryption != "Open":
            return False

        if self._named_only:
            # classify.py falls back to the MAC address as the display name
            # when there's no SSID/hostname - that fallback is exactly what
            # "named only" should exclude, no separate flag needed.
            if not dev.name or dev.name == dev.mac:
                return False

        if self._text:
            haystack = " ".join([
                dev.name, dev.mac, dev.manuf, dev.encryption,
                dev.kind.value, dev.standard.value, dev.bssid,
            ]).lower()
            if self._text not in haystack:
                return False

        return True
