"""Common interface for BLE sniffer hardware.

The primary web app uses :class:`wirelessboss.ble.wch_provider.WchBleManager`
for the reverse-engineered WCH BLE Analyzer Pro.  This small abstraction is
retained for alternate sniffers and the optional legacy PyQt view.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from ..models import BleDevice

BleDeviceCallback = Callable[[BleDevice], None]


class BleProvider(ABC):
    """A source of live BLE device sightings."""

    @abstractmethod
    def start(self, on_device: BleDeviceCallback) -> None:
        """Begin scanning/sniffing; call on_device(...) for every sighting."""

    @abstractmethod
    def stop(self) -> None:
        """Stop scanning and release the hardware."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        ...

    @property
    def display_name(self) -> str:
        return self.__class__.__name__


class NullBleProvider(BleProvider):
    """No-op provider used when an optional view has no hardware configured."""

    def start(self, on_device: BleDeviceCallback) -> None:
        pass

    def stop(self) -> None:
        pass

    @property
    def is_running(self) -> bool:
        return False

    @property
    def display_name(self) -> str:
        return "No BLE source configured"
