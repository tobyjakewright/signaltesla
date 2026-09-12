from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from wirelessboss.ble.wch_provider import WchBleManager


def advertisement(address_wire: str, name: str, channel: int, rssi: int, ts: float) -> dict:
    encoded_name = name.encode()
    ad_data = bytes([len(encoded_name) + 1, 0x09]) + encoded_name
    payload = bytes.fromhex(address_wire) + ad_data
    pdu = bytes([0x00, len(payload)]) + payload
    return {
        "host_timestamp": ts,
        "channel": channel,
        "rssi": rssi,
        "pdu_hex": pdu.hex(),
        "type_code": 0,
        "access_address": "8E89BED6",
    }


def data_packet(ts: float, *, decrypted: bool = False) -> dict:
    return {
        "host_timestamp": ts,
        "channel": 16,
        "raw_channel": 0x10,
        "rssi": -48,
        "link_layer": "data",
        "pdu_hex": "0309080100000000000000",
        "type_code": 3,
        "access_address": "6907863F",
        "crc_init": "01A120",
        "crc": "A1B2C3",
        "direction": 1,
        "direction_name": "initiator_to_advertiser",
        "initiator": "06:05:04:03:02:01",
        "advertiser": "16:15:14:13:12:11",
        "encrypted": decrypted,
        "decrypted": decrypted,
        "mic_valid": True if decrypted else None,
    }


class _RunningProcess:
    """Small text-mode Popen stand-in for lifecycle tests."""

    def __init__(
        self,
        *,
        pid: int = 1234,
        stdout: list[str] | None = None,
        stderr: list[str] | None = None,
    ) -> None:
        self.pid = pid
        self.stdout = iter(stdout or [])
        self.stderr = iter(stderr or [])

    def poll(self) -> None:
        return None


class _FailedStartupProcess(_RunningProcess):
    def __init__(self) -> None:
        self._stderr_drained = threading.Event()
        self._finished = threading.Event()
        super().__init__(pid=9876, stdout=[])
        self.stderr = self._failure_lines()

    def _failure_lines(self):
        yield "Found 3 MCU radio(s).\n"
        yield "Started 0 MCU radio(s).\n"
        yield "No analyzer radio completed startup; stopping capture.\n"
        self._stderr_drained.set()

    def poll(self) -> int | None:
        return 1 if self._finished.is_set() else None

    def wait(self, timeout: float | None = None) -> int:
        if not self._stderr_drained.wait(timeout if timeout is not None else 1.0):
            raise TimeoutError("stderr was not consumed")
        self._finished.set()
        return 1

    def send_signal(self, _signal: int) -> None:
        self._finished.set()

    terminate = send_signal
    kill = send_signal


class WchBleManagerTests(unittest.TestCase):
    def test_snapshots_are_bounded_filterable_and_json_safe(self) -> None:
        manager = WchBleManager(max_packets=2, max_rssi_samples=2, max_devices=2)
        now = time.time()
        manager.ingest_record(advertisement("010203040506", "Watch", 37, -70, now))
        manager.ingest_record(advertisement("010203040506", "Watch", 38, -60, now + 0.1))
        manager.ingest_record(advertisement("111213141516", "Tag", 39, -50, now + 0.2))

        packets = manager.packets(limit=10)
        self.assertEqual([packet["seq"] for packet in packets], [2, 3])
        self.assertEqual(len(manager.packets(channel=38)), 1)
        self.assertEqual(len(manager.packets(packet_type="ADV_IND")), 2)
        self.assertEqual(
            len(manager.packets(address="06:05:04:03:02:01", after=1)), 1
        )

        watch = manager.device("06:05:04:03:02:01")
        self.assertIsNotNone(watch)
        assert watch is not None
        self.assertEqual(watch["channels_seen"], [37, 38])
        self.assertEqual(len(watch["rssi_history"]), 2)
        self.assertEqual(watch["packets"], 2)
        # Mutating a caller snapshot cannot mutate manager-owned state.
        packets[0]["details"]["changed"] = True
        self.assertNotIn("changed", manager.packets()[0]["details"])

        stats = manager.stats()
        self.assertEqual(stats["total_devices"], 2)
        self.assertEqual(stats["active_devices"], 2)
        self.assertEqual(stats["named_devices"], 2)
        self.assertEqual(stats["total_packets"], 3)
        self.assertEqual(stats["advertising_packets"], 3)
        self.assertEqual(stats["data_packets"], 0)

    def test_clear_keeps_sequence_monotonic(self) -> None:
        manager = WchBleManager(max_packets=5)
        now = time.time()
        first = manager.ingest_record(advertisement("010203040506", "One", 37, -60, now))
        manager.clear()
        second = manager.ingest_record(advertisement("111213141516", "Two", 38, -50, now))
        self.assertGreater(second["seq"], first["seq"])

    def test_invalid_phy_is_rejected_before_launch(self) -> None:
        manager = WchBleManager(driver_path="/does/not/matter")
        ok, message = manager.start(phy="3")
        self.assertFalse(ok)
        self.assertIn("1, 2, S8, or S2", message)

        ok, message = manager.start(ltk="not-a-key")
        self.assertFalse(ok)
        self.assertIn("32 hexadecimal digits", message)

    def test_phy_filters_and_ltk_are_passed_as_exact_cli_arguments(self) -> None:
        process = _RunningProcess(pid=4321, stderr=["Started 3 MCU radio(s).\n"])
        with tempfile.TemporaryDirectory() as capture_dir, patch(
            "wirelessboss.ble.wch_provider.discover_wch_driver",
            return_value=Path("/fake/wch_capture"),
        ), patch(
            "wirelessboss.ble.wch_provider.subprocess.Popen", return_value=process
        ) as popen, patch.object(WchBleManager, "_wait_for_exit", return_value=None):
            manager = WchBleManager(capture_dir=capture_dir)
            ok, message = manager.start(
                channel=0,
                phy="S8",
                initiator="06-05-04-03-02-01",
                advertiser="16:15:14:13:12:11",
                ltk="00112233445566778899aabbccddeeff",
            )

        self.assertTrue(ok, message)
        args = popen.call_args.args[0]
        self.assertEqual(args[args.index("-p") + 1], "S8")
        self.assertEqual(args[args.index("-i") + 1], "06:05:04:03:02:01")
        self.assertEqual(args[args.index("-a") + 1], "16:15:14:13:12:11")
        self.assertEqual(
            args[args.index("-k") + 1], "00112233445566778899AABBCCDDEEFF"
        )
        status = manager.status()
        self.assertEqual(status["phy"], "S8")
        self.assertTrue(status["native_connection_following"])
        self.assertTrue(status["ltk_configured"])
        self.assertNotIn("00112233445566778899AABBCCDDEEFF", str(status))
        self.assertNotIn("00112233445566778899AABBCCDDEEFF", message)

    def test_followed_connection_and_decryption_stats(self) -> None:
        manager = WchBleManager(max_packets=10)
        now = time.time()
        packet = manager.ingest_record(data_packet(now, decrypted=True))

        self.assertEqual(packet["link_layer"], "data")
        self.assertEqual(packet["type_name"], "LL_FEATURE_REQ")
        stats = manager.stats()
        self.assertEqual(stats["data_packets"], 1)
        self.assertEqual(stats["followed_connections"], 1)
        self.assertEqual(stats["encrypted_packets"], 1)
        self.assertEqual(stats["decrypted_packets"], 1)
        self.assertEqual(stats["mic_valid_packets"], 1)
        initiator = manager.device("06:05:04:03:02:01")
        self.assertIsNotNone(initiator)
        assert initiator is not None
        self.assertEqual(initiator["data_packets"], 1)
        self.assertEqual(initiator["decrypted_packets"], 1)
        self.assertTrue(initiator["following"])
        self.assertEqual(initiator["data_channels_seen"], [16])
        self.assertEqual(initiator["connection_access_addresses"], ["6907863F"])

    def test_concurrent_start_launches_exactly_one_process(self) -> None:
        first_popen_entered = threading.Event()
        second_popen_entered = threading.Event()
        release_popen = threading.Event()
        popen_calls = 0
        popen_lock = threading.Lock()

        def launch_process(*_args, **_kwargs):
            nonlocal popen_calls
            with popen_lock:
                popen_calls += 1
                call_number = popen_calls
            if call_number == 1:
                first_popen_entered.set()
            else:
                second_popen_entered.set()
            self.assertTrue(release_popen.wait(2.0))
            return _RunningProcess(
                pid=4000 + call_number,
                stderr=["Started 1 MCU radio(s).\n"],
            )

        with tempfile.TemporaryDirectory() as capture_dir, patch(
            "wirelessboss.ble.wch_provider.discover_wch_driver",
            return_value=Path("/fake/wch_capture"),
        ), patch(
            "wirelessboss.ble.wch_provider.subprocess.Popen",
            side_effect=launch_process,
        ), patch.object(WchBleManager, "_wait_for_exit", return_value=None):
            manager = WchBleManager(capture_dir=capture_dir)
            results: list[tuple[bool, str] | None] = [None, None]

            def start_capture(index: int) -> None:
                results[index] = manager.start(channel=37)

            first = threading.Thread(target=start_capture, args=(0,))
            second = threading.Thread(target=start_capture, args=(1,))
            first.start()
            self.assertTrue(first_popen_entered.wait(1.0))
            second.start()
            # In the broken implementation both callers get past the running
            # check and enter Popen.  A serialized implementation keeps the
            # second caller out until the first process is registered.
            second_popen_entered.wait(0.25)
            release_popen.set()
            first.join(2.0)
            second.join(2.0)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(popen_calls, 1)
        self.assertEqual(sum(bool(result and result[0]) for result in results), 1)
        self.assertEqual(sum(bool(result and not result[0]) for result in results), 1)

    def test_stale_process_readers_cannot_mutate_current_capture(self) -> None:
        manager = WchBleManager()
        current = _RunningProcess(pid=2000)
        stale = _RunningProcess(
            pid=1000,
            stdout=[
                json.dumps(
                    advertisement(
                        "010203040506", "Old capture", 37, -55, time.time()
                    )
                )
                + "\n"
            ],
            stderr=[
                "Started 3 MCU radio(s).\n",
                "Analyzer disconnected; stopping capture.\n",
            ],
        )
        with manager._lock:
            manager._process = current
            manager._stderr_lines.append("current capture")

        manager._read_stdout(stale)
        manager._read_stderr(stale)

        status = manager.status()
        self.assertEqual(status["packet_count"], 0)
        self.assertIsNone(status["active_mcu_count"])
        self.assertEqual(status["error"], "")
        self.assertEqual(status["stderr"], ["current capture"])

    def test_early_cli_startup_failure_is_returned_to_caller(self) -> None:
        process = _FailedStartupProcess()
        with tempfile.TemporaryDirectory() as capture_dir, patch(
            "wirelessboss.ble.wch_provider.discover_wch_driver",
            return_value=Path("/fake/wch_capture"),
        ), patch(
            "wirelessboss.ble.wch_provider.subprocess.Popen", return_value=process
        ):
            manager = WchBleManager(capture_dir=capture_dir)
            ok, message = manager.start(channel=0)

        self.assertFalse(ok)
        self.assertIn("no analyzer radio", message.lower())
        self.assertFalse(manager.status()["running"])
        self.assertEqual(manager.status()["channels"], [])

    def test_pinned_channel_is_active_only_after_current_process_confirmation(self) -> None:
        manager = WchBleManager()
        process = _RunningProcess(pid=3000, stderr=["Started 1 MCU radio(s).\n"])
        with manager._lock:
            manager._process = process
            manager._channel = 38
            manager._active_mcu_count = None

        before = manager.status()
        self.assertIsNone(before["active_mcu_count"])
        self.assertEqual(before["channels"], [])
        self.assertEqual(before["configured_channels"], [38])

        manager._read_stderr(process)

        after = manager.status()
        self.assertEqual(after["active_mcu_count"], 1)
        self.assertEqual(after["channels"], [38])

    def test_read_error_surfaces_reduced_all_channel_coverage(self) -> None:
        read_error = (
            "Read error bus=001 address=002 radio=1: LIBUSB_ERROR_IO"
        )
        manager = WchBleManager()
        process = _RunningProcess(
            pid=3100,
            stderr=[
                "Started 3 MCU radio(s).\n",
                read_error + "\n",
                "Active 2 MCU radio(s).\n",
            ],
        )
        ready = threading.Event()
        with manager._lock:
            manager._process = process
            manager._channel = 0
            manager._active_mcu_count = None

        manager._read_stderr(process, ready)

        status = manager.status()
        self.assertTrue(ready.is_set())
        self.assertEqual(status["active_mcu_count"], 2)
        self.assertEqual(status["channels"], [37, 38])
        self.assertEqual(status["error"], read_error)


if __name__ == "__main__":
    unittest.main()
