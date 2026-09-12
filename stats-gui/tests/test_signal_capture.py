from __future__ import annotations

import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wirelessboss.signal_capture import SignalCaptureManager, parse_ek_packet


def config(*, tshark_path: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        kismet=SimpleNamespace(
            url="http://127.0.0.1:2501",
            username="wirelessboss",
            password="secret",
            apikey="",
        ),
        signal_analysis=SimpleNamespace(
            tshark_path=tshark_path,
            max_packets=3,
        ),
    )


def packet(*, ts: float, src: str, dst: str, channel: int, packet_type: str) -> dict:
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "bssid": src,
        "type": packet_type,
        "protocol": "802.11",
        "channel": channel,
        "frequency": 2407 + channel * 5,
        "rssi": -50,
        "RSSI": -50,
        "length": 42,
        "info": packet_type,
        "purpose": "test packet",
        "raw_hex": "00112233",
    }


class SignalEkParserTests(unittest.TestCase):
    def test_nested_kali_tshark_ek_document_is_normalised(self) -> None:
        document = {
            "timestamp": "1710000000123",
            "layers": {
                "frame": {
                    "frame_frame_time_epoch": "1710000000.123456789",
                    "frame_frame_len": "128",
                    "frame_frame_protocols": "radiotap:wlan:wlan_mgt:eapol",
                    "frame_raw": ["001122aabbcc", 0, 6, 0, 0],
                },
                "radiotap": {
                    "radiotap_radiotap_channel_freq": "2412",
                    "radiotap_radiotap_dbm_antsignal": "-47 dBm",
                },
                "wlan": {
                    "wlan_wlan_fc_type": "0",
                    "wlan_wlan_fc_subtype": "8",
                    "wlan_wlan_sa": "AA:BB:CC:DD:EE:FF",
                    "wlan_wlan_da": "FF:FF:FF:FF:FF:FF",
                    "wlan_wlan_bssid": "AA:BB:CC:DD:EE:FF",
                },
                "_ws.col": {
                    "_ws_col_protocol": "EAPOL",
                    "_ws_col_info": "Key (Message 1 of 4)",
                },
            },
        }

        parsed = parse_ek_packet(document)

        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertAlmostEqual(parsed["ts"], 1710000000.1234567)
        self.assertEqual(parsed["src"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["dst"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(parsed["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["type"], "Beacon")
        self.assertEqual(parsed["protocol"], "EAPOL")
        self.assertEqual(parsed["channel"], 1)
        self.assertEqual(parsed["frequency"], 2412)
        self.assertEqual(parsed["rssi"], -47)
        self.assertEqual(parsed["RSSI"], -47)
        self.assertEqual(parsed["length"], 128)
        self.assertEqual(parsed["info"], "Key (Message 1 of 4)")
        self.assertIn("key-exchange", parsed["purpose"])
        self.assertEqual(parsed["raw_hex"], "001122aabbcc")

    def test_index_metadata_and_invalid_json_are_ignored(self) -> None:
        self.assertIsNone(parse_ek_packet('{"index":{"_index":"packets"}}'))
        self.assertIsNone(parse_ek_packet("not json"))
        self.assertIsNone(parse_ek_packet({"timestamp": "1710000000"}))

    def test_millisecond_timestamp_and_6ghz_channel_are_normalised(self) -> None:
        parsed = parse_ek_packet(
            {
                "layers": {
                    "frame": {
                        "frame_frame_time_epoch": "1710000000123",
                        "frame_frame_len": "20",
                    },
                    "radiotap": {
                        "radiotap_radiotap_channel_freq": "5955 MHz",
                    },
                    "wlan": {
                        "wlan_wlan_fc_type_subtype": "0x0008",
                    },
                }
            }
        )
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertAlmostEqual(parsed["ts"], 1710000000.123)
        self.assertEqual(parsed["channel"], 1)
        self.assertEqual(parsed["frequency"], 5955)
        self.assertEqual(parsed["type"], "Beacon")


class SignalCaptureManagerTests(unittest.TestCase):
    def test_bounded_buffer_filters_and_cursor_pagination(self) -> None:
        manager = SignalCaptureManager(config(), max_packets=3)
        manager._record_packet(
            packet(
                ts=1.0,
                src="00:00:00:00:00:01",
                dst="ff:ff:ff:ff:ff:ff",
                channel=1,
                packet_type="Beacon",
            )
        )
        manager._record_packet(
            packet(
                ts=2.0,
                src="00:00:00:00:00:02",
                dst="00:00:00:00:00:01",
                channel=6,
                packet_type="Data",
            )
        )
        manager._record_packet(
            packet(
                ts=3.0,
                src="00:00:00:00:00:03",
                dst="00:00:00:00:00:02",
                channel=11,
                packet_type="Probe Request",
            )
        )
        manager._record_packet(
            packet(
                ts=4.0,
                src="00:00:00:00:00:04",
                dst="00:00:00:00:00:03",
                channel=6,
                packet_type="Data",
            )
        )

        # Sequence 1 has fallen out of the bounded three-row buffer.
        self.assertEqual([p["seq"] for p in manager.get_packets()], [2, 3, 4])
        self.assertEqual([p["seq"] for p in manager.get_packets(limit=2)], [3, 4])
        # Cursor requests return the oldest next page, avoiding skipped rows.
        self.assertEqual(
            [p["seq"] for p in manager.get_packets(after=1, limit=2)], [2, 3]
        )
        self.assertEqual(
            [p["seq"] for p in manager.get_packets(channel="6")], [2, 4]
        )
        self.assertEqual(
            [p["seq"] for p in manager.get_packets(address="00-00-00-00-00-02")],
            [2, 3],
        )
        self.assertEqual(
            [p["seq"] for p in manager.get_packets(packet_type="data")], [2, 4]
        )

        removed = manager.clear()
        self.assertEqual(removed, 3)
        manager._record_packet(
            packet(
                ts=5.0,
                src="00:00:00:00:00:05",
                dst="ff:ff:ff:ff:ff:ff",
                channel=1,
                packet_type="Beacon",
            )
        )
        self.assertEqual(manager.get_packets()[0]["seq"], 5)

    def test_missing_tshark_fails_before_starting_worker(self) -> None:
        manager = SignalCaptureManager(config(tshark_path="/missing/tshark"))
        with patch.object(manager, "_resolve_tshark", return_value=None):
            ok, message = manager.start()

        self.assertFalse(ok)
        self.assertIn("not found", message)
        self.assertFalse(manager.running)
        self.assertEqual(manager.status(refresh=False)["state"], "error")

    def test_protocol_name_is_a_valid_packet_type_filter(self) -> None:
        manager = SignalCaptureManager(config(), max_packets=3)
        eapol = packet(
            ts=1.0,
            src="00:00:00:00:00:01",
            dst="00:00:00:00:00:02",
            channel=6,
            packet_type="Data",
        )
        eapol["protocol"] = "EAPOL"
        manager._record_packet(eapol)

        matched = manager.get_packets(packet_type="eapol")

        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["type"], "Data")
        self.assertEqual(matched[0]["protocol"], "EAPOL")

    def test_start_is_idempotent_and_stop_joins_worker(self) -> None:
        manager = SignalCaptureManager(config())
        entered = threading.Event()

        def fake_worker() -> None:
            entered.set()
            manager._stop_event.wait(2.0)

        manager._worker = fake_worker  # type: ignore[method-assign]
        with patch.object(manager, "_resolve_tshark", return_value="/usr/bin/tshark"):
            ok, _ = manager.start()
            self.assertTrue(ok)
            self.assertTrue(entered.wait(1.0))
            again_ok, again_message = manager.start()
            self.assertTrue(again_ok)
            self.assertIn("already running", again_message)

        stop_ok, _ = manager.stop(timeout_sec=1.0)
        self.assertTrue(stop_ok)
        self.assertFalse(manager.running)
        self.assertEqual(manager.status(refresh=False)["state"], "stopped")


if __name__ == "__main__":
    unittest.main()
