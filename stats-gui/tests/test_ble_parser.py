from __future__ import annotations

import unittest

from wirelessboss.ble.parser import decode_pdu, parse_ad_structures, parse_wch_packet


class BleParserTests(unittest.TestCase):
    def test_legacy_advertisement_identity_and_services(self) -> None:
        advertiser = bytes.fromhex("0102030405C6")  # static random address
        ad_data = (
            bytes([6, 0x09])
            + b"Watch"
            + bytes.fromhex("03030D18")
            + bytes.fromhex("05FF4C000102")
        )
        payload = advertiser + ad_data
        packet = decode_pdu(
            bytes([0x40, len(payload)]) + payload,
            host_timestamp=1234.5,
            channel=37,
            rssi=-51,
            access_address="8E89BED6",
        )

        self.assertFalse(packet["malformed"])
        self.assertEqual(packet["type_name"], "ADV_IND")
        self.assertEqual(packet["src"], "C6:05:04:03:02:01")
        self.assertEqual(packet["address_type"], "random")
        self.assertEqual(packet["address_subtype"], "static")
        self.assertEqual(packet["name"], "Watch")
        self.assertEqual(packet["manufacturer"], "Apple, Inc.")
        self.assertIn("Heart Rate (0x180D)", packet["services"])
        self.assertEqual(packet["protocol"], "BLE")
        self.assertEqual(packet["type"], "ADV_IND")
        self.assertEqual(packet["ts"], 1234.5)
        self.assertEqual(packet["length"], len(packet["pdu_hex"]) // 2)
        self.assertTrue(packet["raw_hex"].startswith("D6BE898E"))
        self.assertEqual(len(packet["crc"]), 6)
        self.assertTrue(packet["crc_reconstructed"])
        self.assertTrue(packet["raw_hex"].endswith(packet["crc"]))
        self.assertIn("reconstructed CRC", packet["raw_note"])

    def test_connect_ind_decodes_ll_data_and_explains_native_follow(self) -> None:
        initiator = bytes.fromhex("010203040506")
        advertiser = bytes.fromhex("111213141516")
        ll_data = (
            bytes.fromhex("D6BE8912")  # new access address: 0x1289BED6
            + bytes.fromhex("555555")
            + bytes([2])
            + (3).to_bytes(2, "little")
            + (24).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (500).to_bytes(2, "little")
            + bytes.fromhex("FFFFFFFF1F")
            + bytes([0xE5])  # SCA 7, hop increment 5
        )
        payload = initiator + advertiser + ll_data
        packet = decode_pdu(bytes([0x05, len(payload)]) + payload, channel=37)
        connection = packet["details"]["connection"]

        self.assertFalse(packet["connectable"])
        self.assertEqual(packet["type_name"], "CONNECT_IND")
        self.assertEqual(connection["access_address"], "1289BED6")
        self.assertEqual(connection["crc_init"], "555555")
        self.assertEqual(connection["window_size_ms"], 2.5)
        self.assertEqual(connection["window_offset_ms"], 3.75)
        self.assertEqual(connection["interval_ms"], 30.0)
        self.assertEqual(connection["supervision_timeout_ms"], 5000)
        self.assertEqual(connection["data_channels"], list(range(37)))
        self.assertEqual(connection["hop_increment"], 5)
        self.assertEqual(connection["sleep_clock_accuracy"], "0-20 ppm")
        self.assertFalse(connection["metadata_only"])
        self.assertTrue(connection["followed_by_firmware"])
        self.assertIn("data channels 0-36", connection["capture_note"])
        self.assertEqual(packet["initiator"], "06:05:04:03:02:01")
        self.assertEqual(packet["advertiser"], "16:15:14:13:12:11")

    def test_extended_header_and_aux_pointer(self) -> None:
        advertiser = bytes.fromhex("0102030405C6")
        # Flags + AdvA + AuxPtr + TxPower = 11-byte extended header.
        aux_ptr = bytes([20, 0x23, 0x21])  # ch20, 0x123 * 30 us, LE 2M
        extended_header = bytes([0x51]) + advertiser + aux_ptr + bytes([0xF6])
        ad_data = bytes([4, 0x08]) + b"Tag"
        payload = bytes([0x40 | len(extended_header)]) + extended_header + ad_data
        packet = decode_pdu(bytes([0x47, len(payload)]) + payload, channel=37)
        extended = packet["details"]["extended"]

        self.assertFalse(packet["malformed"])
        self.assertEqual(packet["type_name"], "ADV_EXT_IND")
        self.assertEqual(packet["src"], "C6:05:04:03:02:01")
        self.assertEqual(packet["address_subtype"], "static")
        self.assertTrue(packet["connectable"])
        self.assertFalse(packet["scannable"])
        self.assertEqual(packet["name"], "Tag")
        self.assertEqual(extended["aux_ptr"]["channel"], 20)
        self.assertEqual(extended["aux_ptr"]["offset_us"], 0x123 * 30)
        self.assertEqual(extended["aux_ptr"]["phy"], "LE 2M")
        self.assertEqual(extended["tx_power_dbm"], -10)
        self.assertIn("natively follow", extended["capture_note"])
        self.assertIn("not automatically followed", extended["capture_note"])

    def test_data_control_packet_uses_llid_not_advertising_nibble(self) -> None:
        # LLID=3, LL_FEATURE_REQ opcode + 8-byte feature mask.
        pdu = bytes.fromhex("0309080100000000000000")
        packet = parse_wch_packet(
            {
                "link_layer": "data",
                "pdu_hex": pdu.hex(),
                "channel": 16,
                "raw_channel": 0x10,
                "phy": "LE 1M",
                "access_address": "6907863F",
                "crc_init": "01A120",
                "crc": "A1B2C3",
                "crc_reconstructed": True,
                "direction": 1,
                "direction_name": "initiator_to_advertiser",
                "initiator": "84:C2:E4:03:02:02",
                "advertiser": "01:02:03:04:05:06",
            }
        )

        self.assertFalse(packet["malformed"])
        self.assertEqual(packet["link_layer"], "data")
        self.assertEqual(packet["type_code"], 3)
        self.assertEqual(packet["type_name"], "LL_FEATURE_REQ")
        self.assertIn("features", packet["purpose"])
        self.assertEqual(packet["details"]["data"]["llid"], 3)
        self.assertEqual(packet["details"]["data"]["control"]["opcode"], 8)
        self.assertEqual(packet["src"], "84:C2:E4:03:02:02")
        self.assertEqual(packet["dst"], "01:02:03:04:05:06")
        self.assertEqual(packet["direction"], "initiator to advertiser (central → peripheral)")
        self.assertTrue(packet["raw_hex"].startswith("3F860769"))
        self.assertTrue(packet["raw_hex"].endswith("A1B2C3"))
        self.assertEqual(packet["address_type"], "")
        self.assertEqual(packet["ad_structures"], [])

    def test_empty_and_encrypted_data_packets_are_explained(self) -> None:
        empty = parse_wch_packet(
            {
                "link_layer": "data",
                "pdu_hex": "0100",
                "access_address": "6907863F",
                "crc_init": "01A120",
            }
        )
        self.assertEqual(empty["type_name"], "LL_EMPTY")
        self.assertIn("acknowledges", empty["purpose"])

        encrypted = parse_wch_packet(
            {
                "link_layer": "data",
                "pdu_hex": "0305AABBCCDDEE",
                "access_address": "6907863F",
                "crc_init": "01A120",
                "encrypted": True,
                "decrypted": False,
            }
        )
        self.assertEqual(encrypted["type_name"], "LL_ENCRYPTED")
        self.assertIn("LTK", encrypted["purpose"])
        self.assertEqual(
            encrypted["details"]["data"]["ciphertext_hex"], "AABBCCDDEE"
        )

    def test_decryption_metadata_is_preserved(self) -> None:
        packet = parse_wch_packet(
            {
                "link_layer": "data",
                "pdu_hex": "030102",
                "access_address": "12345678",
                "crc_init": "ABCDEF",
                "encrypted": True,
                "decrypted": True,
                "mic_valid": True,
                "mic_checked": True,
                "retransmission": True,
                "packet_counter": 42,
                "decrypt_status": "ltk",
            }
        )
        self.assertEqual(packet["type_name"], "LL_TERMINATE_IND")
        self.assertTrue(packet["decrypted"])
        self.assertTrue(packet["mic_valid"])
        self.assertTrue(packet["mic_checked"])
        self.assertTrue(packet["retransmission"])
        self.assertEqual(packet["packet_counter"], 42)
        self.assertEqual(packet["decrypt_status"], "ltk")
        self.assertIn("decrypted PDU", packet["raw_note"])

    def test_malformed_packets_return_partial_result(self) -> None:
        packet = parse_wch_packet({"pdu_hex": "000A0102", "rssi": "bad"})
        self.assertTrue(packet["malformed"])
        self.assertEqual(packet["type_name"], "ADV_IND")
        self.assertGreaterEqual(len(packet["errors"]), 1)
        self.assertIsNone(packet["rssi"])

        invalid_hex = parse_wch_packet({"pdu_hex": "not-hex"})
        self.assertTrue(invalid_hex["malformed"])
        self.assertIn("non-hexadecimal", " ".join(invalid_hex["errors"]))

    def test_malformed_ad_structure_is_reported(self) -> None:
        ad = parse_ad_structures(bytes.fromhex("09094142"))
        self.assertTrue(ad["errors"])
        self.assertEqual(ad["ad_structures"], [])


if __name__ == "__main__":
    unittest.main()
