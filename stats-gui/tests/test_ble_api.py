from __future__ import annotations

import unittest

from pydantic import ValidationError

from wirelessboss.server.app import BleStartRequest


class BleStartRequestTests(unittest.TestCase):
    def test_beginner_defaults_select_all_primary_channels_and_1m(self) -> None:
        request = BleStartRequest()

        self.assertEqual(request.channel, 0)
        self.assertEqual(request.phy, "1")
        self.assertEqual(request.initiator, "")
        self.assertEqual(request.advertiser, "")
        self.assertEqual(request.ltk, "")

    def test_advanced_follow_and_decryption_fields_are_available(self) -> None:
        request = BleStartRequest(
            channel=38,
            phy="S2",
            initiator="06:05:04:03:02:01",
            advertiser="16:15:14:13:12:11",
            ltk="00112233445566778899AABBCCDDEEFF",
        )

        self.assertEqual(request.model_dump()["phy"], "S2")
        # Pydantic's ordinary debug representation must not print key material.
        self.assertNotIn("00112233445566778899AABBCCDDEEFF", repr(request))

    def test_invalid_channel_and_phy_fail_before_driver_launch(self) -> None:
        with self.assertRaises(ValidationError):
            BleStartRequest(channel=36)
        with self.assertRaises(ValidationError):
            BleStartRequest(phy="coded")


if __name__ == "__main__":
    unittest.main()
