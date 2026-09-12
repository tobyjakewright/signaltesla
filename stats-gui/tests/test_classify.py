import unittest

from wirelessboss.classify import parse_device


def _raw_device(macaddr, frequency_khz, channel="", dev_type="Wi-Fi AP"):
    return {
        "kismet.device.base.macaddr": macaddr,
        "kismet.device.base.frequency": frequency_khz,
        "kismet.device.base.channel": channel,
        "kismet.device.base.type": dev_type,
    }


class ParseDeviceBandTest(unittest.TestCase):
    def test_2_4ghz_frequency_in_khz_maps_to_band(self):
        # Kismet reports kismet.device.base.frequency in kHz (2412000 == channel 1).
        dev = parse_device(_raw_device("AA:AA:AA:AA:AA:AA", 2412000, channel="1"))
        self.assertEqual(dev.frequency_mhz, 2412)
        self.assertEqual(dev.band, "2.4GHz")

    def test_5ghz_frequency_in_khz_maps_to_band(self):
        dev = parse_device(_raw_device("BB:BB:BB:BB:BB:BB", 5180000, channel="36"))
        self.assertEqual(dev.frequency_mhz, 5180)
        self.assertEqual(dev.band, "5GHz")

    def test_6ghz_frequency_in_khz_maps_to_band(self):
        dev = parse_device(_raw_device("CC:CC:CC:CC:CC:CC", 5955000, channel="1"))
        self.assertEqual(dev.frequency_mhz, 5955)
        self.assertEqual(dev.band, "6GHz")

    def test_zero_frequency_has_no_band(self):
        dev = parse_device(_raw_device("DD:DD:DD:DD:DD:DD", 0, dev_type="Wi-Fi Bridged"))
        self.assertEqual(dev.frequency_mhz, 0)
        self.assertEqual(dev.band, "")


if __name__ == "__main__":
    unittest.main()
