from __future__ import annotations

import unittest
from unittest.mock import patch

from wirelessboss import capture_control


class CaptureControlStopTests(unittest.TestCase):
    @patch.object(capture_control, "_user_service_active", return_value=False)
    @patch.object(capture_control.os, "kill")
    @patch.object(capture_control, "kismet_pid", side_effect=[321, None])
    def test_direct_stop_waits_until_kismet_exits(self, pid, kill, _service) -> None:
        ok, message = capture_control.stop(timeout_sec=0.5)

        self.assertTrue(ok)
        self.assertIn("stopped", message.lower())
        kill.assert_called_once_with(321, capture_control.signal.SIGTERM)
        self.assertEqual(pid.call_count, 2)

    @patch.object(capture_control, "_user_service_active", return_value=False)
    @patch.object(capture_control.os, "kill")
    @patch.object(capture_control, "kismet_pid", return_value=654)
    @patch.object(capture_control.time, "monotonic", side_effect=[0.0, 0.2])
    def test_direct_stop_reports_timeout(self, _clock, _pid, kill, _service) -> None:
        ok, message = capture_control.stop(timeout_sec=0.1)

        self.assertFalse(ok)
        self.assertIn("did not stop", message)
        kill.assert_called_once_with(654, capture_control.signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
