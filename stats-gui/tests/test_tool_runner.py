from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from wirelessboss.server.state import ToolRunner


class ToolRunnerSafetyTests(unittest.TestCase):
    def test_deauth_validation_rejects_unbounded_or_shell_like_inputs(self) -> None:
        self.assertIsNotNone(
            ToolRunner.validate_deauth_request(
                "wlan0mon;reboot", "AA:BB:CC:DD:EE:FF", "", 5
            )
        )
        self.assertIsNotNone(
            ToolRunner.validate_deauth_request("wlan0mon", "not-a-mac", "", 5)
        )
        self.assertIsNotNone(
            ToolRunner.validate_deauth_request(
                "wlan0mon", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:ZZ", 5
            )
        )
        self.assertIsNotNone(
            ToolRunner.validate_deauth_request(
                "wlan0mon", "AA:BB:CC:DD:EE:FF", "", 21
            )
        )

    def test_authorization_gate_prevents_process_launch(self) -> None:
        runner = ToolRunner()
        with patch("wirelessboss.server.state.subprocess.Popen") as popen:
            ok, message = runner.run_deauth(
                "wlan0mon", "AA:BB:CC:DD:EE:FF", "", 5
            )

        self.assertFalse(ok)
        self.assertIn("Not authorized", message)
        popen.assert_not_called()

    def test_authorized_deauth_uses_an_argument_vector_and_bounded_count(self) -> None:
        runner = ToolRunner()
        runner.set_authorized(True)
        process = MagicMock()
        process.stdout = []
        with patch(
            "wirelessboss.server.state.subprocess.Popen", return_value=process
        ) as popen:
            ok, _ = runner.run_deauth(
                "wlan0mon",
                "AA:BB:CC:DD:EE:FF",
                "11:22:33:44:55:66",
                3,
            )

        self.assertTrue(ok)
        args, kwargs = popen.call_args
        self.assertEqual(
            args[0],
            [
                "aireplay-ng",
                "--deauth",
                "3",
                "-a",
                "AA:BB:CC:DD:EE:FF",
                "-c",
                "11:22:33:44:55:66",
                "wlan0mon",
            ],
        )
        self.assertNotIn("shell", kwargs)


if __name__ == "__main__":
    unittest.main()
