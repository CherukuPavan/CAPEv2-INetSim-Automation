"""Pure offline bounded CAPE Agent disk-marker challenge tests."""
import base64
import unittest
from unittest import mock

import command2_disposable_guest_marker as m

IP = "192.168.241.101"
BRIDGE = "192.168.241.1"


def answer(word):
    return {"message": "Successfully executed command",
            "stdout": base64.b64encode(word.encode()).decode()}


class MarkerTests(unittest.TestCase):
    def test_static_command_restricted_to_single_benign_file(self):
        self.assertIn(m.MARKER, m.READ_SCRIPT)
        self.assertIn(m.MARKER, m.WRITE_SCRIPT)
        self.assertIn("[IO.FileMode]::CreateNew", m.WRITE_SCRIPT)
        self.assertIn("Test-Path -LiteralPath", m.WRITE_SCRIPT)
        self.assertNotIn("Remove-Item", m.WRITE_SCRIPT)
        self.assertNotIn("Set-MpPreference", m.WRITE_SCRIPT)

    def test_read_absent(self):
        with mock.patch.object(m.transport, "agent_post", return_value=answer(
                "CAPE_DISK_MARKER_ABSENT\n")) as mock_post:
            self.assertFalse(m.read_marker(IP, BRIDGE))
        args = mock_post.call_args.args
        self.assertEqual(args[:3], (IP, BRIDGE, "/execute"))
        self.assertIn(b"encoding=base64", args[3])

    def test_read_present_and_write_created(self):
        with mock.patch.object(m.transport, "agent_post",
                               side_effect=[answer("CAPE_DISK_MARKER_PRESENT"),
                                            answer("CAPE_DISK_MARKER_CREATED")]):
            self.assertTrue(m.read_marker(IP, BRIDGE))
            self.assertTrue(m.create_marker(IP, BRIDGE))

    def test_refuse_wrong_bridge_and_guest_source(self):
        for ip, source in ((IP, "192.168.241.2"),
                           ("8.8.8.8", BRIDGE),
                           ("192.168.242.101", BRIDGE),
                           ("127.0.0.1", "127.0.0.1"),
                           (IP, "invalid")):
            with self.subTest(ip=ip, source=source):
                with self.assertRaises(m.MarkerBlocked):
                    m.read_marker(ip, source)

    def test_refuse_unexpected_agent_response(self):
        for response in (
            {"message": "Execution failed", "stdout": answer(
                "CAPE_DISK_MARKER_ABSENT")["stdout"]},
            answer("MALWARE"),
            {"message": "Successfully executed command", "stdout": "@notb64"},
            answer("CAPE_DISK_MARKER_ABSENT\nextra"),
        ):
            with mock.patch.object(m.transport, "agent_post",
                                   return_value=response):
                with self.assertRaises(m.MarkerBlocked):
                    m.read_marker(IP, BRIDGE)

    def test_never_execute_unreviewed_payload(self):
        with self.assertRaises(m.MarkerBlocked):
            m.execute_fixed(IP, BRIDGE, "powershell -Command dangerous",
                            modifying=True)
        with self.assertRaises(m.MarkerBlocked):
            m.execute_fixed(IP, BRIDGE, m.READ_SCRIPT, modifying=True)

    def test_write_witness_requires_exact_created_response(self):
        with mock.patch.object(m.transport, "agent_post",
                               return_value=answer("CAPE_DISK_MARKER_ABSENT")):
            with self.assertRaises(m.MarkerBlocked):
                m.create_marker(IP, BRIDGE)


if __name__ == "__main__":
    unittest.main()
