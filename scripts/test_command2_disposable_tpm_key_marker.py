"""Offline exact-command CNG TPM probe tests; no Windows TPM commands run."""
import base64
import unittest
from unittest import mock

import command2_disposable_tpm_key_marker as m

GUEST = "192.168.241.101"
BRIDGE = "192.168.241.1"
VM = "win11_1"


def reply(word):
    return {"message": "Successfully executed command",
            "stdout": base64.b64encode((word + "\r\n").encode()).decode()}


class TPMMarkerTests(unittest.TestCase):
    def test_only_fixed_disposable_clone_key_names(self):
        self.assertEqual(m.approved_name("win11_1"),
                         "CAPE_BENIGN_DISPOSABLE_TPM_REVERT_WIN11_1")
        self.assertTrue(m.approved_name("win11_16").endswith("_16"))
        for name in ("win11", "win11_0", "win11_17",
                     "win11_1;Remove-Item", "../win11_1", "win11_01"):
            with self.assertRaises(m.TPMKeyBlocked):
                m.approved_name(name)

    def test_creator_pins_hardware_provider_and_no_dangerous_operations(self):
        src = m.script_for(VM, "create")
        self.assertIn("Microsoft Platform Crypto Provider", src)
        self.assertIn("CngKeyCreationParameters", src)
        self.assertIn("CngKey]::Create", src)
        self.assertIn("TPM_MARKER_ALREADY_EXISTS", src)
        self.assertIn("CngExportPolicies]::None", src)
        self.assertNotIn("CngKey]::Delete", src)
        for bad in ("Clear-Tpm", "Remove-Item", "Set-MpPreference",
                    "Invoke-WebRequest", "ExecutionPolicy Bypass",
                    "Microsoft Software Key Storage Provider"):
            self.assertNotIn(bad, src)

    def test_read_only_no_key_creation(self):
        src = m.script_for(VM, "read")
        self.assertIn("CAPE_TPM_KEY_PRESENT", src)
        self.assertIn("CAPE_TPM_KEY_ABSENT", src)
        self.assertNotIn("CngKey]::Create", src)

    def test_probed_absence_pins_guest_bridge_and_fixed_encoded_command(self):
        with mock.patch.object(m.transport, "agent_post",
                               return_value=reply("CAPE_TPM_KEY_ABSENT")) as post:
            self.assertFalse(m.key_exists(GUEST, BRIDGE, VM))
        args = post.call_args.args
        self.assertEqual(args[:3], (GUEST, BRIDGE, "/execute"))
        self.assertIn(b"encoding=base64", args[3])
        self.assertIn(b"-EncodedCommand", args[3])

    def test_report_present_and_create(self):
        with mock.patch.object(m.transport, "agent_post",
                               side_effect=[reply("CAPE_TPM_KEY_PRESENT"),
                                            reply("CAPE_TPM_KEY_CREATED")]):
            self.assertTrue(m.key_exists(GUEST, BRIDGE, VM))
            self.assertTrue(m.create_key(GUEST, BRIDGE, VM))

    def test_unexpected_or_invalid_result_refuses_success(self):
        for bad in (reply("unknown"),
                    reply("CAPE_TPM_KEY_ABSENT\nextra"),
                    {"message": "error", "stdout": ""},
                    {"message": "Successfully executed command", "stdout": "!bad"}):
            with mock.patch.object(m.transport, "agent_post", return_value=bad):
                with self.assertRaises(m.TPMKeyBlocked):
                    m.key_exists(GUEST, BRIDGE, VM)

    def test_wrong_bridges_and_unreviewed_source_refused(self):
        for ip, source in (("8.8.8.8", BRIDGE),
                           (GUEST, "192.168.241.2"),
                           (GUEST, "127.0.0.1")):
            with mock.patch.object(m.transport, "agent_post",
                                   side_effect=AssertionError("No contact")):
                with self.assertRaises(m.TPMKeyBlocked):
                    m.key_exists(ip, source, VM)

    def test_creator_never_accepts_arbitrary_command_text(self):
        for bad in ("delete", "clear", "verify;os.system('x')"):
            with self.assertRaises(m.TPMKeyBlocked):
                m.script_for(VM, bad)


if __name__ == "__main__":
    unittest.main()
