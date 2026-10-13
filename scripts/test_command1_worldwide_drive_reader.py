#!/usr/bin/env python3
"""Offline tests of root-private worldwide service-account reader (no real OAuth)."""
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import command1_worldwide_drive_reader as m


class WorldReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = self.root / "service.json"
        self.key.write_text(json.dumps({
            "type": "service_account",
            "client_email": "cape-reader@example-project.iam.gserviceaccount.com",
            "private_key": "-----BEGIN PRIVATE KEY-----\\nMOCK\\n-----END PRIVATE KEY-----",
            "token_uri": "https://oauth2.googleapis.com/token",
        }))
        self.key.chmod(0o600)
        self.args = types.SimpleNamespace(
            approved_host="remote-village",
            service_account_file=self.key,
            shared_parent_folder_id="ABCDefghi_123456789",
            crypt_subfolder="master-backups",
            config=self.root / "readonly.conf",
        )

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_plan_never_writes_and_never_needs_personal_login(self, _):
        result = m.plan(self.args)
        self.assertEqual(result["result"], "WORLDWIDE_PRIVATE_DRIVE_READER_PLAN_ONLY")
        self.assertFalse(result["personal_google_login_on_target_required"])
        self.assertFalse(result["public_google_drive_link_required"])
        self.assertFalse(self.args.config.exists())

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_reject_wrong_host_or_source(self, hostname):
        self.args.approved_host = "another"
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)
        self.args.approved_host = "CSE-SSL-55"
        hostname.return_value = "CSE-SSL-55"
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_existing_config_is_preserved(self, _):
        self.args.config.write_text("do not overwrite")
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)
        self.assertEqual(self.args.config.read_text(), "do not overwrite")

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_symlink_and_insecure_key_rejected(self, _):
        link = self.root / "link.json"
        link.symlink_to(self.key)
        self.args.service_account_file = link
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)
        self.args.service_account_file = self.key
        self.key.chmod(0o644)
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_reject_invalid_drive_folder(self, _):
        self.args.shared_parent_folder_id = "https://drive.google.com/folders/id"
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)
        self.args.shared_parent_folder_id = "ABCDefghi_123456789"
        self.args.crypt_subfolder = "../../outside"
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_create_one_restricted_0600_reader_only(self, _):
        with mock.patch.object(m.sys, "stdin") as stdin, \
             mock.patch.object(m, "input", return_value=m.APPROVAL), \
             mock.patch.object(m.getpass, "getpass",
                               side_effect=["existing-crypt-password",
                                            "existing-crypt-password",
                                            "existing-salt-password"]), \
             mock.patch.object(m, "obscure",
                               side_effect=["obscured_crypt_password",
                                            "obscured_salt_password"]):
            stdin.isatty.return_value = True
            result = m.setup(self.args)
        self.assertEqual(result["result"],
                         "WORLDWIDE_PRIVATE_DRIVE_READER_CONFIG_CREATED")
        self.assertEqual(os.stat(self.args.config).st_mode & 0o777, 0o600)
        c = self.args.config.read_text()
        self.assertIn("scope = drive.readonly", c)
        self.assertIn("remote = cape_drive:master-backups", c)
        self.assertIn("root_folder_id = ABCDefghi_123456789", c)
        self.assertNotIn("existing-crypt-password", c)
        self.assertNotIn("token =", c)
        with self.assertRaises(m.ReaderBlocked):
            m.plan(self.args)

    @mock.patch.object(m.socket, "gethostname", return_value="remote-village")
    def test_password_mismatch_writes_nothing(self, _):
        with mock.patch.object(m.sys, "stdin") as stdin, \
             mock.patch.object(m, "input", return_value=m.APPROVAL), \
             mock.patch.object(m.getpass, "getpass",
                               side_effect=["first-password", "wrong-password"]):
            stdin.isatty.return_value = True
            with self.assertRaises(m.ReaderBlocked):
                m.setup(self.args)
        self.assertFalse(self.args.config.exists())


if __name__ == "__main__":
    unittest.main()
