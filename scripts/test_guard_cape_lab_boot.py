#!/usr/bin/env python3
"""Pure tests, mock all root/nft commands. No host modifications."""
import hashlib
import unittest
from unittest.mock import patch
import guard_cape_lab_boot as b

class Tests(unittest.TestCase):
    def test_policy_matches_operator_verified_sha(self):
        source=b.prepare_source()
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                         b.installer.APPROVED_POLICY_SHA256)

    def test_existing_guard_verification_never_applies_nft(self):
        with patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.LOCK.__class__,"is_symlink",return_value=False),\
             patch.object(b.os,"open",return_value=10),\
             patch.object(b.os,"fstat") as stat,\
             patch.object(b.os,"close"),\
             patch.object(b.fcntl,"flock"),\
             patch.object(b,"nft_exists",return_value=True),\
             patch.object(b.installer,"verify_installed") as verify,\
             patch.object(b.installer,"execute") as exec_mock:
            stat.return_value.st_uid=0
            stat.return_value.st_mode=0o600
            result=b.reconcile()
        self.assertFalse(result["new_firewall_table_created"])
        verify.assert_called_once_with()
        exec_mock.assert_not_called()

    def test_unknown_nft_table_error_blocks_instead_of_overwriting(self):
        from subprocess import CompletedProcess
        with patch.object(b.subprocess,"run",return_value=CompletedProcess(
                ["nft"],returncode=1,stdout="",stderr="Operation not permitted")):
            with self.assertRaisesRegex(b.GuardBootError,"Cannot distinguish"):
                b.nft_exists()

    def test_missing_table_is_identified(self):
        from subprocess import CompletedProcess
        with patch.object(b.subprocess,"run",return_value=CompletedProcess(
                ["nft"],returncode=1,stdout="",
                stderr="Error: No such file or directory")):
            self.assertFalse(b.nft_exists())

    def test_lock_permission_rejects(self):
        with patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.LOCK.__class__,"is_symlink",return_value=False),\
             patch.object(b.os,"open",return_value=10),\
             patch.object(b.os,"fstat") as stat,\
             patch.object(b.os,"close"),\
             patch.object(b,"nft_exists") as inspect:
            stat.return_value.st_uid=0
            stat.return_value.st_mode=0o666
            with self.assertRaisesRegex(b.GuardBootError,"permissions"):
                b.reconcile()
            inspect.assert_not_called()

    def test_nonroot_rejected_without_net_access(self):
        with patch.object(b.os,"geteuid",return_value=1000),\
             patch.object(b,"nft_exists") as inspect:
            with self.assertRaisesRegex(b.GuardBootError,"root"):
                b.reconcile()
            inspect.assert_not_called()

if __name__=="__main__":unittest.main()
