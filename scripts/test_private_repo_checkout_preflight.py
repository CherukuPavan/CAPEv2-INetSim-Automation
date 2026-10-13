"""Read-only test of private authenticated development source checker."""
from __future__ import annotations
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest
import private_repo_checkout_preflight as m

SHA="a"*40

class PrivateCheckoutTests(unittest.TestCase):
    def test_exact_https_and_ssh_github_remote_with_no_embedded_token(self):
        for remote in (
            "https://github.com/CherukuPavan/CAPEv2-INetSim-Automation.git",
            "https://github.com/CherukuPavan/CAPEv2-INetSim-Automation",
            "git@github.com:CherukuPavan/CAPEv2-INetSim-Automation.git",
        ):
            with self.subTest(remote=remote):
                self.assertIsNotNone(m.accepted_remote(remote))
        for remote in (
            "https://username:secret@github.com/CherukuPavan/CAPEv2-INetSim-Automation.git",
            "https://github.com.evil.test/CherukuPavan/CAPEv2-INetSim-Automation",
            "http://github.com/CherukuPavan/CAPEv2-INetSim-Automation",
            "https://github.com/someone/CAPEv2-INetSim-Automation",
            "file:///tmp/CAPEv2-INetSim-Automation",
            "ssh://other@fake-github.com/a/b",
            "https://github.com/CherukuPavan/CAPEv2-INetSim-Automation.git?token=abc",
            "git@evil.test:CherukuPavan/CAPEv2-INetSim-Automation.git",
        ):
            with self.subTest(remote=remote):
                self.assertIsNone(m.accepted_remote(remote))

    def test_readonly_exact_development_tree_git_commands(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)
            results=iter([str(target),"development",
                         "git@github.com:CherukuPavan/CAPEv2-INetSim-Automation.git",
                         SHA,""])
            calls=[]
            def fake(*cmd):
                calls.append(cmd)
                return next(results)
            with patch.object(m,"git",side_effect=fake):
                r=m.inspect(target,SHA)
            self.assertTrue(r["working_tree_clean"])
            self.assertEqual(r["branch"],"development")
            self.assertEqual(r["commit"],SHA)
            self.assertFalse(r["host_modified"])
            self.assertEqual(len(calls),5)
            self.assertNotIn("reset",str(calls))

    def test_wrong_branch_rejected_even_if_commit_matches(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)
            with patch.object(m,"git",side_effect=[str(target),"main"]), \
                 self.assertRaisesRegex(m.PrivateCheckoutBlocked,"NOT main"):
                m.inspect(target,SHA)

    def test_mismatched_sha_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for value in ("", "development", "a"*39, "A"*40,
                          "HEAD", "a"*40+"junk"):
                with self.subTest(value=value), \
                     self.assertRaises(m.PrivateCheckoutBlocked):
                    m.inspect(root,value)

    def test_private_repo_remote_secrets_never_in_error(self):
        token="SENSITIVE_OAUTH_DO_NOT_ECHO"
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            remote="https://someone:"+token+"@github.com/"+m.OWNER+"/"+m.REPO+".git"
            with patch.object(m,"git",side_effect=[
                 str(root),"development",remote]), \
                 self.assertRaisesRegex(m.PrivateCheckoutBlocked,
                                         "embedded URL credentials") as e:
                m.inspect(root,SHA)
            self.assertNotIn(token,str(e.exception))

    def test_dirty_tree_rejected_even_on_development(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with patch.object(m,"git",side_effect=[
                 str(root),"development",
                 "git@github.com:"+m.OWNER+"/"+m.REPO+".git",
                 SHA,"?? private-rclone.conf"]), \
                 self.assertRaisesRegex(m.PrivateCheckoutBlocked,"untracked"):
                m.inspect(root,SHA)

    def test_no_host_install_or_github_auth_side_effect(self):
        src=Path(m.__file__).read_text()
        for word in ("systemctl restart", "git clone", "gh auth login",
                     "apt-get install", "shell=True", "os.system(",
                     "virsh start", "snapshot-revert", "write_text("):
            self.assertNotIn(word,src)

if __name__=="__main__":
    unittest.main()
