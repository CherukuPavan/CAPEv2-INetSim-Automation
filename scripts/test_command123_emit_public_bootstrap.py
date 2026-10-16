"""Offline regression: source-only public bootstrap pins bytes without secrets."""
import ast
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import command123_emit_public_bootstrap as e
import command123_private_pinned_checkout as checkout

REV = "a" * 40
BLOB = "b" * 40


class PublicBootstrapTests(unittest.TestCase):
    def test_single_paste_command_compiles_and_pins_both_objects(self):
        command = e.render(REV, BLOB)
        self.assertTrue(command.startswith(
            "python3 - <<'CAPE_VERIFIED_PUBLIC_BOOTSTRAP'\n"))
        self.assertTrue(command.rstrip().endswith(
            "CAPE_VERIFIED_PUBLIC_BOOTSTRAP"))
        raw = command.split("\n",1)[1].rsplit(
            "\nCAPE_VERIFIED_PUBLIC_BOOTSTRAP",1)[0]
        ast.parse(raw)
        self.assertIn('REVISION = "'+REV+'"',raw)
        self.assertIn('EXPECTED_BLOB = "'+BLOB+'"',raw)
        self.assertIn('b"\\0"',raw)

    def test_no_secret_or_private_token_is_requested_in_public_bootstrap(self):
        command = e.render(REV,BLOB)
        self.assertNotIn("getpass",command)
        self.assertNotIn("Bearer ",command)
        self.assertNotIn("os.environ",command)
        self.assertIn("base64.b64decode",command)
        self.assertIn("hashlib.sha1",command)
        self.assertIn('["verified-public-source", "--revision", REVISION, "--public"]',command)
        self.assertIn("env[\"main\"]()",command)

    def test_bad_or_tainted_pinned_ids_refused(self):
        for invalid in ("", "a"*39, "a"*41, "A"*40,
                        "a"*40+"; echo untrusted"):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(ValueError):
                    e.render(invalid,BLOB)
                with self.assertRaises(ValueError):
                    e.render(REV,invalid)
        with self.assertRaises(ValueError):
            e.render(REV,REV)

    def test_public_checkout_cannot_prompt_for_github_token(self):
        original = sys.argv
        try:
            sys.argv=["verified-public-source","--revision",REV,"--public"]
            with mock.patch.object(checkout.os,"geteuid",return_value=1000), \
                 mock.patch.object(checkout.sys.stdin,"isatty",return_value=True), \
                 mock.patch.object(checkout.os,"uname",return_value=SimpleNamespace(
                     machine="x86_64")), \
                 mock.patch.object(checkout.getpass,"getpass",
                                   side_effect=AssertionError("must not prompt")), \
                 mock.patch.object(checkout,"acquire",
                                   return_value=Path("/tmp/public-source/"+REV)) as acquire:
                self.assertEqual(checkout.main(),0)
            acquire.assert_called_once_with(REV,None,Path.home())
        finally:
            sys.argv=original


if __name__=="__main__":
    unittest.main()
