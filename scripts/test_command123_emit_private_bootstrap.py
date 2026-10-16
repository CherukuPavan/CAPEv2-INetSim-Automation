"""Synthetic tests for single-paste private authenticated source bootstrap."""
import ast
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import command123_emit_private_bootstrap as e
import command123_private_pinned_checkout as c


REV = "a" * 40
BLOB = "b" * 40


class BootstrapEmitterTests(unittest.TestCase):
    def test_single_shell_command_is_pinned_and_compiles(self):
        command = e.render(REV, BLOB)
        self.assertTrue(command.startswith("python3 - <<'CAPE_VERIFIED_PRIVATE_BOOTSTRAP'\n"))
        self.assertTrue(command.rstrip().endswith("CAPE_VERIFIED_PRIVATE_BOOTSTRAP"))
        raw = command.split("\n", 1)[1].rsplit("\nCAPE_VERIFIED_PRIVATE_BOOTSTRAP", 1)[0]
        ast.parse(raw)
        self.assertIn('REVISION = "' + REV + '"', raw)
        self.assertIn('EXPECTED_HELPER_BLOB = "' + BLOB + '"', raw)

    def test_bootstrap_fetches_exact_private_file_and_verifies_blob(self):
        command = e.render(REV, BLOB)
        self.assertIn('/contents/" + PATH + "?ref=" + REVISION', command)
        self.assertIn('hashlib.sha1(', command)
        self.assertIn('if got != EXPECTED_HELPER_BLOB:', command)
        self.assertIn('base64.b64decode(doc["content"], validate=True)', command)
        self.assertIn('Bearer " + token', command)
        self.assertIn('getpass.getpass(', command)
        self.assertIn('namespace["main"](bootstrap_token=token)', command)
        self.assertNotIn("GIT_ASKPASS", command)
        self.assertNotIn("os.environ[", command)

    def test_reject_unpinned_and_tainted_identifiers(self):
        for bad in ("abc", "A" * 40, "a" * 40 + ";rm -rf /",
                    "a" * 39 + "\n"):
            with self.assertRaises(ValueError):
                e.render(bad, BLOB)
        with self.assertRaises(ValueError):
            e.render(REV, REV)

    def test_in_memory_token_handoff_avoids_second_prompt(self):
        argv = sys.argv
        try:
            sys.argv = ["verified-private-source", "--revision", REV]
            with mock.patch.object(c.os, "geteuid", return_value=1000), \
                 mock.patch.object(c.sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(c.os, "uname", return_value=SimpleNamespace(
                     machine="x86_64")), \
                 mock.patch.object(c.getpass, "getpass",
                     side_effect=AssertionError("Do not prompt twice")), \
                 mock.patch.object(c, "acquire",
                     return_value=Path("/home/test/.local/share/cape-three-command/" + REV)
                     ) as acquire:
                value = c.main(bootstrap_token="a-readonly-test-token")
            self.assertEqual(value, 0)
            acquire.assert_called_once()
            self.assertEqual(acquire.call_args.args[0], REV)
            self.assertEqual(acquire.call_args.args[1], "a-readonly-test-token")
        finally:
            sys.argv = argv


if __name__ == "__main__":
    unittest.main()
