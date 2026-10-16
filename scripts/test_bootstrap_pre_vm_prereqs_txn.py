"""Nonmutating shell integration checks for transaction-bound base APT stage."""
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "bootstrap_pre_vm_prereqs.sh"


class ShellTransactionGuards(unittest.TestCase):
    def run_shell(self, *args):
        return subprocess.run(["bash", str(SCRIPT), *args],
                              capture_output=True, text=True, timeout=12)

    def test_script_parses_under_bash(self):
        p = subprocess.run(["bash", "-n", str(SCRIPT)],
                           capture_output=True, text=True, timeout=12)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_transaction_cannot_be_used_in_untracked_plan(self):
        p = self.run_shell("--plan",
                           "--deployment-transaction", "a" * 32,
                           "--approved-host", "rakshati")
        self.assertEqual(p.returncode, 2)
        self.assertIn("requires --apply", p.stderr)

    def test_bad_transaction_id_fails_before_host_changes(self):
        p = self.run_shell("--apply",
                           "--deployment-transaction", "../../etc",
                           "--approved-host", "rakshati")
        self.assertEqual(p.returncode, 2)
        self.assertIn("Invalid transaction ID", p.stderr)

    def test_no_unpaired_host_identifier(self):
        p = self.run_shell("--apply",
                           "--approved-host", "rakshati")
        self.assertEqual(p.returncode, 2)
        self.assertIn("BOTH transaction/host", p.stderr)

    def test_invalid_host_fails_before_host_changes(self):
        p = self.run_shell("--apply",
                           "--deployment-transaction", "a" * 32,
                           "--approved-host", "SSL-55")
        self.assertEqual(p.returncode, 2)
        self.assertIn("Invalid approved host", p.stderr)

    def test_script_delegates_transaction_to_provenance_wrapper(self):
        text = SCRIPT.read_text()
        self.assertIn('command123_tracked_prereqs.py" --mode apply', text)
        self.assertIn('--transaction "$DEPLOYMENT_TRANSACTION"', text)
        self.assertIn('--approved-host "$APPROVED_HOST"', text)
        self.assertIn('exec sudo python3 -B', text)


if __name__ == "__main__":
    unittest.main()
