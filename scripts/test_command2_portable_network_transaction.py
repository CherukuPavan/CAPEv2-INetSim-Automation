"""Offline network creation ownership receipts; no nft/libvirt mutations."""
from pathlib import Path
from contextlib import ExitStack
import tempfile
import unittest
from unittest import mock

import command2_portable_network_transaction as owned

HOST = "rakshati"
PLAN = {
    "approved_host": HOST, "network_name": "cape-analysis-isolated",
    "bridge": "cape-lab0", "nft_table": "cape_analysis_cmd2_guard",
    "network_xml_sha256": "a" * 64,
    "nft_rules_sha256": "b" * 64,
    "nft_table_preexisting": False,
    "libvirt_network_preexisting": False,
    "guests_running": False,
}


class NetworkOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.journal = self.parent / "command2-identity-reservation.json"
        self.journal.write_bytes(b"durable guest reservation\n")
        # Exercise all exact input/state/atomic-write code paths without
        # altering system-owned directories in an unprivileged CI runner.
        self.patchers = [
            mock.patch.object(owned, "safe_dir", return_value=self.parent),
            mock.patch.object(owned, "root_private", return_value=True),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_receipt_precedes_network_mutation_and_is_private(self):
        result = owned.begin(HOST, self.journal, dict(PLAN))
        self.assertEqual(result["status"], "prepared")
        self.assertFalse(result["retries_authorized"])
        self.assertEqual(result["network"], "cape-analysis-isolated")
        self.assertEqual((self.parent / owned.RECEIPT).stat().st_mode & 0o777,
                         0o600)
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.begin(HOST, self.journal, dict(PLAN))

    def test_five_steps_monotonic_and_replay_refused(self):
        owned.begin(HOST, self.journal, dict(PLAN))
        for before, after in zip(owned.PHASES[:4], owned.PHASES[1:5]):
            kwargs = ({"post_state": {
                "post_live_libvirt_xml_sha256": "c" * 64,
                "post_nft_stateless_sha256": "d" * 64}}
                if after == "verified" else {})
            update = owned.advance(self.journal, before, after, **kwargs)
            self.assertEqual(update["status"], after)
        self.assertEqual(owned.read(owned.record_path(self.journal))["status"],
                         "verified")
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.advance(self.journal, "prepared", "nft_applied")

    def test_rollback_journal_requires_exact_live_post_hashes(self):
        owned.begin(HOST, self.journal, dict(PLAN))
        for before, after in zip(owned.PHASES[:4], owned.PHASES[1:5]):
            if after == "verified":
                with self.assertRaises(owned.NetworkTransactionBlocked):
                    owned.advance(self.journal, before, after)
                owned.advance(self.journal, before, after, post_state={
                    "post_live_libvirt_xml_sha256": "f" * 64,
                    "post_nft_stateless_sha256": "e" * 64})
            else:
                owned.advance(self.journal, before, after)
        result = owned.advance(self.journal, "verified", "rollback_started")
        self.assertEqual(result["post_nft_stateless_sha256"], "e" * 64)
        self.assertEqual(result["status"], "rollback_started")

    def test_attempted_skipped_network_step_blocks(self):
        owned.begin(HOST, self.journal, dict(PLAN))
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.advance(self.journal, "prepared", "network_defined")

    def test_prior_ownership_cannot_be_inferred_from_colliding_table(self):
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.begin(HOST, self.journal, {
                **PLAN, "nft_table_preexisting": True})
        self.assertFalse((self.parent / owned.RECEIPT).exists())

    def test_attested_table_name_cannot_be_changed(self):
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.begin(HOST, self.journal, {
                **PLAN, "nft_table": "unrelated_user_table"})
        self.assertFalse((self.parent / owned.RECEIPT).exists())

    def test_tampered_receipt_rejected_before_next_mutation(self):
        owned.begin(HOST, self.journal, dict(PLAN))
        path = owned.record_path(self.journal)
        source = path.read_text()
        path.write_text(source.replace("cape-analysis-isolated",
                                       "default", 1))
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.advance(self.journal, "prepared", "nft_applied")

    def test_file_path_and_payload_bounded(self):
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.validate({"schema": 1, "status": "verified"})
        with self.assertRaises(owned.NetworkTransactionBlocked):
            owned.write(self.parent / owned.RECEIPT,
                        {**PLAN, "status": "prepared"}, first=True)

    def test_create_only_network_installer_has_journal_before_first_write(self):
        import command2_portable_network_install as install
        source = Path(install.__file__).read_text()
        start = source.index('owned_network.begin(host,journal,initial)')
        nft = source.index('command("nft","-f","-",input_text=initial["nft_rules"])')
        self.assertLess(start, nft)
        for step in (
                'owned_network.advance(journal,"prepared","nft_applied")',
                'owned_network.advance(journal,"nft_applied","network_defined")',
                'owned_network.advance(journal,"network_defined","network_started")',
                'owned_network.advance(journal,"network_started","verified",'):
            self.assertIn(step, source)


if __name__ == "__main__":
    unittest.main()
