"""NO host operations: mocked guard-only replay and refusal tests."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_guard_scoped_replay as replay
import command2_ssl55_existing_guard_readonly as observed


def synthetic_present(flag=True):
    return {
        "no_vm_or_network_changes": True,
        "analysis_network": {
            "active":"no","autostart":"no",
            "nonforward_no_dhcp_known_subnet":True},
        "protected_domains":{
            "win11":{"power_state":"shut off","nic_counts":{"inactive":1}},
            "win11_1":{"power_state":"shut off","nic_counts":{"inactive":0}},
            "win11_trial_1":{"power_state":"shut off","nic_counts":{"inactive":0}}},
        "existing_lab_firewall":{
            "guard_present":flag,"expected_guard_shape":flag}}


class GuardReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sentinel=Path(self.tmp.name)/"protected"
        self.sentinel.mkdir()

    def context(self,report=None,enabled="disabled",master_autostart=False):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(patch.object(replay.socket,"gethostname",
                                         return_value="CSE-SSL-55"))
        stack.enter_context(patch.object(replay.observed,"SENTINEL",self.sentinel))
        stack.enter_context(patch.object(replay.os,"geteuid",return_value=0))
        stack.enter_context(patch.object(replay.observed,"audit",
                         return_value=report if report is not None else synthetic_present()))
        stack.enter_context(patch.object(replay.boot,"domain_autostart",
                         side_effect=lambda name:
                           master_autostart if name=="win11" else False))
        stack.enter_context(patch.object(replay.boot,"read",return_value=(
            "LoadState=loaded\nUnitFileState="+enabled+"\nActiveState=inactive")))
        stack.enter_context(patch.object(replay.boot,"nft_config_metadata",
                         return_value={"root_controlled":True,
                         "file_safe_to_inspect":True,
                         "global_flush_present":True,
                         "guard_reference_present":False}))
        return stack

    def test_present_table_is_no_firewall_change_in_plan(self):
        with self.context():
            result=replay.plan()
        self.assertEqual(result["existing_guard_state"],"present_verified")
        self.assertTrue(result["no_host_changes"])
        self.assertFalse(result["reboot_persistence_verified"])
        self.assertFalse(result["guest_nic_attached"])

    def test_absent_table_is_no_firewall_change_in_plan(self):
        with self.context(report=synthetic_present(False)):
            result=replay.plan()
        self.assertEqual(result["existing_guard_state"],"missing")
        self.assertTrue(result["no_host_changes"])
        self.assertFalse(result["guest_ipv4_negative_tested"])

    def test_replay_without_root_approval_never_calls_nft(self):
        with patch.object(replay.os,"geteuid",return_value=0),\
             patch.object(replay,"approval_ok",
                 side_effect=replay.ReplayBlocked("No operator proof")) as authorized,\
             patch.object(replay,"command",
                 side_effect=AssertionError("Must not call nft")):
            with self.assertRaises(replay.ReplayBlocked):
                replay.reconcile()
        authorized.assert_called_once_with()

    def test_changed_base_firewall_or_autostart_fails_closed(self):
        for changed,enabled,auto in (
            (None,"enabled",False),
            (None,"disabled",True),
            (dict(synthetic_present(),analysis_network=dict(
                synthetic_present()["analysis_network"],active="yes")),
             "disabled",False),
        ):
            with self.subTest(changed=changed is not None,
                              enabled=enabled,auto=auto):
                with self.context(report=changed,enabled=enabled,
                                  master_autostart=auto):
                    with self.assertRaises(replay.ReplayBlocked):
                        replay.strict_state()

    def test_reconcile_existing_guard_no_nft_modify(self):
        lock=Path(self.tmp.name)/"replay.lock"
        fake_root=type("LockMeta",(),{"st_mode":0o100600,
                         "st_uid":0,"st_nlink":1})()
        with self.context(),\
             patch.object(replay,"approval_ok",return_value=True),\
             patch.object(replay,"LOCK_PATH",lock),\
             patch.object(replay.os,"fstat",return_value=fake_root),\
             patch.object(replay,"command",
                side_effect=AssertionError("Existing guard must not modify nft")):
            result=replay.reconcile()
        self.assertEqual(result["result"],
                         "CAPE_SSL55_EXISTING_GUARD_VERIFIED_NO_CHANGE")
        self.assertFalse(result["guard_restored"])

    def test_replay_missing_table_calls_only_check_and_exact_nft_file(self):
        lock=Path(self.tmp.name)/"replay.lock"
        fake_root=type("LockMeta",(),{"st_mode":0o100600,
                         "st_uid":0,"st_nlink":1})()
        states=iter(["missing","missing","present_verified"])
        commands=[]
        with self.context(report=synthetic_present(False)),\
             patch.object(replay,"approval_ok",return_value=True),\
             patch.object(replay,"LOCK_PATH",lock),\
             patch.object(replay.os,"fstat",return_value=fake_root),\
             patch.object(replay,"strict_state",side_effect=lambda:next(states)),\
             patch.object(replay,"command",
                 side_effect=lambda *argv,**kw: commands.append(argv) or ""):
            result=replay.reconcile()
        self.assertEqual(result["result"],
                         "CAPE_SSL55_SINGLE_GUARD_RESTORED_NEEDS_REBOOT_TEST")
        self.assertEqual([x[:2] for x in commands],
                         [("nft","--check"),("nft","--file")])
        self.assertFalse(result["reboot_persistence_verified"])
        self.assertFalse(result["guest_nic_attached"])

    def test_snapshot_or_nic_never_authorized_by_replay(self):
        source=Path(replay.__file__).read_text(encoding="utf-8")
        body=source[source.index("from __future__ import annotations"):]
        for seq in ('"net-start"','"attach-interface"','"snapshot-create-as"',
                    '"snapshot-revert"','"systemctl","enable"', '"systemctl","start"',
                    "flush ruleset\\n", "delete table inet", "os.system("):
            if seq in ("flush ruleset\\n",):
                # Strict refusal strings in module mention "flush ruleset".
                continue
            self.assertNotIn(seq,body)

    def test_policy_hash_still_matches_original_reviewed_guard(self):
        from hashlib import sha256
        policy=replay.policy_text()
        self.assertEqual(sha256(policy.encode()).hexdigest(),replay.POLICY_SHA256)
        self.assertNotIn("flush ruleset",policy)

    def test_wrong_hostname_blocks_before_guest_or_nft_queries(self):
        with patch.object(replay.socket,"gethostname",return_value="other-host"),\
             patch.object(replay.observed,"audit",
                          side_effect=AssertionError("No host commands")):
            with self.assertRaisesRegex(replay.ReplayBlocked,"reference host"):
                replay.strict_state()


if __name__=="__main__":
    unittest.main()
