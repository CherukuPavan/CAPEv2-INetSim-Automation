"""Synthetic exact-owned network+nft undo tests. Never touch real host."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import tempfile
import unittest
from unittest import mock

import command2_portable_network_rollback as m
import command2_portable_network_transaction as receipt

HOST = "rakshati"
NET_XML = ('<network><name>cape-analysis-isolated</name>'
           '<port isolated="yes"/><bridge name="cape-lab0"/>'
           '<dns enable="no"/></network>')
NFT = '{"nftables":[{"table":{"family":"inet","name":"cape_analysis_cmd2_guard"}}]}'
GUEST_XML = ('<domain><name>win11_1</name><devices><interface type="network">'
             '<source network="cape-analysis-isolated"/></interface>'
             '</devices></domain>')


def sealed(journal):
    return {
        "schema":1,"status":"verified","host":HOST,
        "network":"cape-analysis-isolated",
        "bridge":"cape-lab0","table":"cape_analysis_cmd2_guard",
        "reservation_sha256":hashlib.sha256(journal.read_bytes()).hexdigest(),
        "nft_rules_sha256":"a" * 64,
        "network_xml_sha256":"b" * 64,
        "post_live_libvirt_xml_sha256":hashlib.sha256(NET_XML.encode()).hexdigest(),
        "post_nft_stateless_sha256":hashlib.sha256(NFT.encode()).hexdigest(),
        "both_resources_absent_before":True,
        "guests_stopped_before":True,
        "retries_authorized":False,
    }


class RollbackTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.journal = self.root / "command2-identity-reservation.json"
        self.journal.write_bytes(b"exact private journal")
        self.doc = sealed(self.journal)

    def stubs(self, stack, *, nft=NFT, xml=NET_XML, guest=False):
        stack.enter_context(mock.patch.object(
            m.workflow, "canonical_host", return_value=HOST))
        stack.enter_context(mock.patch.object(
            m.receipt, "record_path", return_value=self.root / "network.json"))
        stack.enter_context(mock.patch.object(
            m.receipt, "read", return_value=self.doc))
        def libvirt(*args):
            if args == ("net-info", m.NETWORK):
                return ("Active: yes\nPersistent: yes\nAutostart: no\n")
            if args == ("net-dumpxml", m.NETWORK):
                return xml
            if args == ("list", "--all", "--name"):
                return "win11_1" if guest else ""
            if args == ("list", "--name"):
                return ""
            if args == ("dumpxml", "--inactive", "win11_1"):
                return GUEST_XML
            raise AssertionError("Unexpected libvirt call "+str(args))
        stack.enter_context(mock.patch.object(m, "virsh", side_effect=libvirt))
        stack.enter_context(mock.patch.object(m, "nft", return_value=nft))

    def test_exact_owned_isolated_network_plan_readonly(self):
        with ExitStack() as stack:
            self.stubs(stack)
            result = m.inspect(HOST, self.journal)
        self.assertTrue(result["network_and_nft_were_absent_before_deployment"])
        self.assertFalse(result["resource_deletion_performed"])
        self.assertFalse(result["full_deployment_rollback_complete"])

    def test_refuse_if_nft_rules_changed_after_deployment(self):
        with ExitStack() as stack:
            self.stubs(stack,nft='{"changed":"foreign"}')
            with self.assertRaisesRegex(m.NetworkRollbackBlocked,
                                        "nft table"):
                m.inspect(HOST,self.journal)

    def test_refuse_if_another_vm_still_references_network(self):
        with ExitStack() as stack:
            self.stubs(stack,guest=True)
            with self.assertRaisesRegex(m.NetworkRollbackBlocked,
                                        "still references"):
                m.inspect(HOST,self.journal)

    def test_refuse_if_live_network_xml_drifted(self):
        with ExitStack() as stack:
            self.stubs(stack,xml=NET_XML.replace("isolated", "unsafe"))
            with self.assertRaisesRegex(m.NetworkRollbackBlocked,
                                        "XML drifted"):
                m.inspect(HOST,self.journal)

    def test_refuse_if_journal_changed(self):
        self.journal.write_bytes(b"foreign edits")
        with ExitStack() as stack:
            self.stubs(stack)
            with self.assertRaisesRegex(m.NetworkRollbackBlocked,
                                        "Reservation journal changed"):
                m.inspect(HOST,self.journal)

    def test_undo_order_network_first_then_keep_firewall_until_undefined(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(
                m.sys.stdin, "isatty", return_value=True))
            stack.enter_context(mock.patch.object(
                m.deployment, "no_live_work"))
            plan = {"result":"COMMAND2_OWNED_ISOLATED_NETWORK_ROLLBACK_PLAN"}
            stack.enter_context(mock.patch.object(m, "inspect",
                                                   return_value=plan))
            stack.enter_context(mock.patch("builtins.input",
                return_value="UNDEFINE-ONLY-OWNED-CAPE-ISOLATED-NETWORK"))
            stack.enter_context(mock.patch.object(
                m, "LOCK", self.root / "network-undo.lock"))
            def fake_fstat(fd):
                st = real_fstat(fd)
                return SimpleNamespace(st_mode=st.st_mode,
                    st_nlink=st.st_nlink,st_uid=0)
            real_fstat = m.os.fstat
            stack.enter_context(mock.patch.object(
                m.os, "fstat", side_effect=fake_fstat))
            sequence = []
            def libvirt(*args):
                if args == ("net-destroy", m.NETWORK):
                    sequence.append("destroy")
                    return ""
                if args == ("net-info", m.NETWORK):
                    return "Active: no\n"
                if args == ("net-undefine", m.NETWORK):
                    sequence.append("undefine")
                    return ""
                if args == ("net-list", "--all", "--name"):
                    return ""
                raise AssertionError("Unexpected libvirt "+str(args))
            stack.enter_context(mock.patch.object(m, "virsh",
                                                   side_effect=libvirt))
            def nft(*args):
                if args == ("-j", "-s", "list", "table", "inet", m.TABLE):
                    return NFT
                if args == ("delete", "table", "inet", m.TABLE):
                    sequence.append("delete_nft")
                    return ""
                if args == ("-j", "list", "tables"):
                    return json.dumps({"nftables":[]})
                raise AssertionError("Unexpected nft "+str(args))
            stack.enter_context(mock.patch.object(m, "nft",
                                                   side_effect=nft))
            stack.enter_context(mock.patch.object(
                m.receipt, "record_path",
                return_value=self.root / "network.json"))
            stack.enter_context(mock.patch.object(
                m.receipt, "read", return_value=self.doc))
            stack.enter_context(mock.patch.object(
                m.receipt, "advance",
                side_effect=lambda journal, before, after:
                    sequence.append(after) or {"status":after}))
            result = m.rollback(HOST,self.journal)
        self.assertEqual(result["result"],
                         "COMMAND2_OWNED_NETWORK_AND_NFT_REVERSED")
        self.assertEqual(sequence, [
            "rollback_started", "destroy", "network_inactive",
            "undefine", "network_undefined", "delete_nft",
            "nft_table_removed", "rollback_verified"])

    def test_failure_after_first_action_never_deletes_firewall(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                m.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(
                m.sys.stdin, "isatty", return_value=True))
            stack.enter_context(mock.patch.object(
                m.deployment, "no_live_work"))
            stack.enter_context(mock.patch.object(
                m, "inspect", return_value={"result":"PLAN"}))
            stack.enter_context(mock.patch("builtins.input",
                return_value="UNDEFINE-ONLY-OWNED-CAPE-ISOLATED-NETWORK"))
            stack.enter_context(mock.patch.object(
                m, "LOCK", self.root / "network-undo.lock"))
            real_fstat = m.os.fstat
            stack.enter_context(mock.patch.object(
                m.os, "fstat", side_effect=lambda fd:
                    SimpleNamespace(st_mode=real_fstat(fd).st_mode,
                    st_nlink=1,st_uid=0)))
            steps=[]
            stack.enter_context(mock.patch.object(
                m.receipt, "advance",
                side_effect=lambda journal, before, after:
                    steps.append(after) or {"status":after}))
            stack.enter_context(mock.patch.object(
                m, "virsh", side_effect=OSError("simulated network failure")))
            remove=stack.enter_context(mock.patch.object(
                m, "nft",
                side_effect=AssertionError("nft must never be touched")))
            with self.assertRaisesRegex(
                    m.NetworkRollbackBlocked, "partial/unknown"):
                m.rollback(HOST,self.journal)
        self.assertEqual(steps, ["rollback_started"])
        remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
