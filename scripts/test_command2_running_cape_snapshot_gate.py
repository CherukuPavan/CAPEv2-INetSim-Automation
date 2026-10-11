"""Synthetic running CAPE snapshot controls — NO real virsh/snapshot actions."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_running_cape_snapshot_gate as s

NAME="win11_1"
UUID="8b20a326-4eef-4e31-938f-f7a63b015d4a"
MAC="02:01:02:03:04:05"
IP="192.168.240.101"
HOST="separate-lab-host"


def domain(nic=True, tpm=True, disk=True):
    interface=(f'<interface type="network"><source network="cape-analysis-isolated"/>'
               f'<mac address="{MAC}"/></interface>') if nic else ""
    backend='<tpm><backend type="emulator" version="2.0"/></tpm>' if tpm else ""
    storage=('<disk device="disk" type="file">'
             '<driver type="qcow2"/><source file="/analysis/win11_1.command2.qcow2"/>'
             '</disk>') if disk else ""
    return (f'<domain type="kvm"><name>{NAME}</name><uuid>{UUID}</uuid>'
            '<os><nvram>/nvram/win11_1.command2_VARS.fd</nvram></os>'
            f'<devices>{interface}{backend}{storage}</devices></domain>')


def virsh_fake(*argv, **kwargs):
    if argv==("domstate",NAME):return "running"
    if argv==("domuuid",NAME):return UUID
    if argv==("dumpxml",NAME):return domain()
    if argv==("net-info","cape-analysis-isolated"):return "Active: yes"
    if argv==("snapshot-list",NAME,"--name"):return ""
    if argv[:1]==("snapshot-create-as",):return "created"
    if argv==("snapshot-dumpxml",NAME,"cape_ready_win11_1"):
        return ('<domainsnapshot><name>cape_ready_win11_1</name>'
                '<memory snapshot="internal"/>'
                '<disks><disk name="vda" snapshot="internal"/></disks></domainsnapshot>')
    raise AssertionError("Unexpected libvirt command "+str(argv))


class RunningSnapshotTests(unittest.TestCase):
    def test_plan_correct_running_candidate_does_not_create_snapshot(self):
        calls=[]
        def read(*a, **kw):
            calls.append(a)
            return virsh_fake(*a,**kw)
        with patch.object(s.socket,"gethostname",return_value=HOST),\
             patch.object(s,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
             patch.object(s,"virsh",side_effect=read):
            report=s.plan(NAME,HOST,UUID,MAC,IP)
        self.assertEqual(report["snapshot_name"],"cape_ready_win11_1")
        self.assertFalse(report["snapshot_created"])
        self.assertFalse(report["restore_tested"])
        self.assertFalse(any("snapshot-create-as" in a for a in calls))

    def test_reference_host_is_guarded_before_libvirt(self):
        with patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s,"virsh",side_effect=AssertionError("libvirt reached")):
            with self.assertRaisesRegex(s.SnapshotBlocked,"REFERENCE_HOST_PROTECTED"):
                s.plan(NAME,"cse-ssl-55",UUID,MAC,IP)

    def test_renamed_reference_with_backup_still_blocked(self):
        with patch.object(s.socket,"gethostname",return_value=HOST),\
             patch.object(s,"SENTINEL",Path(__file__).parent),\
             patch.object(s,"virsh",side_effect=AssertionError("libvirt reached")):
            with self.assertRaisesRegex(s.SnapshotBlocked,"REFERENCE_HOST_PROTECTED"):
                s.plan(NAME,HOST,UUID,MAC,IP)

    def test_requires_one_exact_isolated_nic(self):
        for replacement in (domain(nic=False),
                            domain().replace("cape-analysis-isolated","default"),
                            domain().replace(MAC,"02:ff:ff:ff:ff:ff")):
            with self.subTest(replacement=replacement):
                with patch.object(s,"virsh",side_effect=lambda *a:
                      replacement if a==("dumpxml",NAME) else virsh_fake(*a)):
                    with self.assertRaisesRegex(s.SnapshotBlocked,"isolated"):
                        s.saved_xml_checks(NAME,UUID,MAC,IP,"192.168.240.0/24")

    def test_requires_tpm_and_independent_disk(self):
        for xml in (domain(tpm=False),domain(disk=False)):
            with patch.object(s,"virsh",side_effect=lambda *a:
                  xml if a==("dumpxml",NAME) else virsh_fake(*a)):
                with self.assertRaises(s.SnapshotBlocked):
                    s.saved_xml_checks(NAME,UUID,MAC,IP,"192.168.240.0/24")

    def test_guest_must_be_running(self):
        with patch.object(s,"virsh",return_value="shut off"):
            with self.assertRaisesRegex(s.SnapshotBlocked,"RUNNING"):
                s.saved_xml_checks(NAME,UUID,MAC,IP,"192.168.240.0/24")

    def test_nondefault_private_subnet_match_and_bad_subnet_fail(self):
        with patch.object(s,"virsh",side_effect=virsh_fake):
            self.assertTrue(s.saved_xml_checks(NAME,UUID,MAC,"172.28.240.101",
                                                "172.28.240.0/24"))
            for bad in ("192.168.241.0/24","8.8.8.0/24","169.254.1.0/24"):
                with self.subTest(bad=bad), self.assertRaises(s.SnapshotBlocked):
                    s.saved_xml_checks(NAME,UUID,MAC,IP,bad)

    def test_exact_snapshot_name_must_not_exist(self):
        with patch.object(s,"virsh",return_value="cape_ready_win11_1"):
            with self.assertRaisesRegex(s.SnapshotBlocked,"already exists"):
                s.check_snapshot_absence(NAME,"cape_ready_win11_1")

    def test_capture_must_be_direct_interactive_and_root(self):
        with patch.object(s.socket,"gethostname",return_value=HOST),\
             patch.object(s,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
             patch.object(s.os,"geteuid",return_value=1000):
            with self.assertRaisesRegex(s.SnapshotBlocked,"Root"):
                s.capture(NAME,HOST,UUID,MAC,IP,"/nonexistent")
        with patch.object(s.socket,"gethostname",return_value=HOST),\
             patch.object(s,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
             patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.sys.stdin,"isatty",return_value=False):
            with self.assertRaisesRegex(s.SnapshotBlocked,"interactive"):
                s.capture(NAME,HOST,UUID,MAC,IP,"/nonexistent")

    def test_snapshot_metadata_requires_disk_and_memory(self):
        for xml in (
            '<domainsnapshot><memory snapshot="no"/><disks><disk snapshot="internal"/></disks></domainsnapshot>',
            '<domainsnapshot><memory snapshot="internal"/></domainsnapshot>',
        ):
            with tempfile.TemporaryDirectory() as tmp:
                lock=Path(tmp)/"snapshot.lock"
                pre={"domain_live_xml_sha256":"a"*64,"receipt_sha256":"b"*64,
                     "snapshot_name":"cape_ready_win11_1"}
                def faux_virsh(*a,**kw):
                    if a[:1]==("snapshot-create-as",):return "created"
                    if a[:1]==("snapshot-dumpxml",):return xml
                    return "running"
                with patch.object(s.socket,"gethostname",return_value=HOST),\
                     patch.object(s,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
                     patch.object(s.os,"geteuid",return_value=0),\
                     patch.object(s.os,"fstat",return_value=type(
                         "RootLock",(),{"st_mode":0o100600,
                                        "st_uid":0,"st_nlink":1})()),\
                     patch.object(s.sys.stdin,"isatty",return_value=True),\
                     patch("builtins.input",return_value="CAPTURE-RUNNING-WIN11_1"),\
                     patch.object(s,"plan",return_value=pre),\
                     patch.object(s.agentprobe,"probe_agent",return_value={
                         "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED"}),\
                     patch.object(s,"LOCK",lock),\
                     patch.object(s,"virsh",side_effect=faux_virsh):
                    with self.assertRaisesRegex(s.SnapshotBlocked,"INTERNAL disk and INTERNAL memory"):
                        s.capture(NAME,HOST,UUID,MAC,IP,"/verified")

    def test_live_snapshot_requires_real_cape_agent_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock=Path(tmp)/"snapshot.lock"
            pre={"domain_live_xml_sha256":"a"*64,"receipt_sha256":"b"*64,
                 "snapshot_name":"cape_ready_win11_1"}
            with patch.object(s.socket,"gethostname",return_value=HOST),\
                 patch.object(s,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s.os,"fstat",return_value=type(
                     "RootLock",(),{"st_mode":0o100600,
                                    "st_uid":0,"st_nlink":1})()),\
                 patch.object(s.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value="CAPTURE-RUNNING-WIN11_1"),\
                 patch.object(s,"plan",return_value=pre),\
                 patch.object(s,"LOCK",lock),\
                 patch.object(s.agentprobe,"probe_agent",
                     side_effect=s.agentprobe.AgentBlocked("Agent missing")):
                with self.assertRaisesRegex(s.agentprobe.AgentBlocked,"Agent missing"):
                    s.capture(NAME,HOST,UUID,MAC,IP,"/verified")

    def test_no_automatic_revert_or_network_mutation_commands(self):
        source=Path(s.__file__).read_text(encoding="utf-8")
        for needle in ('"snapshot-revert"', '"net-start"', '"attach-interface"',
                       '"destroy"', '"shutdown"', '"start"', 'os.system('):
            self.assertNotIn(needle,source)


if __name__=="__main__":
    unittest.main()
