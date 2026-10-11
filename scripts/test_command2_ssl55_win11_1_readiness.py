"""Offline SSL55 win11_1 read-only readiness mock tests; no VM access."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import command2_ssl55_win11_1_readiness as q

VM_XML=('<domain type="kvm"><name>win11_1</name>'
        '<uuid>732b2256-ee99-41fa-881d-fbf5c476d960</uuid>'
        '<os><nvram>/var/lib/libvirt/qemu/nvram/win11_1_VARS.fd</nvram></os>'
        '<devices><disk device="disk" type="file">'
        '<driver type="qcow2"/><source file="/images/win11_1.qcow2"/>'
        '</disk><tpm><backend type="emulator" version="2.0"/></tpm>'
        '</devices></domain>')
NETWORK_XML=('<network><name>cape-analysis-isolated</name>'
             '<bridge name="cape-lab0"/><ip address="192.168.240.1"'
             ' netmask="255.255.255.0"/></network>')


def fakelib(*args):
    if args==("domuuid",q.VM):return 0,q.UUID
    if args==("domstate",q.VM):return 0,"running"
    if args==("dumpxml","--inactive",q.VM):return 0,VM_XML
    if args==("dumpxml",q.VM):return 0,VM_XML
    if args==("net-info",q.NET):
        return 0,"Name: cape-analysis-isolated\nActive: no\nAutostart: no\nBridge: cape-lab0\nPersistent: yes"
    if args==("net-dumpxml",q.NET):return 0,NETWORK_XML
    if args==("snapshot-list",q.VM,"--name"):return 0,""
    raise AssertionError("Unexpected guest/net inspection "+str(args))


def fakecmd(*args):
    if args==("ip","-j","-4","route","show","table","all"):
        return 0,'[{"dst":"10.23.96.0/20","dev":"enp0s31f6"}]'
    if args==("ip","-j","-4","addr","show"):
        return 0,'[{"ifname":"enp0s31f6","addr_info":[{"family":"inet","local":"10.23.105.55","prefixlen":20}]}]'
    if args[:1]==("nft",):
        return 1,""
    if args[:1]==("df",):
        return 0,"Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/sda 160000000 64000000 96000000 40% /\n"
    raise AssertionError("Unexpected host command "+str(args))


class ReadinessTests(unittest.TestCase):
    def test_no_nic_clone_current_readiness_blockers_are_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            safe=Path(td)/"protected"
            safe.mkdir()
            with patch.object(q.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(q,"SENTINEL",safe),\
                 patch.object(q,"virsh",side_effect=fakelib),\
                 patch.object(q,"command",side_effect=fakecmd):
                data=q.check()
        self.assertEqual(data["result"],"SSL55_WIN11_1_COMMAND2_READINESS_READ_ONLY")
        self.assertEqual(data["domain_views"]["live"]["nics"],[])
        self.assertEqual(data["domain_views"]["inactive"]["nics"],[])
        self.assertFalse(data["snapshots"]["running_cape_snapshot_found"])
        self.assertEqual(data["analysis_network"]["active"],"no")
        self.assertEqual(data["planned_first_analysis_guest_static_ipv4"],
                         "192.168.240.101")
        self.assertTrue(data["analysis_ipv4_subnet_overlap"]
                        ["no_nonbridge_collision_proven"])
        for key in ("host_ipv4_egress_isolation_proved",
                    "host_ipv6_egress_isolation_proved",
                    "guest_windows_static_ipv4_verified",
                    "guest_cape_agent_http_port_8000_verified",
                    "guest_running_snapshot_restore_proved",
                    "master_modified","clone_modified",
                    "host_network_modified"):
            self.assertFalse(data[key])

    def test_nonbridge_route_and_address_overlaps_are_detected(self):
        def conflicted(*args):
            if args[:3]==("ip","-j","-4"):
                if "route" in args:
                    return 0,'[{"dst":"192.168.240.0/24","dev":"docker0"}]'
                return 0,'[{"ifname":"campus0","addr_info":[{"family":"inet","local":"192.168.240.55","prefixlen":24}]}]'
            raise AssertionError("Only IPv4 inventory allowed")
        with patch.object(q,"command",side_effect=conflicted):
            report=q.check_ipv4_subnet_overlap()
        self.assertFalse(report["no_nonbridge_collision_proven"])
        self.assertEqual(len(report["nonbridge_overlaps"]),2)
        self.assertEqual({x["device"] for x in report["nonbridge_overlaps"]},
                         {"docker0","campus0"})

    def test_missing_ipv4_host_inventory_never_implies_safe_subnet(self):
        with patch.object(q,"command",return_value=(1,"")):
            result=q.check_ipv4_subnet_overlap()
        self.assertFalse(result["inventory_available"])
        self.assertFalse(result["no_nonbridge_collision_proven"])

    def test_wrong_reference_host_rejected_before_libvirt(self):
        with patch.object(q.socket,"gethostname",return_value="other-server"),\
             patch.object(q,"virsh",side_effect=AssertionError("No libvirt")):
            with self.assertRaisesRegex(q.ReadinessBlocked,"restricted"):
                q.check()

    def test_wrong_clone_uuid_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            def fake(*args):
                if args==("domuuid",q.VM):return 0,"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
                raise AssertionError("Unexpected libvirt access")
            with patch.object(q.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(q,"SENTINEL",Path(td)),\
                 patch.object(q,"virsh",side_effect=fake):
                with self.assertRaisesRegex(q.ReadinessBlocked,"UUID changed"):
                    q.check()

    def test_bad_xml_identity_refused(self):
        with self.assertRaisesRegex(q.ReadinessBlocked,"identity differs"):
            q.xml_parts(VM_XML.replace("<name>win11_1</name>",
                                        "<name>win11</name>"),"inactive")

    def test_readonly_source_never_executes_change_commands(self):
        src=Path(q.__file__).read_text(encoding="utf-8")
        code=src[src.index("from __future__ import annotations"):]
        for unsafe in ('"net-start"', '"attach-interface"', '"attach-device"',
                       '"snapshot-create-as"', '"snapshot-revert"', '"shutdown"',
                       '"start"', '"destroy"', '"nft","-f"', '"nft","add"',
                       "shutil.copy", "os.system("):
            self.assertNotIn(unsafe,code)

if __name__=="__main__":
    unittest.main()
