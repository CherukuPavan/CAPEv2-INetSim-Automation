"""Mocked OTHER-host 1..16 zero-NIC persistent master NAT apply/verify tests."""
import ipaddress
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET

import command2_portable_master_nat_attach as m

MASTER_UUID="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
MASTER=('<domain type="kvm"><name>win11</name><uuid>'+MASTER_UUID+
        '</uuid><devices><interface type="network">'
        '<source network="default"/><mac address="52:54:00:62:a0:00"/>'
        '<model type="e1000e"/></interface></devices></domain>')
def guest(row,mac=None):
    nic=('<interface type="network"><source network="default"/>'
         '<mac address="'+mac+'"/><model type="e1000e"/>'
         '</interface>' if mac else "")
    return ('<domain type="kvm"><name>'+row["libvirt_name"]+'</name>'
            '<uuid>'+row["libvirt_uuid_candidate"]+'</uuid>'
            '<os><nvram>'+row["uefi_nvram_target"]+'</nvram></os>'
            '<devices><disk type="file" device="disk"><driver type="qcow2"/>'
            '<source file="'+row["disk_target"]+'"/></disk>'
            '<tpm model="tpm-crb"><backend type="emulator" version="2.0"/>'
            '</tpm>'+nic+'</devices></domain>')
def identity_rows(n):
    return [{"libvirt_name":f"win11_{i}",
        "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}",
        "mac_candidate":f"02:ca:22:00:00:{i:02x}",
        "disk_target":f"/srv/clones/win11_{i}.command2.qcow2",
        "uefi_nvram_target":f"/srv/ovmf/win11_{i}.command2_VARS.fd",
        "guest_static_ipv4_target":f"192.168.240.{100+i}"} for i in range(1,n+1)]
class Network:
    def __init__(self,n):
        self.rows=identity_rows(n)
        self.attached={}
        self.reserved={}
        self.calls=[]
        self.running=False
        self.bad_saved=False
        self.bad_lease=False
    def network_xml(self):
        dhcp=ET.Element("dhcp")
        ET.SubElement(dhcp,"range",start="192.168.122.2",end="192.168.122.254")
        for mac,ip,name in self.reserved.values():
            ET.SubElement(dhcp,"host",mac=mac,ip=ip,name=name)
        root=ET.Element("network")
        ET.SubElement(root,"name").text="default"
        ET.SubElement(root,"forward",mode="nat")
        ET.SubElement(root,"bridge",name="virbr0")
        ipv4=ET.SubElement(root,"ip",address="192.168.122.1",
                           netmask="255.255.255.0")
        ipv4.append(dhcp)
        return ET.tostring(root,encoding="unicode")
    def call(self,*args,**kwargs):
        self.calls.append(args)
        if args==("domstate","win11"):return "shut off"
        if args[0]=="domstate" and args[1].startswith("win11_"):
            return "running" if self.running else "shut off"
        if args==("domuuid","win11"):return MASTER_UUID
        if args[0]=="domuuid":
            return next(x["libvirt_uuid_candidate"] for x in self.rows
                        if x["libvirt_name"]==args[1])
        if args[:2]==("dumpxml","--inactive"):
            if args[2]=="win11":return MASTER
            row=next(x for x in self.rows if x["libvirt_name"]==args[2])
            return guest(row,self.attached.get(args[2]))
        if args==("list","--name"):return "win11_1" if self.running else ""
        if args==("list","--all","--name"):
            return "\n".join(["win11"]+[x["libvirt_name"] for x in self.rows])
        if args==("net-dumpxml","default") or args==(
             "net-dumpxml","default","--inactive"):
            return self.network_xml()
        if args==("net-info","default"):
            return "Name:     default\nActive:          yes\nBridge:    virbr0"
        if args==("net-dhcp-leases","default"):
            return ("2026-10-12 19:00:00 52:54:00:aa:00:00 ipv4 "
                    "192.168.122.201/24" if self.bad_lease else "")
        if args[0]=="snapshot-list":return ""
        if args[:3]==("net-update","default","add"):
            item=ET.fromstring(args[4])
            self.reserved[item.get("name")]=(
                item.get("mac"),item.get("ip"),item.get("name"))
            return ""
        if args[0]=="attach-interface":
            self.attached[args[1]]=args[5]
            return ""
        raise AssertionError(args)

class Attachment(unittest.TestCase):
    def configure(self,n):
        sim=Network(n)
        patches=[
            patch.object(m.workflow,"canonical_host",return_value="lab02"),
            patch.object(m.os,"geteuid",return_value=0),
            patch.object(m.workflow.snapshotgate,"private_evidence_folder",
                         return_value=True),
            patch.object(m.workflow.snapshotgate,"reservation_rows",
                         return_value=sim.rows),
            patch.object(m.profile,"virsh",side_effect=sim.call),
        ]
        return sim,patches

    def test_all_n_plan_and_exact_permanent_apply(self):
        for n in (1,3,16):
            sim,ps=self.configure(n)
            with ps[0],ps[1],ps[2],ps[3],ps[4]:
                before=m.build("lab02",Path("/root/secret/command2-identity-reservation.json"),
                               False)
                self.assertEqual(before["count"],n)
                self.assertEqual(before["guest_reservations"][0]["ip"],
                                 "192.168.122.201")
                self.assertFalse(before["guest_saved_nics_attached"])
                self.assertFalse(before["CAPE_READY"])
                self.assertFalse(before["public_malware_egress_authorized"])
                for entry in before["dhcp_hosts"]:
                    mac,ip,name=entry["mac"],entry["ip"],entry["name"]
                    xml=f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
                    sim.call("net-update","default","add","ip-dhcp-host",xml,
                             "--live","--config")
                    vm="win11_"+name.split("-")[1]
                    sim.call("attach-interface",vm,"network","default",
                             "--mac",mac,"--model","e1000e","--config")
                after=m.build("lab02",Path("/root/secret/command2-identity-reservation.json"),
                              True)
            self.assertTrue(after["host_nat_dhcp_config_applied"])
            self.assertEqual(len(sim.reserved),n)
            self.assertEqual(len(sim.attached),n)
            self.assertFalse(after["guest_booted_or_configured"])

    def test_guest_vm_uuid_and_exact_disk_firmware_must_match(self):
        row=identity_rows(1)[0]
        with patch.object(m,"virsh",side_effect=lambda *args,**kw:
                           guest(row).replace(row["disk_target"],"/different")
                           if args[0]=="dumpxml" else (
                           "shut off" if args[0]=="domstate" else
                           row["libvirt_uuid_candidate"] if args[0]=="domuuid"
                           else "")),\
             self.assertRaisesRegex(m.NatAttachBlocked,"OS disk"):
            m.check_exact_guest(row)

    def test_live_lease_collision_blocks_before_mutation(self):
        sim,ps=self.configure(2)
        sim.bad_lease=True
        with ps[0],ps[1],ps[2],ps[3],ps[4],\
             self.assertRaisesRegex((m.NatAttachBlocked,
                m.profile.PortableNatBlocked),"collides"):
            m.build("lab02",Path("/root/j/command2-identity-reservation.json"),False)
        self.assertNotIn("attach-interface",[c[0] for c in sim.calls])
        self.assertNotIn("net-update",[c[0] for c in sim.calls])

    def test_running_domain_denied(self):
        sim,ps=self.configure(2);sim.running=True
        with ps[0],ps[1],ps[2],ps[3],ps[4],\
             self.assertRaisesRegex(m.NatAttachBlocked,"ALL host guest"):
            m.build("lab02",Path("/root/j/command2-identity-reservation.json"),False)

    def test_apply_exact_typed_operator_and_postflight(self):
        sim,ps=self.configure(2)
        with tempfile.TemporaryDirectory() as td:
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with ps[0],ps[1],ps[2],ps[3],ps[4],\
                 patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                   "STAGE-2-PERSISTENT-MASTER-NAT-GUESTS-BENIGN-ONLY")):
                r=m.apply("lab02",Path("/root/j/command2-identity-reservation.json"))
            self.assertEqual(r["result"],
               "COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED")
            writes=[x for x in sim.calls if x[0] in (
                 "net-update","attach-interface")]
            self.assertEqual(len(writes),4)
            self.assertTrue(all(x[-1]=="--config" for x in writes))

    def test_partial_guest_attach_failure_never_rolls_back_or_retries(self):
        sim,ps=self.configure(1)
        def fail(*args,**kw):
            if args[0]=="attach-interface":
                raise m.profile.PortableNatBlocked("libvirt rejected NIC")
            return sim.call(*args,**kw)
        with tempfile.TemporaryDirectory() as td:
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with ps[0],ps[1],ps[2],ps[3],ps[4],\
                 patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                    "STAGE-1-PERSISTENT-MASTER-NAT-GUESTS-BENIGN-ONLY")),\
                 patch.object(m,"virsh",side_effect=fail),\
                 self.assertRaisesRegex(m.NatAttachBlocked,"POSSIBLE_PARTIAL"):
                m.apply("lab02",Path("/root/j/command2-identity-reservation.json"))
            self.assertTrue(sim.reserved)
            self.assertFalse(sim.attached)
            self.assertFalse(any(x[0] in ("snapshot-revert","snapshot-delete",
                           "net-destroy","detach-interface","shutdown","start")
                           for x in sim.calls))

    def test_no_unapproved_delete_restart_or_snapshot_operations(self):
        src=Path(m.__file__).read_text(encoding="utf-8")
        for action in ('"net-destroy"','"net-update","delete"',
              '"detach-interface"','"shutdown"','"destroy"','"start"',
              '"snapshot-revert"','"snapshot-delete"','os.replace(',
              "shell=True","os.unlink("):
            self.assertNotIn(action,src)
if __name__=="__main__":unittest.main()
