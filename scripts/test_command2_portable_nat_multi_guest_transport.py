"""Multi-guest Windows NAT: reject unverified older clones, permit proven ones.

Offline mocks only; no libvirt, Windows, TPM or network operations.
"""
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

import command2_portable_nat_agent_setup_transport as g
import command2_portable_master_nat_firstboot as boot

VM="win11_2"
UUID="00000000-0000-4000-8000-000000000002"
MAC="02:ca:22:00:00:02"
IP="192.168.122.202"
MASTER="win11_1"
OLD_UUID="00000000-0000-4000-8000-000000000001"
OLD_MAC="02:ca:22:00:00:01"
JOURNAL=Path("/root/cape/command2-identity-reservation.json")
ROWS=[
    {"libvirt_name":MASTER,"libvirt_uuid_candidate":OLD_UUID,
     "mac_candidate":OLD_MAC},
    {"libvirt_name":VM,"libvirt_uuid_candidate":UUID,"mac_candidate":MAC},
]
DOMAIN=('<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+
        '</uuid><devices><interface type="network">'
        '<source network="default"/><mac address="'+MAC+'"/>'
        '<model type="e1000e"/></interface></devices></domain>')
ISO={"config":{"format":"COMMAND2_MASTER_NAT_WINDOWS_V1",
     "guest_name":VM,"nic_network":"default","bridge":"virbr0",
     "malware_public_internet_authorized":False,
     "expected_machine_uuid":UUID,"nic_mac":MAC,
     "ipv4":IP,"default_gateway":"192.168.122.1"},
     "config_sha256":"a"*64,"script_sha256":"b"*64}
NETWORK={"ipv4":{"subnet":"192.168.122.0/24",
                 "gateway":"192.168.122.1"}}

def virsh(*args,**kwargs):
    if args==("domuuid",VM):return UUID
    if args==("domstate",VM):return "running"
    if args==("domstate","win11"):return "shut off"
    if args==("list","--name"):return MASTER+"\n"+VM
    if args[0]=="dumpxml":return DOMAIN
    raise AssertionError(args)

class MultiVM(unittest.TestCase):
    def test_verified_previous_vm_allowed_for_guest_two(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_2.master-nat.iso";iso.write_bytes(b"test")
            witnesses=Path(td)/"evidence";witnesses.mkdir()
            called=[]
            def approve(*args,**kwargs):
                called.append((args,kwargs))
                return [{"vm":MASTER,"reserved_ip":"192.168.122.201",
                         "Windows_verified_and_guest_agent_live":True}]
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=ROWS),\
                 patch.object(g.attach,"virsh",side_effect=virsh),\
                 patch.object(g,"iso_profile",return_value=ISO),\
                 patch.object(g.attach.profile,"check_active_nat",
                              return_value=NETWORK),\
                 patch.object(boot,"completed_running_clones",
                              side_effect=approve),\
                 patch.object(g,"agent_get",side_effect=lambda ip,source:{
                              "ip":ip,"agent_version":"0.23"}),\
                 patch.object(g,"mac_of_neighbor",return_value=MAC):
                result=g.inspect("lab02",JOURNAL,VM,iso,witnesses)
            self.assertEqual(result["vm"],VM)
            self.assertEqual(result["bootstrap_ip"],IP)
            self.assertEqual(len(called),1)
            self.assertEqual(called[0][0][2],VM)
            self.assertEqual(called[0][0][4],witnesses)
            self.assertEqual(called[0][1],{"requested_is_running":True})

    def test_no_prior_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_2.master-nat.iso";iso.write_bytes(b"x")
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=ROWS),\
                 patch.object(g.attach,"virsh",side_effect=virsh),\
                 self.assertRaisesRegex(g.TransportBlocked,"Prior running"):
                g.inspect("lab02",JOURNAL,VM,iso)

    def test_prior_boot_gate_rejection_cannot_be_silenced(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_2.master-nat.iso";iso.write_bytes(b"x")
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=ROWS),\
                 patch.object(g.attach,"virsh",side_effect=virsh),\
                 patch.object(g.attach.profile,"check_active_nat",
                              return_value=NETWORK),\
                 patch.object(boot,"completed_running_clones",
                    side_effect=boot.NatBootBlocked("unknown predecessor")) ,\
                 self.assertRaisesRegex(g.TransportBlocked,"Previous cloned"):
                g.inspect("lab02",JOURNAL,VM,iso,Path(td))

    def test_wrong_previous_domain_list_always_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_2.master-nat.iso";iso.write_bytes(b"x")
            def fake(*args,**kwargs):
                if args==("list","--name"):
                    return "unapproved_guest\n"+VM
                return virsh(*args,**kwargs)
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=ROWS),\
                 patch.object(g.attach,"virsh",side_effect=fake),\
                 patch.object(g.attach.profile,"check_active_nat",
                              return_value=NETWORK),\
                 patch.object(boot,"completed_running_clones",
                              return_value=[{"vm":MASTER}]),\
                 self.assertRaisesRegex(g.TransportBlocked,"Unexpected unverified"):
                g.inspect("lab02",JOURNAL,VM,iso,Path(td))

    def test_firstboot_refuses_missing_target_in_running_inventory(self):
        with patch.object(boot.network,"virsh",
                          return_value="win11_1"),\
             self.assertRaisesRegex(boot.NatBootBlocked,"Selected running"):
            boot.completed_running_clones("lab02",ROWS,VM,NETWORK,
                evidence=None,requested_is_running=True)

if __name__=="__main__":unittest.main()
