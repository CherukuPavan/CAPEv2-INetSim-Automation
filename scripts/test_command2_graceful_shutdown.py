"""Offline tests for strict state-verified CAPE Windows guest shutdown.

All virsh commands and clock are mocked: NEVER boots, shuts down or changes a VM.
"""
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import patch
import command2_graceful_shutdown as s

VM="win11_1"
UUID=s.SSL55_UUID
HOST="cse-ssl-55"
EXPECT={"uuid":UUID,"disk":s.SSL55_DISK if hasattr(s,"SSL55_DISK") else
        "/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2",
        "nvram":"/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd",
        "mac":"02:0a:30:6a:3f:50"}

def xml(qga=False,acpi=True,hostdev=False):
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+
            '</uuid><features>'+("<acpi/>" if acpi else "")+'</features>'
            '<os><nvram format="raw">'+EXPECT["nvram"]+'</nvram></os>'
            '<devices><disk type="file" device="disk"><driver type="qcow2"/>'
            '<source file="'+EXPECT["disk"]+'"/></disk>'
            '<interface type="network"><source network="cape-analysis-isolated"/>'
            '<mac address="'+EXPECT["mac"]+'"/></interface>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'+
            ('<channel type="unix"><target type="virtio" '
             'name="org.qemu.guest_agent.0"/></channel>' if qga else '')+
            ('<hostdev/>' if hostdev else '')+'</devices></domain>')

class Shutdown(unittest.TestCase):
    def test_domain_rejects_other_nic_and_hostdev_and_missing_methods(self):
        good=s.capabilities(xml(),VM,EXPECT)
        self.assertTrue(good["acpi"])
        self.assertFalse(good["qga_channel"])
        self.assertTrue(s.capabilities(xml(qga=True),VM,EXPECT)["qga_channel"])
        for bad in (
            xml(acpi=False),
            xml(hostdev=True),
            xml().replace("cape-analysis-isolated","default"),
            xml().replace("02:0a:30:6a:3f:50","02:aa:bb:cc:dd:ee"),
        ):
            with self.assertRaises(s.ShutdownBlocked):
                s.capabilities(bad,VM,EXPECT)

    def test_ssl55_restricted_to_one_clone_and_master_trial_protected(self):
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s,"virsh",side_effect=lambda *a:(
                   s.PROTECTED[a[1]] if a[0]=="domuuid"
                   else "shut off")):
            with self.assertRaisesRegex(s.ShutdownBlocked,"ONLY win11_1"):
                s.guard(HOST,"ssl55-clone","win11",None)
            approved=s.guard(HOST,"ssl55-clone",VM,None)
            self.assertEqual(approved["uuid"],UUID)

    def test_running_inspection_is_read_only_and_requires_same_saved_live(self):
        def virsh(*a,**kwargs):
            if a[0]=="domuuid":return UUID
            if a[0]=="domstate":return "running"
            if a[0]=="dumpxml":return xml()
            raise AssertionError(a)
        with patch.object(s,"guard",return_value=EXPECT),\
             patch.object(s,"virsh",side_effect=virsh):
            out=s.inspect(HOST,"ssl55-clone",VM)
        self.assertEqual(out["state"],"running")
        self.assertFalse(out["shutdown_requested"])
        self.assertFalse(out["shutdown_completed"])

    def exercise_shutdown(self,*,agent=False,stops_after=None):
        with TemporaryDirectory() as td:
            ops=[]
            tick=[0.]
            vmstate=["running"]
            count=[0]
            def clock():return tick[0]
            def sleeper(delay):
                tick[0]+=delay
                count[0]+=1
                if stops_after is not None and count[0]>=stops_after:
                    vmstate[0]="shut off"
            def virsh(*a,**kwargs):
                ops.append(a)
                if a[0]=="shutdown":return "Domain is being shutdown"
                if a[0]=="domuuid":return UUID
                raise AssertionError(a)
            pre={"result":"COMMAND2_GRACEFUL_SHUTDOWN_PLAN_ONLY",
                 "host":HOST,"scope":"ssl55-clone","vm":VM,"uuid":UUID,
                 "state":"running","already_off":False,
                 "capabilities":{"qga_channel":agent,"acpi":True}}
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(s,"LOCK",Path(td)/"lock"),\
                 patch.object(s,"inspect",return_value=pre),\
                 patch.object(s,"guard",return_value=EXPECT),\
                 patch.object(s,"virsh",side_effect=virsh),\
                 patch.object(s,"state",side_effect=lambda vm:vmstate[0]),\
                 patch.object(s.os,"fstat",return_value=fs),\
                 patch.object(s.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="SHUTDOWN-COMMAND2-WIN11_1"):
                try:
                    outcome=s.request_shutdown(HOST,"ssl55-clone",VM,
                         timeout_seconds=90,clock=clock,sleep=sleeper)
                except s.ShutdownBlocked as e:
                    outcome=e
            return outcome,ops,tick[0]

    def test_acpi_request_is_not_success_until_real_shutoff(self):
        out,ops,_=self.exercise_shutdown(stops_after=2)
        self.assertEqual(out["result"],
                         "COMMAND2_GRACEFUL_SHUTDOWN_SHUT_OFF_CONFIRMED")
        self.assertEqual([x for x in ops if x[0]=="shutdown"],
                         [("shutdown",VM,"--mode","acpi")])
        self.assertFalse(out["forced_poweroff"])

    def test_qga_request_then_one_acpi_fallback_if_stalled(self):
        out,ops,_=self.exercise_shutdown(agent=True,stops_after=8)
        self.assertEqual(out["state"],"shut off")
        self.assertEqual([x[3] for x in ops if x[0]=="shutdown"],
                         ["agent","acpi"])

    def test_ignored_requests_timeout_without_force(self):
        out,ops,elapsed=self.exercise_shutdown(stops_after=None)
        self.assertIsInstance(out,s.ShutdownBlocked)
        self.assertIn("TIMEOUT",str(out))
        self.assertGreaterEqual(elapsed,90)
        self.assertNotIn("destroy",[x[0] for x in ops])
        self.assertNotIn("reset",[x[0] for x in ops])

    def test_already_shut_off_is_idempotent_and_never_reissues(self):
        pre={"already_off":True,"state":"shut off","vm":VM}
        with patch.object(s,"inspect",return_value=pre),\
             patch.object(s,"virsh") as v:
            report=s.request_shutdown(HOST,"ssl55-clone",VM)
            v.assert_not_called()
        self.assertTrue(report["no_shutdown_request_needed"])

    def test_master_nat_scope_requires_snapshot_identity_and_reserved_dhcp(self):
        # All local mocks: real host, Windows and libvirt remain untouched.
        import command2_portable_master_nat_attach as nat
        import command2_portable_workflow as workflow
        from xml.etree import ElementTree as ET
        row={"libvirt_name":VM,"libvirt_uuid_candidate":UUID,
             "disk_target":EXPECT["disk"],"uefi_nvram_target":EXPECT["nvram"],
             "mac_candidate":EXPECT["mac"]}
        net={"nat_network":"default","bridge":"virbr0",
             "ipv4":{"subnet":"192.168.122.0/24"}}
        reservation=(EXPECT["mac"],"192.168.122.201","WIN11-1")
        view=ET.fromstring("<network><ip><dhcp><host mac='"+EXPECT["mac"]+
              "' ip='192.168.122.201' name='WIN11-1'/>"
              "</dhcp></ip></network>")
        snapshot=("<domainsnapshot><name>cape_one_nat_win11_1</name>"
                  "<state>running</state><memory snapshot='internal'/>"
                  "</domainsnapshot>")
        with patch.object(s.os,"geteuid",return_value=0),\\
             patch.object(s.socket,"gethostname",return_value="lab02"),\\
             patch.object(workflow,"canonical_host",return_value="lab02"),\\
             patch.object(nat,"journal_rows",return_value=[row]),\\
             patch.object(nat,"check_network_references",
                          return_value=(net,[view,view])),\\
             patch.object(s,"state",return_value="shut off"),\\
             patch.object(s,"virsh",side_effect=lambda *a:
                 "cape_one_nat_win11_1" if a[0]=="snapshot-list"
                 else snapshot if a[0]=="snapshot-dumpxml"
                 else (_ for _ in ()).throw(AssertionError(a))):
            got=s.guard("lab02","portable-master-nat",VM,
                        Path("/root/private/command2-identity-reservation.json"))
            self.assertEqual(got["network"],"default")
            self.assertEqual(got["reserved_nat_ipv4"],"192.168.122.201")
            self.assertEqual(got["nic_model"],"e1000e")
            self.assertEqual(nat.reservations(view),[reservation])
            with patch.object(s,"virsh",return_value=""):
                with self.assertRaisesRegex(s.ShutdownBlocked,"running snapshot"):
                    s.guard("lab02","portable-master-nat",VM,
                            Path("/root/private/command2-identity-reservation.json"))
            with patch.object(nat,"reservations",return_value=[]):
                with self.assertRaisesRegex(s.ShutdownBlocked,"DHCP reservation"):
                    s.guard("lab02","portable-master-nat",VM,
                            Path("/root/private/command2-identity-reservation.json"))

    def test_master_nat_device_model_is_exactly_e1000e(self):
        expected={**EXPECT,"network":"default","nic_model":"e1000e"}
        good=(xml().replace("cape-analysis-isolated","default")
                    .replace('<mac address=', '<model type="e1000e"/><mac address='))
        self.assertTrue(s.capabilities(good,VM,expected)["acpi"])
        for altered in (
            good.replace('type="e1000e"','type="virtio"'),
            good.replace('<model type="e1000e"/>',''),
            good.replace('source network="default"',
                         'source network="cape-analysis-isolated"'),
            good.replace('address="'+EXPECT["mac"]+'"',
                         'address="02:de:ad:00:00:01"'),
        ):
            with self.assertRaisesRegex(s.ShutdownBlocked,"NIC/MAC/model"):
                s.capabilities(altered,VM,expected)
        with self.assertRaises(s.ShutdownBlocked):
            s.capabilities(good,VM,EXPECT)

    def test_no_hard_poweroff_or_firmware_write_actions(self):
        source=Path(s.__file__).read_text(encoding="utf-8")
        for forbidden in ('virsh("destroy"', 'virsh("reset"',
                 'virsh("snapshot-revert"','virsh("snapshot-create"',
                 'virsh("undefine"','virsh("define"', 'shell=True'):
            self.assertNotIn(forbidden,source)

if __name__=="__main__":unittest.main()
