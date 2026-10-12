"""Synthetic guarded SSL55 persistent one-way NAT staging, no real VM calls."""
from pathlib import Path
import json
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
import command2_ssl55_persistent_nat_stage as g

def vmxml(name,uid,*,added=False,network=None,mac=None):
    net=network or g.ISOLATED
    addr=mac or g.ANALYSIS_MAC
    first=(f'<interface type="network"><source network="{net}"/>'
            f'<mac address="{addr}"/><model type="e1000e"/></interface>')
    extra=(f'<interface type="network"><source network="default"/>'
           f'<mac address="{g.ONLINE_MAC}"/><model type="e1000e"/></interface>'
           if added else "")
    return f'<domain type="kvm"><name>{name}</name><uuid>{uid}</uuid><devices>{first}{extra}</devices></domain>'

VM=vmxml(g.VM,g.UID)
BOTH=vmxml(g.VM,g.UID,added=True)
MASTER=vmxml(g.MASTER[0],g.MASTER[1],network="default",mac="52:54:00:62:a0:00")
NAT=('<network><name>default</name><forward mode="nat"/>'
     '<bridge name="virbr0"/><ip address="192.168.122.1">'
     '<dhcp><range start="192.168.122.2" end="192.168.122.254"/>'
     '</dhcp></ip></network>')
ISO=('<network><name>cape-analysis-isolated</name>'
     '<bridge name="cape-lab0"/><port isolated="yes"/>'
     '<dns enable="no"/></network>')
SNAP=('<domainsnapshot><name>'+g.SNAP+'</name><state>running</state>'
      '<memory snapshot="internal"/>'
      '<disks><disk name="sda" snapshot="internal"/>'
      '<disk name="sdb" snapshot="no"/></disks></domainsnapshot>')
def virsh(online=False):
    def run(*args,**kw):
        if args[0]=="domuuid":return {g.VM:g.UID,g.MASTER[0]:g.MASTER[1],
                                     g.TRIAL[0]:g.TRIAL[1]}[args[1]]
        if args[0]=="domstate":return "running" if args[1]==g.VM else "shut off"
        if args==("list","--name"):return g.VM
        if args==("list","--all","--name"):return f"{g.VM}\n{g.MASTER[0]}\n{g.TRIAL[0]}"
        if args==("snapshot-list",g.VM,"--name"):return g.SNAP
        if args==("snapshot-dumpxml",g.VM,g.SNAP):return SNAP
        if args==("dumpxml","--inactive",g.MASTER[0]):return MASTER
        if args==("dumpxml","--inactive",g.VM):return BOTH if online else VM
        if args==("dumpxml",g.VM):return BOTH if online else VM
        if args==("dumpxml","--inactive",g.TRIAL[0]):
            return vmxml(g.TRIAL[0],g.TRIAL[1],network="default",
                        mac="52:54:00:62:a0:04")
        if args==("net-dumpxml",g.DEFAULT):return NAT
        if args==("net-dumpxml",g.ISOLATED):return ISO
        if args==("net-info",g.DEFAULT):return "Name: default\nActive: yes\nBridge: virbr0"
        raise AssertionError(args)
    return run

class Stage(unittest.TestCase):
    def test_plan_root_identity_protects_snapshot_master_network(self):
        with patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(g,"virsh",side_effect=virsh(False)):
            result=g.inspect(False)
        self.assertEqual(result["result"],"SSL55_PERMANENT_MASTER_NAT_STAGE_PLAN_ONLY")
        self.assertEqual(result["snapshot_preserved"],g.SNAP)
        self.assertFalse(result["persistent_nat_adapter_now_attached"])
        self.assertFalse(result["malware_analysis_allowed"])

    def test_stage_live_and_persistent_only_to_exact_clone(self):
        with tempfile.TemporaryDirectory() as td:
            records=[]
            stage=[False]
            def query(*args,**kw):
                records.append(args)
                if args[0]=="attach-interface":
                    stage[0]=True
                    return ""
                return virsh(stage[0])(*args,**kw)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(g.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="STAGE-PERSISTENT-NAT-WIN11_1-TRUSTED-SETUP-ONLY"),\
                 patch.object(g.os,"fstat",return_value=fs),\
                 patch.object(g,"LOCK",Path(td)/"lock"),\
                 patch.object(g,"virsh",side_effect=query):
                result=g.stage()
            self.assertEqual(result["result"],"SSL55_PERMANENT_MASTER_NAT_NIC_STAGED_VERIFIED")
            self.assertEqual([x for x in records if x[0]=="attach-interface"],
             [("attach-interface",g.VM,"network",g.DEFAULT,
               "--mac",g.ONLINE_MAC,"--model","e1000e","--live","--config")])
            self.assertTrue(result["persistent_nat_adapter_now_attached"])
            self.assertFalse(result["final_single_nic_reached"])
            self.assertFalse(result["windows_dhcp_https_tested"])

    def test_unexpected_nat_device_or_master_change_refuses(self):
        with patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(g,"virsh",side_effect=virsh(False)):
            with self.assertRaisesRegex(g.StagingBlocked,"Unexpected saved"):
                g.inspect(True)
        def mutate(*args,**kw):
            if args==("dumpxml","--inactive",g.MASTER[0]):
                return MASTER.replace('network="default"','network="other"')
            return virsh(False)(*args,**kw)
        with patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(g,"virsh",side_effect=mutate):
            with self.assertRaisesRegex(g.StagingBlocked,"master network"):
                g.inspect(False)

    def test_failed_after_attach_must_not_auto_revert_or_detach(self):
        with tempfile.TemporaryDirectory() as td:
            queried=[]
            def fail(*args,**kw):
                queried.append(args)
                if args[0]=="attach-interface":
                    raise g.StagingBlocked("libvirt refused live+config")
                return virsh(False)(*args,**kw)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(g.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="STAGE-PERSISTENT-NAT-WIN11_1-TRUSTED-SETUP-ONLY"),\
                 patch.object(g.os,"fstat",return_value=fs),\
                 patch.object(g,"LOCK",Path(td)/"lock"),\
                 patch.object(g,"virsh",side_effect=fail):
                with self.assertRaisesRegex(g.StagingBlocked,
                        "PERSISTENT_NIC_ATTACH_ATTEMPTED"):
                    g.stage()
            self.assertFalse(any(x[0] in ("detach-interface","destroy",
                                           "snapshot-revert") for x in queried))

    def test_no_master_or_snapshot_mutators(self):
        source=Path(g.__file__).read_text(encoding="utf-8")
        for forbidden in ('virsh("snapshot-create"','virsh("snapshot-revert"',
           'virsh("snapshot-delete"','virsh("shutdown"','virsh("start"',
           'virsh("destroy"','virsh("detach-interface"',
           'virsh("net-update"','virsh("net-define"',
           'os.system(', 'shell=True'):
            self.assertNotIn(forbidden,source)
if __name__=="__main__":unittest.main()
