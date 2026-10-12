"""Offline-only temporary live Internet setup: exact SSL55 clone and cleanup."""
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
import command2_ssl55_temporary_benign_internet as b

DOMAIN=('<domain type="kvm"><name>'+b.VM+'</name><uuid>'+b.UID+
        '</uuid><devices>'
        '<interface type="network"><source network="'+b.ANALYSIS+'"/>'
        '<mac address="'+b.SAVED_MAC+'"/><model type="e1000e"/></interface>'
        '</devices></domain>')
ONLINE_DOMAIN=DOMAIN.replace('</devices>',
     '<interface type="network"><source network="'+b.ONLINE+'"/>'
     '<mac address="'+b.SETUP_MAC+'"/><model type="e1000e"/></interface>'
     '</devices>')
SNAP_XML=('<domainsnapshot><name>'+b.SNAP+'</name><state>running</state>'
          '<memory snapshot="internal"/>'
          '<disks><disk name="sda" snapshot="internal"/>'
          '<disk name="sdb" snapshot="no"/></disks></domainsnapshot>')
ISO=('<network><name>'+b.ANALYSIS+'</name><bridge name="cape-lab0"/>'
     '<port isolated="yes"/><dns enable="no"/>'
     '<ip address="192.168.240.1"/></network>')
NAT=('<network><name>default</name><forward mode="nat"/>'
     '<bridge name="virbr0"/><ip address="192.168.122.1">'
     '<dhcp><range start="192.168.122.2" '
     'end="192.168.122.254"/></dhcp></ip></network>')

def fake_virsh(*args,**kwargs):
    if args[0]=="domuuid":
        return {b.VM:b.UID,b.MAIN[0]:b.MAIN[1],
                b.TRIAL[0]:b.TRIAL[1]}[args[1]]
    if args[0]=="domstate":
        return "running" if args[1]==b.VM else "shut off"
    if args==("list","--name"):return b.VM
    if args==("snapshot-list",b.VM,"--name"):return b.SNAP
    if args==("snapshot-dumpxml",b.VM,b.SNAP):return SNAP_XML
    if args==("dumpxml","--inactive",b.VM):return DOMAIN
    if args==("dumpxml",b.VM):return DOMAIN
    if args==("net-dumpxml",b.ANALYSIS):return ISO
    if args==("net-dumpxml",b.ONLINE):return NAT
    if args==("net-info",b.ONLINE):return "Active: yes\nBridge: virbr0"
    if args==("list","--all","--name"):return b.VM
    raise AssertionError(args)

class TrustedSetup(unittest.TestCase):
    def test_guard_scopes_snapshot_master_network_and_conflict_free_mac(self):
        with patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(b,"virsh",side_effect=fake_virsh),\
             patch.object(b,"command",return_value=json.dumps({
                 "nftables":[{"chain":{"name":v}} for v in (
                     "cape_forward","cape_input","cape_output")]})):
            result=b.before()
        self.assertFalse(result["host_or_guest_modified"])
        self.assertEqual(result["snapshot_preserved"],b.SNAP)
        self.assertEqual(result["approved_temporary_nat"]["bridge"],"virbr0")
        self.assertFalse(result["guest_windows_internet_confirmed"])

    def test_exact_nic_state_live_only_and_detach_verification(self):
        def in_state(online):
            def v(*args,**kwargs):
                if args==("dumpxml","--inactive",b.VM):return DOMAIN
                if args==("dumpxml",b.VM):
                    return ONLINE_DOMAIN if online else DOMAIN
                return fake_virsh(*args,**kwargs)
            with patch.object(b,"virsh",side_effect=v):
                return b.check_domain_views(online)
        self.assertEqual(len(in_state(True)["live_nics"]),2)
        self.assertEqual(len(in_state(False)["live_nics"]),1)
        with patch.object(b,"virsh",side_effect=fake_virsh):
            with self.assertRaisesRegex(b.SessionBlocked,"LIVE VM NICs"):
                b.check_domain_views(True)

    def test_refuses_invalid_nat_or_changed_offline_bridge(self):
        with patch.object(b,"virsh",side_effect=lambda *a,**kw:
                NAT.replace('mode="nat"','mode="bridge"')
                if a==("net-dumpxml",b.ONLINE) else fake_virsh(*a,**kw)):
            with self.assertRaisesRegex(b.SessionBlocked,"separate NAT"):
                b.check_nat_network()
        with patch.object(b,"virsh",side_effect=lambda *a,**kw:
                ISO.replace('<port isolated="yes"/>','')
                if a==("net-dumpxml",b.ANALYSIS) else fake_virsh(*a,**kw)):
            with self.assertRaisesRegex(b.SessionBlocked,"isolated"):
                b.check_isolated_network()

    def test_detach_requires_actual_live_xml_to_remove_adapter(self):
        states=[ONLINE_DOMAIN]
        calls=[]
        def v(*args,**kwargs):
            calls.append(args)
            if args==("dumpxml",b.VM):return states[0]
            if args[:1]==("detach-interface",):
                states[0]=DOMAIN
                return ""
            if args==("dumpxml","--inactive",b.VM):return DOMAIN
            return fake_virsh(*args,**kwargs)
        with patch.object(b,"virsh",side_effect=v):
            answer=b.detach_live()
        self.assertTrue(answer["actual_live_xml_verified_after_detach"])
        self.assertEqual([a for a in calls if a[:1]==("detach-interface",)],
             [("detach-interface",b.VM,"network","--mac",b.SETUP_MAC,"--live")])
        self.assertEqual(states[0],DOMAIN)

    def test_session_attaches_live_only_and_always_detaches(self):
        plan={"result":"SSL55_TRUSTED_WINDOWS_SETUP_INTERNET_PLAN_ONLY"}
        with tempfile.TemporaryDirectory() as td:
            record=[]
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                      st_uid=0,st_nlink=1)
            def v(*args,**kwargs):
                record.append(args)
                if args[:1]==("attach-interface",):return "attached"
                if args==("domstate",b.VM):return "running"
                raise AssertionError(args)
            with patch.object(b,"LOCK",Path(td)/"lock"),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                    return_value="TRUSTED-WINDOWS-SETUP-ONLY-NO-MALWARE"),\
                 patch.object(b,"before",return_value=plan),\
                 patch.object(b,"virsh",side_effect=v),\
                 patch.object(b,"check_domain_views",return_value={
                   "live_nics":[{"network":"default","mac":b.SETUP_MAC}]}),\
                 patch.object(b,"monitor",return_value="operator_finished"),\
                 patch.object(b,"detach_live",return_value={
                     "temporary_nic_disconnected":True}) as cleanup,\
                 patch.object(b,"check_isolated_network",return_value=True),\
                 patch.object(b.os,"fstat",return_value=fs):
                result=b.setup_session(90)
            self.assertEqual(result["result"],
                "SSL55_TRUSTED_WINDOWS_SETUP_FINISHED_OFFLINE")
            self.assertTrue(result["temporary_nat_nic_absent_from_live_and_saved_domain"])
            self.assertEqual(record[0],("attach-interface",b.VM,"network",
                "default","--mac",b.SETUP_MAC,"--model","e1000e","--live"))
            cleanup.assert_called_once()

    def test_interruption_is_fail_closed_with_detach_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                      st_uid=0,st_nlink=1)
            with patch.object(b,"LOCK",Path(td)/"lock"),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                    return_value="TRUSTED-WINDOWS-SETUP-ONLY-NO-MALWARE"),\
                 patch.object(b,"before",return_value={"ready":True}),\
                 patch.object(b,"virsh",side_effect=lambda *a,**kw:
                     "running" if a==("domstate",b.VM) else "attached"),\
                 patch.object(b,"check_domain_views",return_value={
                    "live_nics":[]}),\
                 patch.object(b,"monitor",side_effect=b.SessionInterrupted(
                    "SIGHUP received")),\
                 patch.object(b,"detach_live",return_value={
                    "temporary_nic_disconnected":True}) as cleanup,\
                 patch.object(b,"check_isolated_network",return_value=True),\
                 patch.object(b.os,"fstat",return_value=fs):
                with self.assertRaisesRegex(b.SessionBlocked,"interrupted"):
                    b.setup_session(90)
            cleanup.assert_called_once()

    def test_abandoned_live_nat_can_be_cleaned_up_idempotently(self):
        with tempfile.TemporaryDirectory() as td:
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                      st_uid=0,st_nlink=1)
            original={"network":b.ANALYSIS,"mac":b.SAVED_MAC,"model":"e1000e"}
            ops=[]
            with patch.object(b,"LOCK",Path(td)/"lock"),\
                 patch.object(b.os,"fstat",return_value=fs),\
                 patch.object(b,"guard_exact",return_value=True),\
                 patch.object(b,"virsh",side_effect=lambda *a:(
                     DOMAIN if a==("dumpxml","--inactive",b.VM) else
                     (_ for _ in ()).throw(AssertionError(a)))),\
                 patch.object(b,"detach_live",return_value={
                     "temporary_nic_disconnected":True}) as detach,\
                 patch.object(b,"check_domain_views",return_value={
                     "saved_has_only_isolated_nic":True}) as views:
                output=b.cleanup_abandoned()
            self.assertEqual(output["result"],
                  "SSL55_TRUSTED_SETUP_NAT_CLEANUP_VERIFIED")
            self.assertTrue(output["temporary_nic_disconnected"])
            self.assertFalse(output["safe_for_malware_analysis_proven"])
            detach.assert_called_once()
            views.assert_called_once_with(False)

    def test_abandoned_cleanup_refuses_changed_persistent_nic(self):
        with tempfile.TemporaryDirectory() as td:
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                      st_uid=0,st_nlink=1)
            wrong=DOMAIN.replace(b.SAVED_MAC,"02:ff:ff:ff:ff:ff")
            with patch.object(b,"LOCK",Path(td)/"lock"),\
                 patch.object(b.os,"fstat",return_value=fs),\
                 patch.object(b,"guard_exact",return_value=True),\
                 patch.object(b,"virsh",return_value=wrong),\
                 patch.object(b,"detach_live") as detach:
                with self.assertRaisesRegex(b.SessionBlocked,"drift"):
                    b.cleanup_abandoned()
                detach.assert_not_called()

    def test_read_only_plan_and_no_mutations_of_snapshots_protected_domains(self):
        source=Path(b.__file__).read_text()
        for token in ('virsh("snapshot-create"','virsh("snapshot-revert"',
                      'virsh("snapshot-delete"','virsh("start"',
                      'virsh("destroy"','virsh("net-define"',
                      'virsh("net-update"','virsh("attach-interface",b.MAIN',
                      '"--config"', '"--persistent"', 'shell=True'):
            self.assertNotIn(token,source)
        self.assertIn('"--live"',source)
        self.assertIn('check_domain_views(False)',source)

if __name__=="__main__":unittest.main()
