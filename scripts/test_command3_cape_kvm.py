"""Offline-only regression for Command3 exact master + N KVM machinery stanzas."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import command3_cape_kvm as m

LEGACY = b"""# old unrelated global CAPE setting
[kvm]
machines = cuckoo1
interface = virbr0
dsn = qemu:///system
other = DONT_TOUCH

[cuckoo1]
label = cuckoo1
platform = windows
ip = 192.168.122.105
# old default snapshot not reliable
snapshot = snapshot1

[extra]
retention = preserve_me
"""

LIVE = b"""[kvm]
machines = win11
dsn = qemu:///system
interface = virbr0

[win11]
label = win11
platform = windows
ip = 192.168.122.125
tags = win11
snapshot = Afterfull
resultserver_ip = 192.168.122.1
arch = x64
reserved = no

[extra]
operator_private_option = PRESERVE
"""

def guests(n):
    return [{"name":f"win11_{i}","ip":f"192.168.122.{200+i}",
             "snapshot":f"cape_one_nat_win11_{i}"}
            for i in range(1,n+1)]

class KvmMachineTests(unittest.TestCase):
    def test_legacy_placeholder_replaced_with_actual_master_plus_three(self):
        result, detail = m.render(
            LEGACY, "192.168.122.125", "Afterfull", guests(3),
            "192.168.122.1", "win11")
        self.assertIn(b"machines = win11,win11_1,win11_2,win11_3", result)
        self.assertIn(b"[win11]\n", result)
        self.assertNotIn(b"[cuckoo1]\n", result)
        self.assertIn(b"other = DONT_TOUCH", result)
        self.assertIn(b"[extra]\nretention = preserve_me\n", result)
        self.assertEqual(len(detail), 4)
        for i in range(1,4):
            key = ("[win11_" + str(i) + "]").encode()
            self.assertIn(key, result)
            self.assertIn(("snapshot = cape_one_nat_win11_" + str(i)).encode(), result)
            self.assertIn(("ip = 192.168.122." + str(200+i)).encode(), result)
        self.assertNotIn(b"cape_ready_win11_", result)
        self.assertNotIn(b"win10", result)
        self.assertEqual(m.render(result, "192.168.122.125","Afterfull",
                                  guests(3),"192.168.122.1")[0],result)

    def test_update_manually_configured_master_and_append_new_clones(self):
        out, detail = m.render(
            LIVE,"192.168.122.125","Afterfull", guests(2),"192.168.122.1")
        self.assertEqual(out.count(b"[win11]"),1)
        self.assertEqual(out.count(b"[win11_1]"),1)
        self.assertIn(b"machines = win11,win11_1,win11_2",out)
        self.assertIn(b"operator_private_option = PRESERVE",out)
        self.assertIn(b"tags = win11",out)
        self.assertIn(b"reserved = no",out)
        self.assertIn(b"resultserver_ip = 192.168.122.1",out)
        self.assertEqual(len(detail),3)
        self.assertEqual(m.render(out,"192.168.122.125","Afterfull",
                                  guests(2),"192.168.122.1")[0],out)

    def test_exactly_one_tag_selectable_no_csv(self):
        out,_=m.render(LIVE,"192.168.122.125","Afterfull",[],
                       "192.168.122.1","22H2")
        self.assertIn(b"tags = 22H2",out)
        with self.assertRaisesRegex(m.KvmBlocked,"exactly one tag"):
            m.render(LIVE,"192.168.122.125","Afterfull",[],
                     "192.168.122.1","win11,22H2")

    def test_16_independently_named_stanzas(self):
        result,identities=m.render(
            LIVE,"192.168.122.125","Afterfull",guests(16),
            "192.168.122.1")
        self.assertEqual(len(identities),17)
        for i in range(1,17):
            self.assertEqual(result.count(
                ("[win11_" + str(i) + "]").encode()),1)
        self.assertEqual(m.render(result,"192.168.122.125","Afterfull",
                                  guests(16),"192.168.122.1")[0],result)

    def test_idempotence_crlf_reference(self):
        original=LIVE.replace(b"\n",b"\r\n")
        out,_=m.render(original,"192.168.122.125","Afterfull",
                       guests(2),"192.168.122.1")
        self.assertIn(b"[win11_1]\r\n",out)
        self.assertEqual(out.replace(b"\r\n",b"").count(b"\n"),0)
        self.assertEqual(m.render(out,"192.168.122.125","Afterfull",
                                  guests(2),"192.168.122.1")[0],out)

    def test_reject_unknown_machine_entries_and_incompatible_existing_stanzas(self):
        for old in (
            LIVE.replace(b"machines = win11",b"machines = win11,other"),
            LIVE.replace(b"machines = win11",b"machines = win10"),
            LIVE.replace(b"machines = win11",b"machines = win11,win11_2"),
            LIVE + b"\n[win11_5]\nlabel = win11_5\n",
            LEGACY.replace(b"label = cuckoo1",b"label = unrelated"),
            LIVE + b"\n[win11]\nlabel=win11\n",
        ):
            with self.subTest(sample=old[-60:]),self.assertRaises(m.KvmBlocked):
                m.render(old,"192.168.122.125","Afterfull",guests(2),
                         "192.168.122.1")

    def test_never_delete_real_or_credential_bearing_legacy_registration(self):
        for invalid in (
            LEGACY.replace(b"snapshot = snapshot1\\n",
                           b"snapshot = snapshot1\\npassword = retain-this\\n"),
            LEGACY.replace(b"label = cuckoo1\\n",
                           b"label = cuckoo1\\nsecret_token = PRIVATE\\n"),
            LEGACY.replace(b"label = cuckoo1\\n",
                           b"label = cuckoo1\\nlabel = cuckoo1\\n"),
        ):
            with self.subTest(config=invalid[-80:]), \\
                 self.assertRaisesRegex(m.KvmBlocked,
                                        "custom/unsafe|Duplicate"):
                m.render(invalid, "192.168.122.125", "Afterfull",
                         guests(1), "192.168.122.1")

    def test_duplicate_managed_kvm_options_blocked(self):
        bad=LIVE.replace(b"machines = win11\n",b"machines = win11\nmachines = win11\n")
        with self.assertRaisesRegex(m.KvmBlocked,"Duplicate"):
            m.render(bad,"192.168.122.125","Afterfull",[],
                     "192.168.122.1")
        bad=LIVE.replace(b"snapshot = Afterfull\n",
                         b"snapshot = Afterfull\nsnapshot = Old\n")
        with self.assertRaisesRegex(m.KvmBlocked,"Duplicate"):
            m.render(bad,"192.168.122.125","Afterfull",[],
                     "192.168.122.1")

    def test_reject_unverified_candidate_snapshot_tags_invalid_ip(self):
        invalid=[
            [{"name":"win11_1","ip":"192.168.122.201",
              "snapshot":"cape_ready_win11_1"}],
            [{"name":"win11_2","ip":"192.168.122.201",
              "snapshot":"cape_one_nat_win11_2"}],
            [{"name":"win11_1","ip":"192.168.122.125",
              "snapshot":"cape_one_nat_win11_1"}],
            [{"name":"win11_1","ip":"192.168.122.1",
              "snapshot":"cape_one_nat_win11_1"}],
        ]
        for sample in invalid:
            with self.subTest(guests=sample),self.assertRaises(m.KvmBlocked):
                m.render(LIVE,"192.168.122.125","Afterfull",sample,
                         "192.168.122.1")

    def test_only_private_unique_lan_endpoints(self):
        for bad in ("0.0.0.0","8.8.8.8","192.168.122.1","not-an-ip"):
            with self.subTest(ip=bad),self.assertRaises(m.KvmBlocked):
                m.render(LIVE,bad,"Afterfull",[],"192.168.122.1")

    def test_post_snapshot_discovery_uses_actual_dhcp_and_snapshot_gates(self):
        # Regression: nat.build(...,True) is a PRE-snapshot NIC helper.
        # It rejects clones after any snapshot, so Command3 MUST NOT
        # reuse it to discover already checkpointed analysis guests.
        from unittest.mock import Mock
        import command2_portable_master_nat_attach as nat
        import command2_portable_master_nat_running_snapshots as snapshots
        saved = ET.fromstring(
            '<network><name>default</name><forward mode="nat"/>'
            '<bridge name="virbr0"/></network>')
        guest = (
            '<domain type="kvm"><name>win11_1</name>'
            '<uuid>11111111-1111-4111-8111-111111111111</uuid>'
            '<devices><interface type="network"><source network="default"/>'
            '<mac address="02:aa:bb:cc:dd:ee"/><model type="e1000e"/>'
            '</interface><tpm><backend type="emulator" version="2.0"/>'
            '</tpm></devices></domain>')
        row = {"libvirt_name":"win11_1",
               "libvirt_uuid_candidate":"11111111-1111-4111-8111-111111111111",
               "mac_candidate":"02:aa:bb:cc:dd:ee"}
        report = {"nat_network":"default","bridge":"virbr0",
                  "ipv4":{"subnet":"192.168.122.0/24",
                          "gateway":"192.168.122.1"},
                  "dynamic_dhcp_ranges":[]}
        dns = {("02:aa:bb:cc:dd:ee","192.168.122.201","WIN11-1")}
        def fake_virsh(*args):
            values={
                ("list","--name"):"",
                ("list","--all","--name"):"win11\\nwin11_1\\n",
                ("domuuid","win11_1"):row["libvirt_uuid_candidate"],
                ("domstate","win11_1"):"shut off",
                ("dumpxml","--inactive","win11_1"):guest}
            if args not in values: raise AssertionError(args)
            return values[args].replace("\\\\n","\\n")
        with patch.object(nat.workflow,"canonical_host"), \
             patch.object(m.os,"geteuid",return_value=0), \
             patch.object(nat,"journal_rows",return_value=[row]), \
             patch.object(nat,"virsh",side_effect=fake_virsh), \
             patch.object(nat,"occupied_domain_macs",
                          return_value={"02:aa:bb:cc:dd:ee"}), \
             patch.object(nat,"check_network_references",
                          return_value=(report,[saved,saved])), \
             patch.object(nat.profile.ref,"nat_details",
                          return_value={"ipv4":report["ipv4"],
                                        "dynamic_dhcp_ranges":[]}), \
             patch.object(nat,"reservations",return_value=list(dns)), \
             patch.object(nat,"build",
                          side_effect=AssertionError(
                              "PRE-SNAPSHOT HELPER MUST NOT RUN")), \
             patch.object(m,"find_master_snapshot",return_value=True), \
             patch.object(snapshots,"libvirt_snapshot",
                          return_value={"snapshot_already_exists":True}) as ram, \
             patch.object(snapshots,"images",
                          return_value={"Windows_OS":{},"QCOW2_UEFI":{}}) as disk:
            found,gateway=m.discover(
                "other-host",
                Path("/root/approved/command2-identity-reservation.json"),
                "Afterfull")
            self.assertEqual(found,[{
                "name":"win11_1","ip":"192.168.122.201",
                "snapshot":"cape_one_nat_win11_1"}])
            self.assertEqual(gateway,"192.168.122.1")
            ram.assert_called_once_with("win11_1",True)
            disk.assert_called_once_with(row,True)

    def test_read_only_plan_no_mutation_and_no_cape_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"conf"
            root.mkdir()
            src=root/"kvm.conf"
            src.write_bytes(LIVE)
            import command2_portable_master_nat_attach as nat
            with patch.object(nat.workflow, "canonical_host"), \
                 patch.object(m, "discover",return_value=(
                        guests(2),"192.168.122.1")), \
                 patch.object(m, "safe_conf",wraps=m.safe_conf), \
                 patch.object(m, "ipaddr",wraps=m.ipaddr), \
                 patch.object(m.os,"replace",
                              side_effect=AssertionError("read only")):
                output=m.plan(src,"lab",Path("/root/private/command2-identity-reservation.json"),
                              "192.168.122.125","Afterfull","win11")
            self.assertEqual(src.read_bytes(),LIVE)
            self.assertEqual(output["count"],3)
            self.assertEqual(output["clone_count"],2)
            self.assertFalse(output["CAPE_READY"])
            self.assertFalse(output["snapshot_revert_with_swtpm_proven"])
            self.assertFalse(output["cape_service_restarted"])

    def test_master_running_snapshot_is_verified_by_name_not_guessed(self):
        live_xml=('<domainsnapshot><name>Afterfull</name><state>running</state>'
                  '<memory snapshot="internal"/>'
                  '<disks><disk name="sda" snapshot="internal"/></disks>'
                  '<domain><name>win11</name></domain></domainsnapshot>')
        def fake_virsh(*args):
            if args==("domstate","win11"):return "shut off"
            if args==("snapshot-list","win11","--name"):return "Afterfull\nAnother"
            if args==("snapshot-dumpxml","win11","Afterfull"):return live_xml
            raise AssertionError(args)
        import command2_portable_master_nat_attach as nat
        with patch.object(nat,"virsh",side_effect=fake_virsh):
            self.assertTrue(m.find_master_snapshot("Afterfull"))
            with self.assertRaises(m.KvmBlocked):
                m.find_master_snapshot("snapshot1")

    def test_snapshot_without_os_disk_or_wrong_domain_rejected(self):
        import command2_portable_master_nat_attach as nat
        def query(*args):
            if args==("domstate","win11"):
                return "shut off"
            if args==("snapshot-list","win11","--name"):
                return "Afterfull"
            if args==("snapshot-dumpxml","win11","Afterfull"):
                return snapshot[0]
            raise AssertionError(args)
        candidates=(
            '<domainsnapshot><name>Afterfull</name><state>running</state>'
            '<memory snapshot="internal"/><domain><name>win11</name></domain>'
            '</domainsnapshot>',
            '<domainsnapshot><name>Afterfull</name><state>running</state>'
            '<memory snapshot="internal"/>'
            '<disks><disk name="sda" snapshot="no"/></disks>'
            '<domain><name>win11</name></domain></domainsnapshot>',
            '<domainsnapshot><name>Afterfull</name><state>running</state>'
            '<memory snapshot="internal"/>'
            '<disks><disk name="sda" snapshot="internal"/></disks>'
            '<domain><name>not-win11</name></domain></domainsnapshot>',
        )
        snapshot=[""]
        with patch.object(nat,"virsh",side_effect=query):
            for xml in candidates:
                snapshot[0]=xml
                with self.subTest(xml=xml), self.assertRaisesRegex(
                        m.KvmBlocked,"RAM"):
                    m.find_master_snapshot("Afterfull")

    def test_approved_config_only_apply_backup_and_repeat_noop(self):
        import command2_portable_master_nat_attach as nat
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)/"CAPE"/"conf"
            directory.mkdir(parents=True)
            conf=directory/"kvm.conf"
            conf.write_bytes(LIVE)
            conf.chmod(0o640)
            save=Path(td)/"backups"
            original=conf.read_bytes()
            def fake_private_backup_dir(path):
                folder=Path(path)
                folder.mkdir(mode=0o700)
                return folder
            with patch.object(nat.workflow,"canonical_host"), \
                 patch.object(m,"discover",return_value=(
                      guests(3),"192.168.122.1")), \
                 patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m.socket,"gethostname",return_value="other-host"), \
                 patch.object(m.backup_guard,"safe_backup_dir",
                              side_effect=fake_private_backup_dir), \
                 patch("builtins.input",return_value=m.APPROVAL):
                out=m.apply(conf,"other-host",
                            Path("/root/cape/command2-identity-reservation.json"),
                            "192.168.122.125","Afterfull","win11",save)
            self.assertTrue(out["applied"])
            self.assertEqual(out["result"],
                             "COMMAND3_KVM_ALL_N_CONFIG_ONLY_APPLIED_NOT_STARTED")
            self.assertFalse(out["cape_service_restarted"])
            self.assertFalse(out["CAPE_READY"])
            self.assertIn(b"machines = win11,win11_1,win11_2,win11_3",
                          conf.read_bytes())
            self.assertEqual(Path(out["backup_path"]).read_bytes(),original)
            self.assertEqual(Path(out["backup_path"]).stat().st_mode & 0o777,0o600)
            with patch.object(nat.workflow,"canonical_host"), \
                 patch.object(m,"discover",return_value=(
                      guests(3),"192.168.122.1")), \
                 patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m.socket,"gethostname",return_value="other-host"), \
                 patch("builtins.input",
                       side_effect=AssertionError("Already configured")):
                again=m.apply(conf,"other-host",
                              Path("/root/cape/command2-identity-reservation.json"),
                              "192.168.122.125","Afterfull","win11",save)
            self.assertFalse(again["applied"])
            self.assertEqual(len(list(save.iterdir())),1)

    def test_declined_approval_does_not_touch_kvm_or_create_backup(self):
        import command2_portable_master_nat_attach as nat
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)/"CAPE"/"conf"
            directory.mkdir(parents=True)
            conf=directory/"kvm.conf"
            conf.write_bytes(LIVE)
            save=Path(td)/"backups"
            with patch.object(nat.workflow,"canonical_host"), \
                 patch.object(m,"discover",return_value=(
                      guests(2),"192.168.122.1")), \
                 patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m.socket,"gethostname",return_value="other-host"), \
                 patch("builtins.input",return_value="NO"), \
                 self.assertRaisesRegex(m.KvmBlocked,"authorize"):
                m.apply(conf,"other-host",
                        Path("/root/cape/command2-identity-reservation.json"),
                        "192.168.122.125","Afterfull","win11",save)
            self.assertEqual(conf.read_bytes(),LIVE)
            self.assertFalse(save.exists())

    def test_manual_apply_never_touches_ssl55(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"), \
             patch.object(m,"plan",side_effect=AssertionError("not even plan")), \
             self.assertRaisesRegex(m.KvmBlocked,"SSL-55"):
            m.apply(Path("/opt/CAPEv2/conf/kvm.conf"),"CSE-SSL-55",
                    Path("/root/private/command2-identity-reservation.json"),
                    "192.168.122.125","Afterfull","win11",
                    Path("/var/backups/cape-command3"))


if __name__=="__main__":
    unittest.main()
