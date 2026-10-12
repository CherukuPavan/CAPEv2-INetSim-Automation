"""Unified Command2 workflow: offline dispatch/admission tests only, no host actions."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import command2_portable_workflow as w

HOST="approved-other-host"
SUBNET="192.168.241.0/24"

def row(i):
    return {
        "libvirt_name":f"win11_{i}",
        "libvirt_uuid_candidate":f"12345678-1234-4234-8234-{i:012d}",
        "smbios_generation_id_candidate":f"abcdabcd-aaaa-4aaa-8aaa-{i:012d}",
        "windows_hostname_target":f"WIN11-{i}",
        "guest_static_ipv4_target":f"192.168.241.{100+i}",
        "mac_candidate":f"02:ee:01:02:03:{i:02x}",
        "disk_target":f"/private/images/win11_{i}.command2.qcow2",
        "uefi_nvram_target":f"/private/nvram/win11_{i}.command2_VARS.fd"}

def args(phase,mode="plan",**overrides):
    default=dict(phase=phase,mode=mode,approved_host=HOST,vm="win11_1",
                 count=None,journal=Path("/tmp/notset/command2-identity-reservation.json"),
                 journal_dir=None,disk_dir=None,nvram_dir=None,
                 template=None,template_sha256=None,subnet="auto",
                 network_receipt=None,snapshot_receipt=None,
                 witness_dir=None,kvm_conf=None,recovery_bundle=None,
                 manifest_sha256=None,acknowledge_restore=None,
                 firmware_restore_witness=None,xml_backup_dir=None,
                 acknowledge_revert=None)
    default.update(overrides)
    return argparse.Namespace(**default)

class Workflow(unittest.TestCase):
    def makefixture(self,root,n=2):
        root=Path(root)
        rows=[row(i) for i in range(1,n+1)]
        journal=root/"command2-identity-reservation.json"
        journal.write_text(json.dumps({"format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
             "version":1,"guest_count":n,"entries":rows,
             "host":HOST,"host_network_modified":False}))
        for r in rows:
            value=w.windows.make_guest_config(r,SUBNET)
            filename="command2-guest-config-"+r["libvirt_name"]+".json"
            (root/filename).write_bytes(w.identity.render_config(value))
        return journal,rows

    def choose_fixture(self,journal,rows,phase,mode="plan",**kwargs):
        with patch.object(w,"canonical_host",return_value=HOST),\
             patch.object(w.os,"geteuid",return_value=0),\
             patch.object(w.sys.stdin,"isatty",return_value=True),\
             patch.object(w.snapshotgate,"private_evidence_folder"),\
             patch.object(w.snapshotgate,"reservation_rows",return_value=rows),\
             patch.object(w.identity,"guarded_regular"):
            return w.choose(args(phase,mode,journal=journal,**kwargs))

    def test_identity_build_uses_exact_reservation_paths_and_no_shell(self):
        with TemporaryDirectory() as td:
            journal,rows=self.makefixture(td)
            script,argv,meta=self.choose_fixture(journal,rows,"identity-build")
            self.assertEqual(script.name,"command2_portable_guest_identity_iso.py")
            self.assertEqual(argv[argv.index("--mode")+1],"plan")
            self.assertEqual(argv[argv.index("--dest")+1],
                             str(Path(td)/"win11_1.command2_identity.iso"))
            self.assertEqual(argv[argv.index("--config")+1],
                             str(Path(td)/"command2-guest-config-win11_1.json"))
            self.assertFalse(meta["master_vm_mutations_authorized"])

    def test_stage_apply_delegates_to_authoritative_count_stager(self):
        with patch.object(w,"canonical_host",return_value=HOST),\
             patch.object(w.os,"geteuid",return_value=0),\
             patch.object(w.sys.stdin,"isatty",return_value=True):
            script,argv,meta=w.choose(args("stage","apply",
                   count=2,disk_dir=Path("/private/images"),
                   nvram_dir=Path("/private/nvram"),
                   template=Path("/private/master-template.qcow2"),
                   template_sha256="a"*64,
                   journal_dir=Path("/private/journal")))
            self.assertEqual(script.name,"command2_portable_zero_nic_entrypoint.py")
            self.assertEqual(argv[argv.index("--count")+1],"2")
            self.assertEqual(argv[argv.index("--mode")+1],"stage")
            self.assertEqual(meta["stage"],"ZERO_NIC_COUNT_DRIVEN_ONLY")
            self.assertFalse(meta["guest_approval_or_boot_performed"])

    def test_network_install_uses_exact_reserved_subnet_not_user_override(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            script,argv,result=self.choose_fixture(j,rows,"network-install","apply",
                                                  subnet="10.255.255.0/24")
            self.assertEqual(script.name,"command2_portable_network_install.py")
            self.assertEqual(argv[argv.index("--mode")+1],"install")
            self.assertEqual(argv[argv.index("--journal")+1],str(j))
            self.assertEqual(result["subnet"],SUBNET)
            self.assertNotIn("10.255.255.0/24",argv)
            self.assertTrue(result["not_production_release"])

    def test_network_receipt_is_mandatory_before_host_media_change(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            with self.assertRaisesRegex(w.WorkflowBlocked,"network_receipt"):
                self.choose_fixture(j,rows,"network-approve","apply")
            script,argv,_=self.choose_fixture(j,rows,"network-approve",
                                             "apply",
                              network_receipt=Path("/private/approval.json"))
            self.assertEqual(script.name,"command2_portable_network_approval_iso.py")
            self.assertIn("/private/approval.json",argv)

    def test_nic_attach_is_guest_specific_and_cannot_invent_mac_or_ip(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            script,argv,data=self.choose_fixture(j,rows,"nic-attach","apply",
                  network_receipt=Path("/private/receipt"))
            self.assertEqual(data["subnet"],SUBNET)
            self.assertEqual(argv[argv.index("--uuid")+1],
                             rows[0]["libvirt_uuid_candidate"])
            self.assertEqual(argv[argv.index("--mac")+1],rows[0]["mac_candidate"])
            self.assertEqual(script.name,"command2_guarded_isolated_nic.py")

    def test_cold_restore_has_extra_risk_ack_and_pinned_manifest(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            with self.assertRaisesRegex(w.WorkflowBlocked,"restore-risk"):
                self.choose_fixture(j,rows,"cold-restore","apply",
                         recovery_bundle=Path("/private/backup"),
                         manifest_sha256="a"*64)
            script,argv,_=self.choose_fixture(j,rows,"cold-restore","apply",
                 recovery_bundle=Path("/private/backup"),manifest_sha256="a"*64,
                 acknowledge_restore="I-ACCEPT-DISPOSABLE-COLD-RESTORE-RISK")
            self.assertEqual(script.name,"command2_portable_cold_bundle.py")
            self.assertEqual(argv[argv.index("--mode")+1],"restore")
            self.assertEqual(argv[argv.index("--manifest-sha256")+1],"a"*64)

    def test_qcow2_firmware_prepare_and_activate_require_real_recovery_evidence(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            script,argv,_=self.choose_fixture(j,rows,"firmware-sidecar","apply",
                     recovery_bundle=Path("/private/cold"),
                     manifest_sha256="a"*64)
            self.assertEqual(script.name,"command2_disposable_nvram_qcow2_prepare.py")
            self.assertEqual(argv[argv.index("--mode")+1],"prepare")
            self.assertEqual(argv[argv.index("--reviewed-manifest-sha")+1],"a"*64)
            with self.assertRaisesRegex(w.WorkflowBlocked,"firmware_restore_witness"):
                self.choose_fixture(j,rows,"firmware-activate","apply",
                        recovery_bundle=Path("/private/cold"),
                        manifest_sha256="a"*64)
            script,argv,_=self.choose_fixture(j,rows,"firmware-activate","apply",
                        recovery_bundle=Path("/private/cold"),manifest_sha256="a"*64,
                        firmware_restore_witness=Path("/private/restore-witness"),
                        xml_backup_dir=Path("/private/xmlbackups"))
            self.assertEqual(script.name,"command2_disposable_nvram_qcow2_activate.py")
            self.assertEqual(argv[argv.index("--mode")+1],"apply")
            self.assertIn("/private/restore-witness",argv)
            self.assertIn("/private/xmlbackups",argv)

    def test_snapshot_capture_must_have_private_witness_and_full_backup(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            with self.assertRaisesRegex(w.WorkflowBlocked,"recovery_bundle"):
                self.choose_fixture(j,rows,"snapshot-capture","apply")
            script,argv,meta=self.choose_fixture(j,rows,"snapshot-capture","apply",
                    recovery_bundle=Path("/private/cold"),
                    snapshot_receipt=Path("/private/acceptance"),
                    manifest_sha256="b"*64)
            self.assertEqual(script.name,"command2_running_cape_snapshot_gate.py")
            self.assertEqual(argv[argv.index("--expected-uuid")+1],
                             rows[0]["libvirt_uuid_candidate"])
            self.assertIn("--reviewed-manifest-sha",argv)
            self.assertEqual(meta["guest_ip"],"192.168.241.101")

    def test_disposable_snapshot_revert_needs_risk_ack_and_exact_vm(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            with self.assertRaisesRegex(w.WorkflowBlocked,"revert risk"):
                self.choose_fixture(j,rows,"snapshot-revert-once","apply",
                  recovery_bundle=Path("/private/cold"),
                  manifest_sha256="a"*64)
            script,argv,result=self.choose_fixture(j,rows,"snapshot-revert-once","apply",
                  recovery_bundle=Path("/private/cold"),manifest_sha256="a"*64,
                  acknowledge_revert="I-ACCEPT-DISPOSABLE-REVERT-RISK")
            self.assertEqual(script.name,"command2_disposable_snapshot_revert_probe.py")
            self.assertEqual(argv[argv.index("--mode")+1],"revert-once")
            self.assertEqual(argv[argv.index("--vm")+1],"win11_1")
            self.assertEqual(argv[argv.index("--manifest-sha256")+1],"a"*64)
            self.assertFalse(result["master_vm_mutations_authorized"])

    def test_final_batch_and_registration_use_same_guest_subnet(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            for phase in ("snapshot-batch","cape-register"):
                script,argv,meta=self.choose_fixture(j,rows,phase,
                       witness_dir=Path("/private/evidence"),
                       kvm_conf=Path("/private/kvm.conf"))
                self.assertEqual(argv[argv.index("--subnet")+1],SUBNET)
                self.assertEqual(meta["vm_count"],2)
                self.assertTrue(meta["not_production_release"])

    def test_reference_host_never_delegates_even_plan(self):
        with patch.object(w.socket,"gethostname",return_value="CSE-SSL-55"):
            with self.assertRaisesRegex(w.WorkflowBlocked,"Protected SSL-55"):
                w.canonical_host("cse-ssl-55")

    def test_invalid_unrecorded_vm_refused(self):
        with TemporaryDirectory() as td:
            j,rows=self.makefixture(td)
            with self.assertRaisesRegex(w.WorkflowBlocked,"absent"):
                self.choose_fixture(j,rows,"identity-build",vm="win11_3")

    def test_root_and_tty_required_for_apply(self):
        with patch.object(w,"canonical_host",return_value=HOST),\
             patch.object(w.os,"geteuid",return_value=0),\
             patch.object(w.sys.stdin,"isatty",return_value=False):
            with self.assertRaisesRegex(w.WorkflowBlocked,"Direct interactive"):
                w.choose(args("stage","apply"))

    def test_dispatch_has_no_implicit_virsh_or_network_mutators(self):
        src=Path(w.__file__).read_text()
        self.assertNotIn("shell=True",src)
        self.assertIn("subprocess.run([sys.executable",src)
        for forbidden in ('"snapshot-revert"','"snapshot-create-as"',
                          '"destroy"','"start"','"shutdown"',
                          '"attach-interface"','"net-start"',
                          '"nft","add"'):
            self.assertNotIn(forbidden,src)

if __name__=="__main__":
    unittest.main()
