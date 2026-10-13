"""Offline golden-master bundle tests. No actual win11 or VM touched."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import os
import stat
import tempfile
import unittest

import command1_export_existing_master as m

UUID="289d89be-68ec-4c62-90e1-ea930849266f"

def original_xml(disk,nv):
    return ('<domain type="kvm"><name>win11</name><uuid>'+UUID+
      '</uuid><os><nvram format="raw">'+str(nv)+'</nvram></os>'
      '<devices><disk type="file" device="disk"><driver type="qcow2"/>'
      '<source file="'+str(disk)+'"/></disk>'
      '<tpm><backend type="emulator" version="2.0"/></tpm>'
      '<interface type="network"><source network="default"/>'
      '<mac address="52:54:00:00:00:50"/><model type="e1000e"/>'
      '</interface></devices></domain>')

class GoldenMaster(unittest.TestCase):
    def fixtures(self,td):
        root=Path(td)
        disk=root/"source.qcow2";disk.write_bytes(b"WIN11 APPS REGISTRY DATA")
        nv=root/"vars.fd";nv.write_bytes(b"UEFI")
        tpm=root/"swtpm"/UUID/"tpm2";tpm.mkdir(parents=True)
        (tpm/"tpm2-00.permall").write_bytes(b"TPM PRIVATE STATE")
        xml=original_xml(disk,nv)
        dest=root/"cape-master-exact-cold"
        def virsh(*args):
            if args==("domstate","win11"):return "shut off"
            if args==("domuuid","win11"):return UUID
            if args==("dumpxml","--inactive","win11"):return xml
            if args==("list","--name"):return ""
            raise AssertionError(args)
        def run(*args,**kw):
            if args[:3]==("qemu-img","info","--output=json"):
                return json.dumps({"format":"qcow2",
                         "virtual-size":64*1024**3})
            if args[:3]==("qemu-img","convert","-p"):
                Path(args[-1]).write_bytes(disk.read_bytes())
                return ""
            if args[:3]==("qemu-img","check","-q"):
                return ""
            raise AssertionError(args)
        return disk,nv,tpm,xml,dest,virsh,run

    def test_capture_golden_master_contains_apps_uefi_tpm_xml_and_shas(self):
        with tempfile.TemporaryDirectory() as td:
            disk,nv,tpm,xml,dest,virsh,run=self.fixtures(td)
            # The real exporter REQUIRES root-owned 0700/0600 files.
            # In an unprivileged CI fixture, simulate only the UID of
            # files inside the synthetic bundle; leave production guard
            # code unchanged and preserve actual sizes/modes/checksums.
            real_stat=Path.stat
            def owned_stat(path,*args,**kwargs):
                st=real_stat(path,*args,**kwargs)
                if path==dest or dest in path.parents:
                    values=list(st)
                    values[4]=0  # UID field in os.stat_result
                    return os.stat_result(values)
                return st
            with patch.object(Path,"stat",owned_stat),\
                 patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(m,"virsh",side_effect=virsh),\
                 patch.object(m,"run",side_effect=run),\
                 patch.object(m,"safe_parent",side_effect=lambda x:dest),\
                 patch.object(m,"source",side_effect=lambda :{
                     "vm":"win11","uuid":UUID,"domain_xml":xml,
                     "source_disk":disk,"source_nvram":nv,
                     "tpm_members":sorted(tpm.iterdir()),"tpm_dir":tpm,
                     "virtual_size":64*1024**3,
                     "master_shut_off":True}),\
                 patch.object(m.shutil,"disk_usage",
                   return_value=SimpleNamespace(free=120*1024**3)),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.APPROVE),\
                 patch.object(m,"ROOT",Path(td)/"master-export.lock"),\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                     st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)):
                result=m.capture(dest)
            self.assertEqual(result["result"],
               "COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED")
            self.assertEqual(result["artifact_count"],4)
            self.assertEqual((dest/m.FILES["disk"]).read_bytes(),
                             b"WIN11 APPS REGISTRY DATA")
            self.assertEqual((dest/"tpm-tpm2-00.permall").read_bytes(),
                             b"TPM PRIVATE STATE")
            self.assertEqual((dest/m.FILES["xml"]).read_text(),xml)
            self.assertEqual(result["manifest_sha256"],
                hashlib.sha256((dest/m.MANIFEST).read_bytes()).hexdigest())
            self.assertFalse(result["auto_windows_clone_identity_or_tpm_revert_proven"])
            self.assertTrue(result["master_swtpm_secrets_in_private_bundle"])
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o700)
            (dest/m.FILES["disk"]).write_bytes(b"CORRUPT")
            with patch.object(Path,"stat",owned_stat), \
                 self.assertRaisesRegex(m.MasterExportBlocked,"CORRUPTION"):
                m.manifest_check(dest)

    def test_master_flatten_reads_exact_checked_backing_chain(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            top=root/"top.qcow2";top.write_bytes(b"active Windows changes")
            lower=root/"backing.qcow2";lower.write_bytes(b"older Windows files")
            data=[
                {"format":"qcow2","filename":str(top),
                 "virtual-size":64*1024**3,
                 "full-backing-filename":str(lower)},
                {"format":"qcow2","filename":str(lower),
                 "virtual-size":64*1024**3}]
            with patch.object(m,"run",return_value=json.dumps(data)):
                paths,capacity=m.backing_chain(top)
                self.assertEqual(paths,[top,lower])
                self.assertEqual(capacity,64*1024**3)
            bad=list(data)
            bad[0]=dict(data[0],**{
                "full-backing-filename":"/other/unreviewed.qcow2"})
            with patch.object(m,"run",return_value=json.dumps(bad)),\
                 self.assertRaisesRegex(m.MasterExportBlocked,"chain"):
                m.backing_chain(top)
            lower.unlink()
            with patch.object(m,"run",return_value=json.dumps(data)),\
                 self.assertRaises(m.MasterExportBlocked):
                m.backing_chain(top)

    def test_swtpm_lock_directory_validation_with_actual_source_function(self):
        with tempfile.TemporaryDirectory() as td:
            disk,nv,tpm,xml,dest,virsh,run=self.fixtures(td)
            lock=tpm/".lock"
            lock.touch()
            state_base=Path("/var/lib/libvirt/swtpm")
            real_path_cls=m.Path
            # Supply a fake Path factory only for the hardcoded TPM root.
            def fake_path(x):
                if str(x)==str(state_base):
                    return Path(td)/"swtpm"
                return Path(x)
            with patch.object(m,"Path",side_effect=fake_path), \
                 patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"), \
                 patch.object(m,"virsh",side_effect=virsh), \
                 patch.object(m,"backing_chain",
                     return_value=([disk],64*1024**3)):
                source=m.source()
                self.assertEqual(source["tpm_members"],
                                 [tpm/"tpm2-00.permall"])
                self.assertNotIn(lock,source["tpm_members"])
                for corrupt in (b"tampered",):
                    lock.write_bytes(corrupt)
                    with self.assertRaisesRegex(
                        m.MasterExportBlocked,"Unexpected swtpm .lock"):
                        m.source()
                    lock.write_bytes(b"")
                lock.unlink()
                lock.symlink_to(tpm/"tpm2-00.permall")
                with self.assertRaisesRegex(
                    m.MasterExportBlocked,"Unexpected swtpm .lock"):
                    m.source()
                lock.unlink()
                os.link(tpm/"tpm2-00.permall",lock)
                with self.assertRaisesRegex(
                    m.MasterExportBlocked,"Unexpected swtpm .lock"):
                    m.source()

    def test_source_rejects_powered_master_or_forged_id(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"virsh",return_value="running"),\
             self.assertRaisesRegex(m.MasterExportBlocked,"SHUT OFF"):
            m.source()
        def forged(*args):
            if args[0]=="domstate":return "shut off"
            if args[0]=="domuuid":return "ffffffff-ffff-ffff-ffff-ffffffffffff"
            raise AssertionError(args)
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m,"virsh",side_effect=forged),\
             self.assertRaisesRegex(m.MasterExportBlocked,"identity"):
            m.source()

    def test_root_only_destination_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)
            leaf=parent/"cape-master-cold"
            with patch.object(m.os,"geteuid",return_value=0),\
                 self.assertRaises(m.MasterExportBlocked):
                m.safe_parent(leaf)
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.Path,"stat",autospec=True):
                pass

    def test_no_source_or_vm_mutators(self):
        text=Path(m.__file__).read_text()
        for forbid in ('"snapshot-revert"','"snapshot-delete"',
            '"shutdown"','"destroy"','"start"','"define"',
            '"net-update"','"attach-interface"','"detach-interface"',
            'shell=True'):
            self.assertNotIn(forbid,text)

if __name__=="__main__":unittest.main()
