"""Synthetic tests only: no physical VM or libvirt mutations."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import command2_cold_checkpoint as c


def fixture_xml(nic=""):
    return (f'<domain type="kvm"><name>{c.VM}</name><uuid>{c.UUID}</uuid>'
            f'<os><nvram>{c.NVRAM}</nvram></os><devices>'
            f'<disk type="file" device="disk"><driver type="qcow2"/>'
            f'<source file="{c.DISK}"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            f'{nic}</devices></domain>')


class ColdTests(unittest.TestCase):
    def test_python_source_compiles_and_no_restore(self):
        script = Path(c.__file__).read_text()
        compile(script, c.__file__, 'exec')
        self.assertNotIn('snapshot-revert', script)
        self.assertNotIn('virsh("destroy"', script)
        self.assertNotIn('virsh("shutdown"', script)

    def test_exact_disk_firmware_tpm_no_nics(self):
        self.assertEqual(c.parse_clone_xml(fixture_xml()), fixture_xml())
        for new in ('<interface type="network"/>', '<hostdev/>', '<channel/>'):
            with self.subTest(tag=new), self.assertRaisesRegex(c.Blocked, 'Forbidden'):
                c.parse_clone_xml(fixture_xml(new))

    def test_protected_path_and_uuid_fail(self):
        with self.assertRaisesRegex(c.Blocked, 'Unexpected clone disk'):
            c.parse_clone_xml(fixture_xml().replace(c.DISK.name, 'win11.qcow2'))
        with self.assertRaisesRegex(c.Blocked, 'Unexpected clone identity'):
            c.parse_clone_xml(fixture_xml().replace(c.UUID, 'different-uuid'))
        with self.assertRaisesRegex(c.Blocked, 'NVRAM'):
            c.parse_clone_xml(fixture_xml().replace(c.NVRAM.name, 'bad.vars'))
        with self.assertRaisesRegex(c.Blocked, 'TPM'):
            c.parse_clone_xml(fixture_xml().replace('version="2.0"', 'version="1.2"'))

    def test_read_only_plan_does_not_copy(self):
        with patch.object(c, 'guards', return_value={'status':'running',
                    'tpm':[Path('tpm2-00.permall')], 'free':96*c.GIB,
                    'conservative_required':94*c.GIB}), patch.object(c, 'copy_file',
                    side_effect=AssertionError('unexpected copy')):
            report = c.plan()
        self.assertTrue(report['no_host_changes'])
        self.assertFalse(report['snapshot_or_restore_created'])
        self.assertTrue(report['capture_requires_guest_shutdown'])
        self.assertEqual(report['capture_capacity_gate_gib'],104)
        self.assertFalse(report['capture_capacity_gate_pass'])

    def test_tpm_reject_symlink_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            d=root/'uuid'/'tpm2';d.mkdir(parents=True)
            with patch.object(c, 'TPM_DIR', d):
                with self.assertRaisesRegex(c.Blocked, 'Missing TPM'):
                    c.tpm_inventory()
                (d/'tpm2-00.permall').symlink_to('/etc/passwd')
                with self.assertRaisesRegex(c.Blocked, 'symlink'):
                    c.tpm_inventory()

    def test_copy_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'src'; source.write_bytes(b'abcdef' * 500)
            out=Path(tmp)/'dest'
            meta=c.file_meta(source)
            with patch.object(c, 'free_bytes', return_value=100*c.GIB), \
                 patch.object(c, 'virsh', return_value='shut off'), \
                 patch.object(c, 'assert_stopped_processes'):
                record=c.copy_file(source,out,mode=0o600,owner=(0,0),
                                   expected_identity=meta['identity'])
            self.assertEqual(record['size'], 3000)
            self.assertEqual(out.read_bytes(), source.read_bytes())
            self.assertEqual(record['sha256'], c.sha(out))
            with self.assertRaisesRegex(c.Blocked, 'Destination exists'):
                c.copy_file(source,out,mode=0o600,owner=(0,0),
                            expected_identity=meta['identity'])

    def test_low_disk_aborts_and_retains_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'src'; source.write_bytes(b'message')
            out=Path(tmp)/'dest';meta=c.file_meta(source)
            with patch.object(c, 'free_bytes', return_value=1):
                with self.assertRaisesRegex(c.Blocked, 'Storage floor'):
                    c.copy_file(source,out,mode=0o600,owner=(0,0),
                                expected_identity=meta['identity'])
            self.assertTrue(out.exists())

    def test_running_capture_refused(self):
        with patch.object(c, 'guards', side_effect=c.Blocked('shut off')):
            with self.assertRaises(c.Blocked):
                c.capture()

    def test_verify_reject_manifest_traversal_before_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp)/'checkpoints';parent.mkdir()
            target=parent/'cold-20261011T010000Z-abcdef123456'
            target.mkdir();(target/'swtpm').mkdir()
            (target/'manifest.json').write_text(json.dumps({
                'version':1,'vm':c.VM,'uuid':c.UUID,
                'kind':'command2-cold-clone-checkpoint',
                'artifacts':[{'name':'../master.qcow2'}]*4}))
            (target/'manifest.json').chmod(0o600)
            with patch.object(c,'CHECKPOINTS',parent),patch.object(c.os,'geteuid',return_value=0):
                with self.assertRaisesRegex(c.Blocked, 'Duplicate'):
                    c.verify(target)

    def test_source_change_while_copying_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'src';source.write_bytes(b'a'*30)
            meta=c.file_meta(source)
            source.write_bytes(b'b'*30)
            with self.assertRaisesRegex(c.Blocked, 'Source changed'):
                c.copy_file(source,Path(tmp)/'dest',mode=0o600,owner=(0,0),
                            expected_identity=meta['identity'])

if __name__ == '__main__':
    unittest.main()
