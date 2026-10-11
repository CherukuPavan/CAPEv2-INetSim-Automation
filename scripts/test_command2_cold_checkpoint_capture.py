"""Mocked complete checkpoint capture and publication; no hypervisor access."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import command2_cold_checkpoint as c


class Capture(unittest.TestCase):
    def exercise(self, fail=False):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            disk=d/'win11_1.command2.qcow2';disk.write_bytes(b'fake-cold-qcow2'*100)
            nvram=d/'win11_1.command2_VARS.fd';nvram.write_bytes(b'UEFI-test')
            tpm_dir=d/'TPM';tpm_dir.mkdir()
            tpm=tpm_dir/'tpm2-00.permall';tpm.write_bytes(b'fake TPM state')
            checkpoint_root=d/'cold-checkpoints'
            lock=d/'capture.lock'
            xml=(f'<domain type="kvm"><name>{c.VM}</name><uuid>{c.UUID}</uuid>'
                 f'<os><nvram>{nvram}</nvram></os><devices>'
                 f'<disk device="disk"><source file="{disk}"/>'
                 f'<driver type="qcow2"/></disk>'
                 '<tpm><backend type="emulator" version="2.0"/></tpm>'
                 '</devices></domain>')
            def fake_guards(mode):
                self.assertEqual(mode, 'capture')
                return {'status':'shut off', 'domain_xml':xml,
                        'disk':c.file_meta(disk),'nvram':c.file_meta(nvram),
                        'tpm':[tpm], 'free':100*c.GIB}
            def virsh(*args):
                if args==('domstate',c.VM): return 'shut off'
                if args==('dumpxml','--inactive',c.VM):return xml
                self.fail('unexpected virsh call: '+str(args))
            with patch.object(c,'DISK',disk),patch.object(c,'NVRAM',nvram),\
                 patch.object(c,'CHECKPOINTS',checkpoint_root),patch.object(c,'LOCK',lock),\
                 patch.object(c,'free_bytes',return_value=100*c.GIB),\
                 patch.object(c,'guards',side_effect=fake_guards),\
                 patch.object(c,'virsh',side_effect=virsh),\
                 patch.object(c,'assert_stopped_processes'):
                if fail:
                    with patch.object(c,'copy_file',side_effect=c.Blocked('simulated copy failure')):
                        with self.assertRaisesRegex(c.Blocked,'simulated'):
                            c.capture()
                    self.assertEqual(len(list(checkpoint_root.glob('.incomplete-*'))),1)
                    self.assertFalse(list(checkpoint_root.glob('cold-*')))
                else:
                    result=c.capture()
                    self.assertEqual(result['artifact_count'],4)
                    self.assertFalse(result['restore_tested'])
                    target=Path(result['checkpoint'])
                    self.assertTrue(target.is_dir())
                    self.assertFalse(list(checkpoint_root.glob('.incomplete-*')))
                    records=json.loads((target/'manifest.json').read_text())
                    self.assertEqual(len(records['artifacts']),4)
                    for row in records['artifacts']:
                        self.assertEqual(c.sha(target/row['name']),row['sha256'])
                    with patch.object(c,'cmd', side_effect=lambda *args,**kwargs:
                            json.dumps({'format':'qcow2','virtual-size':64*c.GIB})
                            if args[1]=='info' else ''):
                        verified=c.verify(target)
                    self.assertEqual(verified['result'],'COLD_CHECKPOINT_FILE_INTEGRITY_VERIFIED')
                    self.assertFalse(verified['restore_tested'])

    def test_capture_files_and_verify(self):self.exercise(False)
    def test_partial_copy_retained(self):self.exercise(True)


if __name__=='__main__':unittest.main()
