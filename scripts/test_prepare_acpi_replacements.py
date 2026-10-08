import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from prepare_acpi_replacements import VARS, DEVICE_VARS

SCRIPT=Path(__file__).parent/'prepare_acpi_replacements.py'

def table(oem=b'DELL  ', table=b'Dell Inc', signature=b'DSDT'):
    assert len(oem)==6 and len(table)==8
    data=bytearray(36+16)
    data[:4]=signature
    data[4:8]=len(data).to_bytes(4,'little')
    data[8]=2
    data[10:16]=oem
    data[16:24]=table
    data[9]=(-sum(data))&255
    return bytes(data)

class ACPIAutomationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.installer=self.root/'checkout'/'installer'
        self.installer.mkdir(parents=True)
        self.target=self.installer/'kvm-qemu.sh'
        self.original='#!/bin/bash\n# untouched comment\n'+''.join(f"{v}='<WOOT>'\n" for v in VARS)+"MASK_APT_DAILY_UPGRADE=1\n"
        self.target.write_text(self.original)
        self.target.chmod(0o755)
        self.dsdt=self.root/'dsdt.dat'
        self.dsdt.write_bytes(table())
        self.profile=self.root/'reviewed.json'
        self.values={v: ('ACME' if 'BOCHS' not in v else 'SEAGATE') for v in DEVICE_VARS}
        self.profile.write_text(json.dumps(self.values))
        self.backup=self.root/'external-backups'
        self.base=[sys.executable,str(SCRIPT),'--script',str(self.target),'--dsdt',str(self.dsdt)]
    def run_program(self,*args):
        return subprocess.run(self.base+list(args),capture_output=True,text=True)
    def apply_args(self):
        digest=hashlib.sha256(self.original.encode()).hexdigest()
        return ('--profile',str(self.profile),'--apply','--expected-sha256',digest,'--backup-dir',str(self.backup))
    def test_discovery_audit_without_profile_no_writes(self):
        r=self.run_program()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('BXPC candidate: DELL',r.stdout)
        self.assertEqual(self.target.read_text(),self.original)
    def test_dryrun_without_writes(self):
        r=self.run_program('--profile',str(self.profile))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('DRY RUN',r.stdout)
        self.assertEqual(self.target.read_text(),self.original)
    def test_apply_and_second_run(self):
        args=self.apply_args()
        r=self.run_program(*args)
        self.assertEqual(r.returncode,0,r.stderr)
        after=self.target.read_text()
        self.assertNotIn('<WOOT>',after)
        self.assertIn("BXPC_REPLACER='DELL'",after)
        self.assertIn('# untouched comment',after)
        self.assertEqual(self.target.stat().st_mode & 0o777,0o755)
        backups=list(self.backup.glob('*.bak'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_text(),self.original)
        self.assertEqual(self.run_program(*args).returncode,0)
        self.assertEqual(len(list(self.backup.glob('*.bak'))),1)
    def test_wrong_source_pin_refuses(self):
        args=list(self.apply_args())
        args[args.index('--expected-sha256')+1]='0'*64
        r=self.run_program(*args)
        self.assertEqual(r.returncode,2)
        self.assertEqual(self.target.read_text(),self.original)
    def test_apply_without_pin_refuses(self):
        r=self.run_program('--profile',str(self.profile),'--apply','--backup-dir',str(self.backup))
        self.assertEqual(r.returncode,2)
        self.assertEqual(self.target.read_text(),self.original)
    def test_partial_edit_refuses(self):
        self.target.write_text(self.original.replace("PEN_REPLACER='<WOOT>'", "PEN_REPLACER='DELL'"))
        r=self.run_program('--profile',str(self.profile))
        self.assertEqual(r.returncode,2)
    def test_ambiguous_4_byte_oem_candidates_refuses(self):
        self.dsdt.write_bytes(table(oem=b'ABCD  ',table=b'WXYZ    '))
        r=self.run_program()
        self.assertEqual(r.returncode,2)
        self.assertIn('Conflicting',r.stderr)
    def test_ssl45_oem_table_id_is_eligible(self):
        self.dsdt.write_bytes(table(oem=b'HPQOEM',table=b'895C    '))
        r=self.run_program()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('BXPC candidate: 895C',r.stdout)
    def test_unsupported_oem_lengths_refuse(self):
        self.dsdt.write_bytes(table(oem=b'HPQOEM',table=b'ABCDEFGH'))
        self.assertEqual(self.run_program().returncode,2)
    def test_reference_vm_custom_not_truncated(self):
        # Screenshot method 3a: PTLTD + Custom is not a four-byte ID.
        self.dsdt.write_bytes(table(oem=b'PTLTD ', table=b'Custom  '))
        r=self.run_program()
        self.assertEqual(r.returncode,2)
        self.assertIn('Neither DSDT OEM field',r.stderr)
        self.assertEqual(self.target.read_text(),self.original)

    def test_reference_dell_cbx3_ambiguity_is_not_guessed(self):
        # Screenshot method 3c: Dell CBX3 conflicts with four-byte DELL OEM ID.
        self.dsdt.write_bytes(table(oem=b'DELL  ',table=b'CBX3    '))
        r=self.run_program()
        self.assertEqual(r.returncode,2)
        self.assertIn('Conflicting',r.stderr)

    def test_cbx3_is_eligible_when_unambiguous(self):
        self.dsdt.write_bytes(table(oem=b'DELLXX',table=b'CBX3    '))
        r=self.run_program()
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('BXPC candidate: CBX3',r.stdout)

    def test_pnp0_generic_hardware_id_is_not_selected(self):
        # Screenshot method 3b: generic PNP0-prefix Hardware IDs are not OEMs.
        self.dsdt.write_bytes(table(oem=b'PTLTD ',table=b'PNP0    '))
        r=self.run_program()
        self.assertEqual(r.returncode,2)
        self.assertIn('Generic/virtual ACPI identifier',r.stderr)

    def test_virtual_machine_tokens_are_rejected(self):
        for token in (b'QEMU',b'BXPC',b'VBOX',b'ACPI'):
            with self.subTest(token=token):
                self.dsdt.write_bytes(table(oem=b'PTLTD ',table=token+b'    '))
                r=self.run_program()
                self.assertEqual(r.returncode,2)
                self.assertIn('Generic/virtual ACPI identifier',r.stderr)

    def test_wrong_checksum_refuses(self):
        b=bytearray(self.dsdt.read_bytes()); b[35]^=1; self.dsdt.write_bytes(b)
        self.assertEqual(self.run_program().returncode,2)
    def test_no_unreviewed_replacements(self):
        self.values['PEN_REPLACER']='BAD/VAL'
        self.profile.write_text(json.dumps(self.values))
        self.assertEqual(self.run_program('--profile',str(self.profile)).returncode,2)
    def test_script_symlink_refuses(self):
        link=self.installer/'link.sh'
        link.symlink_to(self.target)
        r=subprocess.run([sys.executable,str(SCRIPT),'--script',str(link),'--dsdt',str(self.dsdt)],capture_output=True,text=True)
        self.assertEqual(r.returncode,2)
    def test_no_rerun_with_mismatched_profile(self):
        args=self.apply_args()
        self.assertEqual(self.run_program(*args).returncode,0)
        self.values['PEN_REPLACER']='OTHER'
        self.profile.write_text(json.dumps(self.values))
        self.assertEqual(self.run_program('--profile',str(self.profile)).returncode,2)

if __name__=='__main__': unittest.main(verbosity=2)
