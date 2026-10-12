"""Synthetic preflight and blockpull invocation tests. No KVM required."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import command2_ssl55_clone_blockpull as s

def xml(chain=None, wrong_network=False):
    chain = list(s.BACKING if chain is None else chain)
    frag = ""
    for x in chain:
        frag += '<backingStore><source file="' + x + '"/>'
    frag += "<backingStore/>" + "</backingStore>"*len(chain)
    net = "default" if wrong_network else "cape-analysis-isolated"
    return (f'<domain><name>{s.VM}</name><uuid>{s.UUID}</uuid><os>'
            f'<nvram>{s.NVRAM}</nvram></os><devices>'
            '<disk device="disk"><driver type="qcow2"/>'
            f'<source file="{s.DISK}"/><target dev="vda"/>{frag}</disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            f'<interface type="network"><source network="{net}"/>'
            '<mac address="02:0a:30:6a:3f:50"/></interface>'
            '</devices></domain>')

def fake_virsh(*args):
    if args[:1] == ("domuuid",):
        return dict((s.VM, s.UUID), (s.MASTER[0], s.MASTER[1]),
                    (s.TRIAL[0], s.TRIAL[1]))[args[1]]
    if args[:1] == ("domstate",):
        return "running" if args[1] == s.VM else "shut off"
    if args == ("snapshot-list", s.VM, "--name"):return ""
    if args[:1] == ("dumpxml",):
        return xml(s.BACKING[:2] if "--inactive" in args else s.BACKING)
    raise AssertionError("Unexpected " + str(args))

class Safety(unittest.TestCase):
    def test_live_saved_expected_backing(self):
        self.assertEqual(s.xml_chain(xml())["chain"],list(s.BACKING))
        self.assertEqual(s.xml_chain(xml(s.BACKING[:2]))["chain"],list(s.BACKING[:2]))
    def test_wrong_network_rejected(self):
        with self.assertRaisesRegex(s.Blocked,"NIC"):
            s.xml_chain(xml(wrong_network=True))
    def test_not_flattened_preflight_tolerances(self):
        m=SimpleNamespace(st_blocks=31*1024**3//512)
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s,"virsh",side_effect=fake_virsh),\
             patch.object(s,"meta",return_value=(1,2,32000,10,11)),\
             patch.object(s,"cmd",return_value=json.dumps({"format":"qcow2","virtual-size":64*s.GIB})),\
             patch.object(s.DISK.__class__,"stat",return_value=m),\
             patch.object(s.os,"statvfs",return_value=SimpleNamespace(f_bavail=100,f_frsize=s.GIB)):
            out=s.preflight()
        self.assertEqual(out["result"],"BLOCKPULL_PREFLIGHT_PASS_NO_WRITES")
        self.assertEqual(out["shared_host_reserve_gib"],40)
    def test_capacity_floor(self):
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s,"virsh",side_effect=fake_virsh),\
             patch.object(s,"meta",return_value=(1,2,32000,10,11)),\
             patch.object(s,"cmd",return_value=json.dumps({"format":"qcow2","virtual-size":64*s.GIB})),\
             patch.object(s.DISK.__class__,"stat",return_value=SimpleNamespace(st_blocks=31*1024**3//512)),\
             patch.object(s.os,"statvfs",return_value=SimpleNamespace(f_bavail=70,f_frsize=s.GIB)):
            with self.assertRaisesRegex(s.Blocked,"Insufficient"):
                s.preflight()
    def test_source_contains_only_blockpull_and_no_blockcommit(self):
        src=Path(s.__file__).read_text()
        self.assertIn('"blockpull", VM, second["target"], "--wait", "--verbose"',src)
        for keyword in ('"blockcommit"', '"snapshot-create-as"', '"snapshot-revert"',
                        '"qemu-monitor-command"', '"destroy"', '"net-start"',
                        '"--pivot"', '"--delete"'):
            # Blocks improper *execution* rather than documentation wording.
            self.assertNotIn('virsh('+keyword,src)
    def test_noninteractive_apply_refuses_first(self):
        with patch.object(s.sys.stdin,"isatty",return_value=False):
            with self.assertRaisesRegex(s.Blocked,"Interactive"):
                s.apply()

if __name__=="__main__":
    unittest.main()
