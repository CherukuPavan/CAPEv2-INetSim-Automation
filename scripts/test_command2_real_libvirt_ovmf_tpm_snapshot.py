"""Disposable libvirt/QEMU/swtpm/UEFI RAM snapshot test, no Windows VM.

Runs only in an isolated Ubuntu26 CI container with no network attached to
the benign test domain. It attempts real libvirt snapshot-create and TWO
snapshot-revert calls on an OVMF QCOW2+emulated TPM guest in TCG mode.
Failing here is valuable evidence of a release blocker; do not translate
it to user machine scripts or CAPE production acceptance.
"""
from __future__ import annotations

import json
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
import xml.etree.ElementTree as ET


@unittest.skipUnless(
    all(shutil.which(x) for x in (
        "qemu-img","qemu-system-x86_64","swtpm","libvirtd","virsh")),
    "Requires dedicated disposable libvirt/TPM CI runtime")
class RealLibvirtSnapshot(unittest.TestCase):
    def run_virsh(self,*args,timeout=75):
        proc=subprocess.run(["virsh","-c","qemu:///system",*args],
             text=True,capture_output=True,check=False,timeout=timeout)
        if proc.returncode:
            raise AssertionError("virsh "+str(args)+" failed: "+proc.stderr[:2400])
        return proc.stdout.strip()

    def run_tool(self,*args,timeout=50):
        proc=subprocess.run(args,text=True,capture_output=True,
                            timeout=timeout,check=False)
        self.assertEqual(proc.returncode,0,(str(args),proc.stderr[:3000]))
        return proc.stdout

    def test_benign_libvirt_running_snapshot_and_two_real_reverts(self):
        for name in ("qemu-img","qemu-system-x86_64","swtpm","libvirtd","virsh"):
            self.assertTrue(shutil.which(name),name)
        fw=Path("/usr/share/OVMF")
        code=fw/"OVMF_CODE_4M.fd"
        template=fw/"OVMF_VARS_4M.fd"
        self.assertTrue(code.is_file() and template.is_file())
        # Guest resources remain completely within a disposable CI
        # container and never inherit a physical machine's disk or network.
        image_parent=Path("/var/lib/libvirt/images")
        self.assertTrue(image_parent.is_dir())
        guest_user=pwd.getpwnam("libvirt-qemu")
        with tempfile.TemporaryDirectory(
                prefix="cape-blank-tcg-",dir=str(image_parent)) as tmp:
            root=Path(tmp)
            root.chown(guest_user.pw_uid,guest_user.pw_gid)
            disk=root/"blank.qcow2"
            varsfile=root/"vars.qcow2"
            self.run_tool("qemu-img","create","-f","qcow2",str(disk),"128M")
            self.run_tool("qemu-img","convert","-f","raw","-O","qcow2",
                          str(template),str(varsfile))
            disk.chown(guest_user.pw_uid,guest_user.pw_gid)
            varsfile.chown(guest_user.pw_uid,guest_user.pw_gid)
            name="cape-ci-blank-"+uuid.uuid4().hex[:10]
            xml=f"""<domain type='qemu'>
  <name>{name}</name>
  <memory unit='MiB'>256</memory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' type='pflash' format='raw'>{code}</loader>
    <nvram format='qcow2'>{varsfile}</nvram>
  </os>
  <features><acpi/><apic/></features>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk}'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <controller type='sata' index='0'/>
    <tpm model='tpm-tis'><backend type='emulator' version='2.0'/></tpm>
    <graphics type='none'/>
    <memballoon model='none'/>
  </devices>
</domain>"""
            ET.fromstring(xml)
            xmlpath=root/"test.xml"
            xmlpath.write_text(xml)
            domain_created=False
            try:
                self.run_virsh("define",str(xmlpath))
                domain_created=True
                details=self.run_virsh("dumpxml",name)
                node=ET.fromstring(details)
                self.assertFalse(node.findall("./devices/interface"))
                self.run_virsh("start",name,timeout=120)
                self.assertEqual(self.run_virsh("domstate",name),"running")
                # Default is internal full snapshot: records RAM and disk.
                result=self.run_virsh("snapshot-create-as",name,
                           "--name","CAPE_BENIGN_TPM","--atomic",timeout=180)
                self.assertIn("CAPE_BENIGN_TPM",result)
                self.assertIn("CAPE_BENIGN_TPM",self.run_virsh(
                    "snapshot-list",name,"--name"))
                for number in (1,2):
                    self.run_virsh("snapshot-revert",name,
                                   "CAPE_BENIGN_TPM","--running",timeout=180)
                    self.assertEqual(self.run_virsh("domstate",name),
                                     "running")
                print(json.dumps({
                    "result":"BENIGN_LIBVIRT_TCG_2_RUNNING_SNAPSHOT_REVERTS",
                    "actual_snapshot_registered_with_libvirt":True,
                    "two_real_virsh_snapshot_reverts":True,
                    "ovmf_writable_vars_qcow2":True,
                    "swtpm_emulated_tpm_present":True,
                    "VM_network_interfaces":0,
                    "guest_TPM_key_witness_proven":False,
                    "CAPE_real_windows_running_snapshot_proven":False,
                },sort_keys=True))
            finally:
                if domain_created:
                    subprocess.run(["virsh","-c","qemu:///system","destroy",name],
                                   capture_output=True,timeout=25,check=False)
                    subprocess.run(["virsh","-c","qemu:///system","undefine",name,
                                    "--nvram","--snapshots-metadata"],
                                   capture_output=True,timeout=25,check=False)


if __name__=="__main__":
    unittest.main()
