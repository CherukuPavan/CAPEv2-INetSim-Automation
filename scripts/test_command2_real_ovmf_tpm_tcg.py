"""Real disposable QEMU/OVMF-QCOW2/swtpm native snapshot compatibility gate.

Exercises firmware-backed memory, OS disk, OVMF writable VARS and swtpm on
an isolated, blank, TCG-emulated VM in GitHub Actions. No real Windows,
libvirt CAPE guest, malware or network interface involved. No true guest TPM
key witness is claimed. Run only on a scratch Ubuntu 26.04 runner.
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest
import time

from test_command2_real_swtpm_snapshot_tcg import QMP, wait_for


class RealOVMFQcow2Snapshot(unittest.TestCase):
    def command(self,*args):
        r=subprocess.run(args,text=True,capture_output=True,timeout=45,
                         check=False)
        self.assertEqual(r.returncode,0,r.stderr[:2500])
        return r.stdout

    def firmware(self):
        root=Path("/usr/share/OVMF")
        self.assertTrue(root.is_dir())
        code=root/"OVMF_CODE_4M.fd"
        vars=root/"OVMF_VARS_4M.fd"
        self.assertTrue(code.is_file(),str(code))
        self.assertTrue(vars.is_file(),str(vars))
        return code,vars

    def test_real_ovmf_qcow2_swtpm_two_ram_reverts(self):
        for binary in ("qemu-system-x86_64","qemu-img","swtpm"):
            self.assertTrue(shutil.which(binary),binary)
        code,original_vars=self.firmware()
        with tempfile.TemporaryDirectory(prefix="cape-ovmf-qcow2-tpm-") as td:
            root=Path(td)
            disk=root/"blank.qcow2"
            nvram=root/"writable_vars.qcow2"
            self.command("qemu-img","create","-f","qcow2",str(disk),"128M")
            self.command("qemu-img","convert","-f","raw","-O","qcow2",
                         str(original_vars),str(nvram))
            tpm_dir=root/"state"
            tpm_dir.mkdir(mode=0o700)
            tpm_socket=root/"swtpm.socket"
            qmp_socket=root/"qmp.socket"
            swlog=(root/"swtpm.log").open("wb")
            qlog=(root/"qemu.log").open("wb")
            processes=[]
            qmp=None
            try:
                swtpm=subprocess.Popen([
                    "swtpm","socket","--tpm2",
                    "--tpmstate","dir="+str(tpm_dir),
                    "--ctrl","type=unixio,path="+str(tpm_socket),
                    ],stdout=swlog,stderr=subprocess.STDOUT)
                processes.append(swtpm)
                wait_for(tpm_socket,swtpm)
                qemu=subprocess.Popen([
                    "qemu-system-x86_64",
                    "-machine","q35,accel=tcg,smm=on",
                    "-cpu","qemu64", "-m","256", "-smp","1",
                    "-nic","none","-display","none",
                    "-drive","if=pflash,unit=0,format=raw,readonly=on,file="+str(code),
                    "-drive","if=pflash,unit=1,format=qcow2,file="+str(nvram),
                    "-drive","if=ide,format=qcow2,file="+str(disk),
                    "-chardev","socket,id=chrtpm,path="+str(tpm_socket),
                    "-tpmdev","emulator,id=tpm0,chardev=chrtpm",
                    "-device","tpm-tis,tpmdev=tpm0",
                    "-qmp","unix:"+str(qmp_socket)+",server=on,wait=off",
                    "-monitor","none",
                ],stdout=qlog,stderr=subprocess.STDOUT)
                processes.append(qemu)
                wait_for(qmp_socket,qemu,seconds=40)
                qmp=QMP(qmp_socket)
                # This test validates QEMU's synchronous snapshot path,
                # NOT guest TPM key/PCR continuity after resume.
                qmp.hmp("savevm BENIGN_OVMF_TPM")
                evidence=qmp.hmp("info snapshots")
                self.assertIn("BENIGN_OVMF_TPM",evidence)
                for cycle in (1,2):
                    qmp.hmp("loadvm BENIGN_OVMF_TPM")
                    self.assertIn("BENIGN_OVMF_TPM",qmp.hmp("info snapshots"))
                self.assertIsNone(qemu.poll())
            finally:
                if qmp is not None:
                    qmp.close()
                for p in reversed(processes):
                    if p.poll() is None:
                        p.terminate()
                    try:
                        p.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
                swlog.close()
                qlog.close()
            for p in (disk,nvram):
                meta=json.loads(self.command("qemu-img","info",
                    "--output=json",str(p)))
                self.assertEqual(meta["format"],"qcow2")
                tags=[row.get("name") for row in meta.get("snapshots",[])]
                self.assertIn("BENIGN_OVMF_TPM",tags,str(p))
            print(json.dumps({
                "result":"REAL_QEMU_TCG_OS_DISK_OVMF_QCOW2_TPM_TWO_LOADS",
                "native_os_disk_snapshot":True,
                "native_UEFI_VARS_qcow2_snapshot":True,
                "two_live_snapshot_loadvm_calls":True,
                "swtpm_socket_participated":True,
                "network_interfaces":0,
                "windows_credential_and_TPM_NV_PCR_continuity_proven":False,
                "libvirt_CAPE_running_snapshot_revert_proven":False,
                "host_KVM_proven":False,
            },sort_keys=True))


if __name__=="__main__":
    unittest.main()
