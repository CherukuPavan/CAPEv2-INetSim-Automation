"""Real benign TCG/QEMU+swtpm internal RAM snapshot/revert probe (NO Windows).

Runs only inside a disposable Ubuntu 26.04 CI container. It starts QEMU TCG
with a blank QCOW2 and isolated swtpm (no NIC, no real Windows image), saves
a native QEMU RAM snapshot and demands TWO loadvm successes. This is a
limited compatibility probe: no firmware QCOW2 or guest TPM key continuity,
no libvirt/CAPE running checkpoint authorization or KVM acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


def wait_for(path, proc, seconds=25):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if path.exists():
            return
        if proc.poll() is not None:
            raise AssertionError("Child terminated before control socket ready")
        time.sleep(0.1)
    raise AssertionError("Control socket never appeared")


class QMP:
    def __init__(self,path):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(20)
        self.sock.connect(str(path))
        self.buffer=b""
        greeting=self.read()
        assert greeting.get("QMP"), greeting
        self.execute("qmp_capabilities")

    def read(self):
        end=time.monotonic()+25
        while time.monotonic()<end:
            if b"\r\n" in self.buffer:
                first,self.buffer=self.buffer.split(b"\r\n",1)
                if first:
                    return json.loads(first)
            fragment=self.sock.recv(65536)
            if not fragment:
                raise AssertionError("QMP closed unexpectedly")
            self.buffer+=fragment
            if len(self.buffer)>1_000_000:
                raise AssertionError("Oversize QMP response")
        raise AssertionError("Timed out reading QMP")

    def execute(self,cmd,argument=None):
        request={"execute":cmd}
        if argument is not None:
            request["arguments"]=argument
        self.sock.sendall(json.dumps(request).encode()+b"\r\n")
        for _ in range(20):
            reply=self.read()
            if "event" in reply:
                continue
            if "error" in reply:
                raise AssertionError("QMP command failure "+cmd+": "+
                                     str(reply["error"])[:1000])
            if "return" in reply:
                return reply["return"]
        raise AssertionError("QMP did not return command result")

    def hmp(self,script):
        result=self.execute("human-monitor-command",{"command-line":script})
        if not isinstance(result,str) or any(
                x in result.lower() for x in (
                    "error:", "not supported", "unknown command",
                    "device does not support", "cannot save")):
            raise AssertionError("QEMU monitor refused "+script+": "+str(result)[:800])
        return result

    def close(self):
        self.sock.close()


@unittest.skipUnless(
    all(shutil.which(x) for x in ("qemu-system-x86_64","qemu-img","swtpm")),
    "Real official QEMU/swtpm binaries required")
class NativeBenignTPMSnapshot(unittest.TestCase):
    def test_tcg_native_internal_snapshot_and_two_reverts_without_guest(self):
        # TCG prevents accidental dependence on host KVM or campus hardware.
        with tempfile.TemporaryDirectory(prefix="cape-blank-qemu-tpm-") as temp:
            root=Path(temp)
            image=root/"blank.qcow2"
            cp=subprocess.run(
                ["qemu-img","create","-f","qcow2",str(image),"128M"],
                text=True,capture_output=True,timeout=20,check=False)
            self.assertEqual(cp.returncode,0,cp.stderr)
            tpm=root/"swtpm"
            tpm.mkdir(mode=0o700)
            tpm_socket=root/"tpm.socket"
            qmp_socket=root/"qmp.socket"
            tpm_output=(root/"swtpm.log").open("wb")
            qemu_output=(root/"qemu.log").open("wb")
            processes=[]
            control=None
            try:
                swtpm=subprocess.Popen([
                    "swtpm","socket","--tpm2",
                    "--tpmstate","dir="+str(tpm),
                    "--ctrl","type=unixio,path="+str(tpm_socket),
                    ],stdout=tpm_output,stderr=subprocess.STDOUT)
                processes.append(swtpm)
                wait_for(tpm_socket,swtpm)
                qemu=subprocess.Popen([
                    "qemu-system-x86_64",
                    "-machine","pc,accel=tcg", "-cpu","qemu64",
                    "-m","128", "-smp","1",
                    "-nic","none","-display","none",
                    "-drive","file="+str(image)+",if=ide,format=qcow2",
                    "-chardev","socket,id=chrtpm,path="+str(tpm_socket),
                    "-tpmdev","emulator,id=tpm0,chardev=chrtpm",
                    "-device","tpm-tis,tpmdev=tpm0",
                    "-qmp","unix:"+str(qmp_socket)+",server=on,wait=off",
                    "-monitor","none",
                ],stdout=qemu_output,stderr=subprocess.STDOUT)
                processes.append(qemu)
                wait_for(qmp_socket,qemu)
                control=QMP(qmp_socket)
                status=control.execute("query-status")
                self.assertIn(status.get("status"),
                              ("running","prelaunch","inmigrate","paused"))
                first=control.hmp("savevm CAPE_BENIGN_QEMU_TPM")
                present=control.hmp("info snapshots")
                self.assertIn("CAPE_BENIGN_QEMU_TPM",present)
                for step in range(2):
                    control.hmp("loadvm CAPE_BENIGN_QEMU_TPM")
                    snapshot=control.hmp("info snapshots")
                    self.assertIn("CAPE_BENIGN_QEMU_TPM",snapshot)
                self.assertIsNone(qemu.poll())
                print(json.dumps({
                    "result":"QEMU_BENIGN_TCG_TPM_2_REVERTS_ONLY",
                    "native_ram_snapshot_exists":True,
                    "two_QEMU_loadvm_completed":True,
                    "untrusted_guest_started":False,
                    "guest_network_card_attached":False,
                    "Windows_TPM_credential_continuity_verified":False,
                    "OVMF_qcow2_snapshot_verified":False,
                    "libvirt_CAPE_running_snapshot_verified":False,
                },sort_keys=True))
            finally:
                if control is not None:
                    control.close()
                for p in reversed(processes):
                    if p.poll() is None:
                        p.terminate()
                    try:
                        p.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
                tpm_output.close()
                qemu_output.close()


if __name__=="__main__":
    unittest.main()
