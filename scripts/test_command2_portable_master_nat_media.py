"""Synthetic host offline master NAT per-VM optical media tests only."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import stat
import tempfile
import unittest

import command2_portable_master_nat_media as m
def attach_result(n):
    rows=[];hosts=[]
    for i in range(1,n+1):
        mac=f"02:ca:22:00:00:{i:02x}"
        ip=f"192.168.122.{200+i}"
        rows.append({"vm":f"win11_{i}","ip":ip,"reserved_mac":mac,
            "saved_nic_state":"SINGLE_MASTER_EQUIVALENT_NAT",
            "uuid":f"00000000-0000-4000-8000-{i:012d}",
            "guest_not_started":True})
        hosts.append({"mac":mac,"ip":ip,"name":f"WIN11-{i}"})
    return {"result":"COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED",
         "count":n,"network":"default","bridge":"virbr0",
         "guest_reservations":rows,"dhcp_hosts":hosts,
         "guest_saved_nics_attached":True,
         "host_nat_dhcp_config_applied":True,
         "CAPE_READY":False,"guest_booted_or_configured":False}
BYTES=(b"#Requires -Version 5.1\n"
       b"COMMAND2_MASTER_NAT_WINDOWS_V1\n"
       b"malware_public_internet_authorized\n")
def shared(n,path):
    return (
      patch.object(m,"safe_dir",return_value=Path(path)),
      patch.object(m.nat,"build",return_value=attach_result(n)),
      patch.object(m,"script_source",return_value=BYTES),
      patch.object(m.os,"statvfs",
         return_value=SimpleNamespace(f_bavail=60*1024**3,f_frsize=1))
    )
class ISOs(unittest.TestCase):
    def test_plan_all_n_uses_verified_mac_uuid_and_sha_no_output(self):
        for n in (1,6,16):
            with tempfile.TemporaryDirectory() as td:
                mocks=shared(n,td)
                with mocks[0],mocks[1],mocks[2],mocks[3]:
                    r=m.plan("lab02",Path("/root/j/command2-identity-reservation.json"),td)
                self.assertEqual(r["count"],n)
                self.assertEqual(len(r["entries"]),n)
                self.assertTrue(all(x["guest_json_sha256"] and
                       len(x["guest_json_sha256"])==64 for x in r["entries"]))
                self.assertFalse(r["guest_media_created"])
                self.assertFalse(r["CAPE_READY"])
                self.assertFalse(r["malware_analysis_authorized"])
                self.assertFalse(list(Path(td).glob("*.iso")))
    def test_immutable_build_outputs_distinct_single_guest_images(self):
        with tempfile.TemporaryDirectory() as td:
            def fakeiso(argv,**kw):
                p=Path(argv[argv.index("-o")+1])
                p.write_bytes(b"mock-media"+b"x"*2048)
                return SimpleNamespace(returncode=0)
            patches=shared(2,td)
            real_fstat=m.os.fstat
            def scoped_fstat(fd):
                st=real_fstat(fd)
                if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600:
                    # Only the script-created private lock needs its
                    # simulated root owner. All directory descriptors
                    # retain real st_dev/st_ino for tempfile safe cleanup.
                    return SimpleNamespace(st_mode=st.st_mode,st_uid=0,
                       st_nlink=st.st_nlink,st_dev=st.st_dev,st_ino=st.st_ino)
                return st
            with patches[0],patches[1],patches[2],patches[3],\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                      "BUILD-2-IMMUTABLE-MASTER-NAT-WINDOWS-ISOS")),\
                 patch.object(m,"subprocess") as process,\
                 patch.object(m.os,"fstat",side_effect=scoped_fstat):
                process.run.side_effect=fakeiso
                got=m.build("lab02",Path("/root/j/command2-identity-reservation.json"),td)
            self.assertTrue(got["guest_media_created"])
            self.assertEqual(len(got["created_paths"]),2)
            self.assertEqual(len(got["per_vm_iso_sha256"]),2)
            self.assertTrue(all(Path(x).is_file() for x in got["created_paths"]))
            self.assertFalse(got["guest_windows_executed"])
            self.assertFalse(got["CAPE_READY"])
    def test_existing_output_is_hard_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/"win11_1.master-nat.iso").write_bytes(b"old")
            p=shared(1,td)
            with p[0],p[1],p[2],p[3],\
                 self.assertRaisesRegex(m.NatMediaBlocked,"already exists"):
                m.plan("lab02",Path("/root/j/command2-identity-reservation.json"),td)
    def test_unverified_host_snapshot_or_nic_does_not_emit(self):
        with tempfile.TemporaryDirectory() as td:
            bad=attach_result(1)
            bad["guest_saved_nics_attached"]=False
            p=shared(1,td)
            with p[0],patch.object(m.nat,"build",return_value=bad),p[2],p[3],\
                 self.assertRaises(m.windows.NatGuestBlocked):
                m.plan("lab02",Path("/root/j/command2-identity-reservation.json"),td)
    def test_no_vm_guest_machine_or_snapshots_modified(self):
        s=Path(m.__file__).read_text()
        for op in ('"snapshot-create"','"snapshot-revert"','"net-update"',
            '"attach-interface"','"detach-interface"','"shutdown"',
            '"start"','"destroy"','shell=True'):
            self.assertNotIn(op,s)
if __name__=="__main__":unittest.main()
