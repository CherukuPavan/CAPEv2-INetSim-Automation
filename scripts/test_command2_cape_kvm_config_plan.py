"""Mocked CAPE KVM conf mappings: one-to-one VM IP/snapshot name."""
import configparser
import unittest
import uuid

import command2_cape_kvm_config_plan as cape


def reservation(n=5):
    entries=[]
    for i in range(1,n+1):
        entries.append({
            "libvirt_name":f"win11_{i}",
            "windows_hostname_target":f"WIN11-{i}",
            "guest_static_ipv4_target":f"192.168.240.{100+i}",
            "mac_candidate":f"02:aa:bb:cc:dd:{i:02x}",
            "libvirt_uuid_candidate":str(uuid.UUID(int=i+10)),
        })
    return {"format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "state":"CANDIDATES_RECORDED_NOT_APPLIED",
            "provisioning_started":False,"libvirt_domains_created":False,
            "host_network_modified":False,"guest_count":n,
            "entries":entries}


class CapeKVMPlanTests(unittest.TestCase):
    def test_count_one_five_sixteen(self):
        for size in (1,5,16):
            with self.subTest(size=size):
                p=cape.create_cape_kvm_conf(reservation(size))
                self.assertEqual(len(p["machine_names"]),size)
                self.assertEqual(len(p["snapshot_names"]),size)
                self.assertFalse(p["live_snapshots_exist_verified"])
                self.assertFalse(p["cape_service_restarted"])
                config=configparser.ConfigParser()
                config.read_string(p["conf_text"])
                self.assertEqual(config["kvm"]["machines"],
                                 ",".join(f"win11_{i}" for i in range(1,size+1)))
                for i in range(1,size+1):
                    row=config[f"win11_{i}"]
                    self.assertEqual(row["ip"],f"192.168.240.{100+i}")
                    self.assertEqual(row["snapshot"],f"cape_ready_win11_{i}")
                    self.assertEqual(row["tags"],"win11")
                    self.assertEqual(row["platform"],"windows")
                    self.assertEqual(row["interface"],"cape-lab0")

    def test_fail_if_unreserved_identity(self):
        for key,val in (("state","APPLIED"),
                        ("provisioning_started",True),
                        ("host_network_modified",True),
                        ("guest_count",8)):
            p=reservation()
            p[key]=val
            with self.subTest(key=key),self.assertRaises(cape.CapeConfigBlocked):
                cape.create_cape_kvm_conf(p)

    def test_duplicate_vm_identity_ip_or_mac_rejected(self):
        for key in ("libvirt_uuid_candidate","mac_candidate",
                    "guest_static_ipv4_target","windows_hostname_target"):
            p=reservation(2)
            p["entries"][1][key]=p["entries"][0][key]
            with self.subTest(key=key), self.assertRaises(cape.CapeConfigBlocked):
                cape.create_cape_kvm_conf(p)

    def test_bad_non_rfc1918_subnet_refused(self):
        for cidr in ("8.8.8.0/24","169.254.0.0/24",
                     "192.168.122.0/24","192.168.240.0/16"):
            with self.subTest(cidr=cidr),self.assertRaises(cape.CapeConfigBlocked):
                cape.create_cape_kvm_conf(reservation(1),cidr)

    def test_no_cape_or_libvirt_writes(self):
        from pathlib import Path
        source=Path(cape.__file__).read_text(encoding="utf-8")
        # Check executable module contents, not the safety docstring
        # that says the module does NOT call systemctl/virsh.
        code=source[source.index("from __future__ import annotations"):]
        for word in ('"virsh"', '"systemctl"', "subprocess.run", "write_text(",
                     "os.open(", "snapshot-create", "nft -f"):
            self.assertNotIn(word,code)


if __name__=="__main__":
    unittest.main()
