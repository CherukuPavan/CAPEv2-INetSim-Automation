"""Offline identity tests: no real host/libvirt/VM side effects."""
import copy
import uuid
import unittest
from unittest.mock import patch
import command2_portable_fresh_count_plan as base
import command2_portable_identity_allocator as alloc

PROFILE = dict(
    disk_dir="/var/lib/libvirt/images/cape-analysis",
    nvram_dir="/var/lib/libvirt/qemu/nvram",
    analysis_subnet="192.168.240.0/24",
    free_gib=1100,
    existing_domains=("win11",),
)


def candidate(n):
    return base.plan_fresh(n, **PROFILE)


class AllocatorTests(unittest.TestCase):
    def test_one_five_sixteen_unique_all_dimensions(self):
        for total in (1, 5, 16):
            with self.subTest(total=total):
                result = alloc.allocate(candidate(total))
                rows = result["allocations"]
                self.assertEqual(len(rows), total)
                self.assertEqual(len({x["libvirt_uuid_candidate"] for x in rows}), total)
                self.assertEqual(len({x["windows_generation_uuid_candidate"] for x in rows}), total)
                self.assertEqual(len({x["mac_candidate"] for x in rows}), total)
                self.assertEqual(len({x["static_ipv4_to_apply"] for x in rows}), total)
                self.assertEqual(len({x["nvram_destination"] for x in rows}), total)
                self.assertEqual(len({x["disk_destination"] for x in rows}), total)
                self.assertEqual(len({x["libvirt_uuid_candidate"] for x in rows} |
                                     {x["windows_generation_uuid_candidate"] for x in rows}), 2*total)
                for i, row in enumerate(rows, 1):
                    self.assertEqual(row["libvirt_name"], f"win11_{i}")
                    self.assertEqual(row["windows_hostname_to_apply"], f"WIN11-{i}")
                    self.assertEqual(row["static_ipv4_to_apply"], f"192.168.240.{100+i}")
                    self.assertEqual(row["tpm_directory_name_should_match_libvirt_uuid"],
                                     row["libvirt_uuid_candidate"])
                    self.assertEqual(uuid.UUID(row["libvirt_uuid_candidate"]).version, 4)
                    self.assertEqual(uuid.UUID(row["windows_generation_uuid_candidate"]).version, 4)
                    self.assertTrue(alloc.mac_ok(row["mac_candidate"]))
                    self.assertTrue(row["windows_ip_not_applied"])
                    self.assertFalse(row["nic_attached"])
                self.assertFalse(result["vm_definitions_written"])
                self.assertFalse(result["deployment_authorized"])
                self.assertFalse(result["allocations_persisted"])

    def test_collision_against_existing_libvirt_id_and_different_vendor_mac(self):
        old_id = uuid.uuid4()
        old_mac = "52:54:00:00:00:01"
        def draws():
            yield old_id
            yield uuid.UUID("c1c23a26-f542-46fe-aec5-bc051a2b3d4e")
            yield uuid.UUID("f142b260-3ee7-4cfd-947e-f34e9626a382")
        supply = iter(draws())
        macvals = iter((bytes([0,0,1]), bytes([0,0,2])))
        result = alloc.allocate(candidate(1), existing_uuids=(str(old_id),),
                                existing_macs=("00:16:3e:ab:cd:ef",old_mac),
                                uuid_generator=lambda:next(supply),
                                mac_random=lambda n:next(macvals))
        rec = result["allocations"][0]
        self.assertNotEqual(rec["libvirt_uuid_candidate"], str(old_id))
        self.assertEqual(rec["mac_candidate"], "52:54:00:00:00:02")

    def test_storage_block_and_malformed_plan_refused(self):
        p = candidate(1)
        p["capacity_estimate_pass"] = False
        with self.assertRaisesRegex(alloc.IdentityBlocked, "storage"):
            alloc.allocate(p)
        for fault in ("deployment_authorized", "no_vm_created"):
            p = candidate(1)
            p[fault] = True if fault == "deployment_authorized" else False
            with self.assertRaisesRegex(alloc.IdentityBlocked, "authorization"):
                alloc.allocate(p)

    def test_changed_ip_hostname_order_refused(self):
        for key, val in (("hostname", "WIN11-999"),
                         ("planned_ipv4", "192.168.240.200"),
                         ("libvirt_name", "win11"),
                         ("guest_ip_not_yet_assigned", False)):
            with self.subTest(key=key):
                p=candidate(2)
                p["planned_vms"][0][key]=val
                with self.assertRaises(alloc.IdentityBlocked):
                    alloc.allocate(p)

    def test_duplicate_existing_inventory_refused(self):
        existing=str(uuid.uuid4())
        with self.assertRaisesRegex(alloc.IdentityBlocked, "Duplicate UUID"):
            alloc.allocate(candidate(1), existing_uuids=(existing, existing))
        with self.assertRaisesRegex(alloc.IdentityBlocked, "Duplicate MAC"):
            alloc.allocate(candidate(1), existing_macs=("52:54:00:aa:bb:cc",)*2)
        with self.assertRaisesRegex(alloc.IdentityBlocked, "normalized"):
            alloc.allocate(candidate(1), existing_macs=("AA:BB:CC:DD:EE:FF",))
        with self.assertRaisesRegex(alloc.IdentityBlocked, "normalized"):
            alloc.allocate(candidate(1), existing_macs=("01:00:5e:01:01:01",))

    def test_exhausted_mac_generator_refuses_no_silent_reuse(self):
        with self.assertRaisesRegex(alloc.IdentityBlocked, "MAC uniqueness"):
            alloc.fresh_mac({"52:54:00:00:00:01"},
                            random_bytes=lambda n: bytes([0,0,1]))

    def test_wrong_uuid_generator_and_mac_generator_refused(self):
        with self.assertRaisesRegex(alloc.IdentityBlocked, "invalid non-v4"):
            alloc.allocate(candidate(1), uuid_generator=lambda:uuid.uuid1())
        with self.assertRaisesRegex(alloc.IdentityBlocked, "Invalid MAC generator"):
            alloc.allocate(candidate(1), mac_random=lambda n:b"short")

    def test_read_only_source_guards(self):
        from pathlib import Path
        source=Path(alloc.__file__).read_text(encoding="utf-8")
        for needle in ("virsh", "os.system", "subprocess.run", "shutil.copy",
                       "mkdir(", "write_bytes(", "os.open(", "ip link set"):
            # Module docstring mentions 'libvirt' but must never launch host CLI.
            self.assertNotIn(needle, source)

if __name__ == "__main__":
    unittest.main()
