"""Offline candidate identity tests; never contact libvirt or create VM files."""
from copy import deepcopy
import unittest
import uuid
from unittest.mock import patch

import command2_guest_identity_blueprint as b
import command2_portable_fresh_count_plan as fresh


def verified(count=5):
    planned = fresh.plan_fresh(
        count,
        disk_dir="/var/lib/libvirt/images/analysis",
        nvram_dir="/var/lib/libvirt/qemu/nvram",
        analysis_subnet="192.168.240.0/24",
        free_gib=2048,
        existing_domains=("win11",),
    )
    return {
        "result": "COMMAND2_READ_ONLY_TARGET_HOST_PREFLIGHT",
        "preflight_pass": True,
        "ssl55_new_vm_prohibited": False,
        "host_modified": False,
        "deploy_authorized": False,
        "requested_vm_count": count,
        "analysis_subnet": "192.168.240.0/24",
        "planned_vms": planned["planned_vms"],
    }


class IdentityBlueprintTests(unittest.TestCase):
    def test_five_candidates_are_unique_but_unreserved(self):
        answer = b.blueprint(verified())
        self.assertEqual(answer["requested_total"], 5)
        self.assertFalse(answer["identities_reserved"])
        self.assertFalse(answer["deploy_authorized"])
        self.assertFalse(answer["created_any_vm"])
        entries = answer["candidates"]
        self.assertEqual([e["libvirt_name"] for e in entries],
                         [f"win11_{i}" for i in range(1, 6)])
        self.assertEqual([e["windows_hostname_target"] for e in entries],
                         [f"WIN11-{i}" for i in range(1, 6)])
        self.assertEqual([e["guest_static_ipv4_target"] for e in entries],
                         [f"192.168.240.{i}" for i in range(101, 106)])
        self.assertEqual(len({e["libvirt_uuid_candidate"] for e in entries}), 5)
        self.assertEqual(len({e["smbios_generation_id_candidate"] for e in entries}), 5)
        self.assertEqual(len({e["mac_candidate"] for e in entries}), 5)
        for item in entries:
            self.assertFalse(item["nic_attached"])
            self.assertFalse(item["windows_identity_change_applied"])
            self.assertFalse(item["static_ipv4_applied"])
            self.assertTrue(item["mac_candidate"].startswith("02:"))

    def test_known_uuid_and_mac_collision_retry(self):
        seen_id = str(uuid.UUID(int=1))
        factory_values = iter([uuid.UUID(int=i) for i in (1, 2, 3)])
        mac_values = iter([b"\x01\x02\x03\x04\x05",
                           b"\x11\x12\x13\x14\x15"])
        out = b.blueprint(
            verified(1),
            existing_uuids=[seen_id],
            existing_macs=["02:01:02:03:04:05"],
            uuid_factory=lambda: next(factory_values),
            entropy=lambda n: next(mac_values),
        )
        only = out["candidates"][0]
        self.assertEqual(only["libvirt_uuid_candidate"], str(uuid.UUID(int=2)))
        self.assertEqual(only["smbios_generation_id_candidate"], str(uuid.UUID(int=3)))
        self.assertEqual(only["mac_candidate"], "02:11:12:13:14:15")

    def test_mac_is_locally_administered_unicast(self):
        value = b.allocate_unique_mac(set(), lambda n: b"\xff"*n)
        first = int(value.split(":")[0], 16)
        self.assertEqual(first & 1, 0)
        self.assertEqual(first & 2, 2)

    def test_ssl55_never_generates_blueprint(self):
        with self.assertRaisesRegex(b.BlueprintBlocked, "SSL-55"):
            b.blueprint(dict(verified(1), ssl55_new_vm_prohibited=True))

    def test_failed_preflight_never_generates_candidate(self):
        with self.assertRaisesRegex(b.BlueprintBlocked, "Host discovery"):
            b.blueprint(dict(verified(1), preflight_pass=False))

    def test_corrupted_preflight_always_fails(self):
        for version in (
            {"result": "SYNTHETIC"},
            {"host_modified": True},
            {"deploy_authorized": True},
            {"planned_vms": []},
            {"requested_vm_count": 17},
        ):
            with self.subTest(version=version), self.assertRaises(b.BlueprintBlocked):
                b.blueprint(dict(verified(), **version))

    def test_unexpected_duplicate_windows_identity_is_blocked(self):
        v = deepcopy(verified(2))
        v["planned_vms"][1]["hostname"] = "WIN11-1"
        with self.assertRaisesRegex(b.BlueprintBlocked, "naming"):
            b.blueprint(v)
        v = deepcopy(verified(2))
        v["planned_vms"][1]["disk"] = v["planned_vms"][0]["disk"]
        with self.assertRaisesRegex(b.BlueprintBlocked, "Duplicated"):
            b.blueprint(v)

    def test_wrong_ip_or_network_identity_is_refused(self):
        v = deepcopy(verified(2))
        v["planned_vms"][1]["planned_ipv4"] = "192.168.240.202"
        with self.assertRaisesRegex(b.BlueprintBlocked, "Unexpected guest IP"):
            b.blueprint(v)
        v = deepcopy(verified(2))
        v["analysis_subnet"] = "192.168.241.0/24"
        with self.assertRaisesRegex(b.BlueprintBlocked, "Unexpected guest IP"):
            b.blueprint(v)
        v = deepcopy(verified(2))
        v["analysis_subnet"] = "not-a-cidr"
        with self.assertRaisesRegex(b.BlueprintBlocked, "subnet missing"):
            b.blueprint(v)

    def test_inventory_must_be_valid_and_finite(self):
        with self.assertRaisesRegex(b.BlueprintBlocked, "Malformed MAC"):
            b.blueprint(verified(1), existing_macs=["incomplete"])
        with self.assertRaisesRegex(b.BlueprintBlocked, "Malformed libvirt UUID"):
            b.blueprint(verified(1), existing_uuids=["no-uuid"])

    def test_exhausted_uniqueness_fails_closed(self):
        used = {str(uuid.UUID(int=1))}
        with self.assertRaisesRegex(b.BlueprintBlocked, "UUID candidate generation"):
            b.allocate_unique_uuid(used, lambda: uuid.UUID(int=1))
        with self.assertRaisesRegex(b.BlueprintBlocked, "MAC candidate generation"):
            b.allocate_unique_mac({"02:00:00:00:00:00"},
                                  lambda n: b"\x00"*n)

    def test_incorrect_entropy_length_is_rejected(self):
        with self.assertRaisesRegex(b.BlueprintBlocked, "entropy provider"):
            b.allocate_unique_mac(set(), lambda n: b"short?")
        with self.assertRaisesRegex(b.BlueprintBlocked, "entropy provider"):
            b.allocate_unique_mac(set(), lambda n: None)

    def test_sixteen_candidates_model_only(self):
        values = b.blueprint(verified(16))["candidates"]
        self.assertEqual(len(values), 16)
        self.assertEqual(values[-1]["windows_hostname_target"], "WIN11-16")

    def test_no_vm_management_modules_are_imported(self):
        import inspect
        src = inspect.getsource(b)
        for forbidden in ("subprocess", "virsh", "qemu-img", "libvirt.",
                          "rclone", "systemctl", "os.system"):
            self.assertNotIn(forbidden, src)
        self.assertIn('"created_any_vm": False', src)


if __name__ == "__main__":
    unittest.main()
