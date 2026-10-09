#!/usr/bin/env python3
"""Synthetic, offline tests for clone plan; no libvirt/network calls."""
import copy
import ipaddress
import unittest

import plan_vm_clones as c


def fixture():
    path = "/lab/masters/win11"
    return {
        "schema": "cape-master-offline-inventory-v1",
        "vm": {"name": "win11",
               "uuid": "289d89be-68ec-4c62-90e1-ea930849266f",
               "state": "shut off", "memory_kib": 4194304,
               "qemu_guest_agent_channel": False,
               "disks": [{"device": "disk", "file": path + ".cold"}]},
        "host": {"MemAvailable": 54000000},
        "snapshots": {
            "current": "cold",
            "items": [{"name": "cold", "state": "shutoff",
                      "memory": {"mode": "no"},
                      "disks": [{"snapshot": "external", "source": path + ".cold"}]},
                      {"name": "running", "state": "running", "memory": {"mode": "external"}}],
        },
        "storage": [{
            "path": path + ".cold",
            "filesystem_available_bytes": 600 * 1024**3,
            "backing_chain": [
                {"filename": path + ".cold", "backing_filename": path + ".overlay",
                 "format": "qcow2", "virtual_size": 64 * 1024**3},
                {"filename": path + ".overlay", "backing_filename": path + ".base",
                 "format": "qcow2", "virtual_size": 64 * 1024**3},
                {"filename": path + ".base", "backing_filename": None,
                 "format": "qcow2", "virtual_size": 64 * 1024**3}],
        }],
        "cape": {"allowlisted_machine_fields": {
            "kvm": {"machines": "cuckoo1"},
            "cuckoo1": {"label": "cuckoo1", "ip": "192.0.2.105"}}},
        "networks": [{"name": "default", "forward_mode": "nat"},
                     {"name": "analysis", "forward_mode": None}],
    }


class Tests(unittest.TestCase):
    def test_realistic_cold_snapshot_and_chain(self):
        f = fixture()
        source, errors = c.select_source(f, "cold")
        self.assertFalse(errors)
        disk, errors = c.image_details(f, source)
        self.assertFalse(errors)
        self.assertEqual(disk["layer_count"], 3)

    def test_four_layer_real_master_layout(self):
        f=fixture()
        layers=f["storage"][0]["backing_chain"]
        old_top=layers[0]
        old_top["filename"]="/lab/masters/win11.Afterfull"
        old_top["backing_filename"]="/lab/masters/win11.basicinstallwinsnapshot"
        layers[1]["filename"]="/lab/masters/win11.basicinstallwinsnapshot"
        layers[1]["backing_filename"]="/lab/masters/win11.qcow2"
        layers[2]["filename"]="/lab/masters/win11.qcow2"
        layers.insert(0,{"filename":"/lab/masters/win11.finalshutoffversion",
                         "backing_filename":"/lab/masters/win11.Afterfull",
                         "format":"qcow2","virtual_size":64*1024**3})
        f["vm"]["disks"][0]["file"]="/lab/masters/win11.finalshutoffversion"
        f["storage"][0]["path"]="/lab/masters/win11.finalshutoffversion"
        f["snapshots"]["items"][0]["disks"][0]["source"]="/lab/masters/win11.finalshutoffversion"
        selected, errors=c.select_source(f,"cold")
        self.assertFalse(errors)
        info, errors=c.image_details(f,selected)
        self.assertFalse(errors)
        self.assertEqual(info["layer_count"],4)

    def test_running_snapshot_refused(self):
        _, issues = c.select_source(fixture(), "running")
        self.assertTrue(any("not marked as shut off" in x for x in issues))

    def test_unknown_source(self):
        _, issues = c.select_source(fixture(), "nonexistent")
        self.assertTrue(issues)

    def test_invalid_chain_link_blocked(self):
        f = fixture()
        f["storage"][0]["backing_chain"][0]["backing_filename"] = "/other"
        _, errors = c.image_details(f, f["snapshots"]["items"][0])
        self.assertTrue(any("link" in x for x in errors))

    def test_offline_names_mac_uuids_unique_and_stable(self):
        f = fixture()
        a, issues = c.make_candidates(
            f["vm"], 5, "win11_", "192.0.2.0/24", "192.0.2.110",
            "192.0.2.109", ["192.0.2.105"])
        b, _ = c.make_candidates(
            f["vm"], 5, "win11_", "192.0.2.0/24", "192.0.2.110",
            "192.0.2.109", ["192.0.2.105"])
        self.assertFalse(issues)
        self.assertEqual(a, b)
        self.assertEqual([x["name"] for x in a],
                         [f"win11_{i}" for i in range(1, 6)])
        self.assertEqual(len({x["uuid_proposed"] for x in a}), 5)
        self.assertEqual(len({x["mac_proposed"] for x in a}), 5)
        self.assertEqual(a[4]["guest_ipv4_proposed"], "192.0.2.114")
        self.assertTrue(all(not x["boot_allowed"] for x in a))

    def test_cape_ip_collision_blocked(self):
        with self.assertRaisesRegex(c.InvalidInventory, "collides"):
            c.generate_plan(fixture(), 2, network_name="analysis",
                            source_snapshot="cold", subnet="192.0.2.0/24",
                            first_ip="192.0.2.105")

    def test_nonusable_network_address_refused(self):
        with self.assertRaisesRegex(c.InvalidInventory, "usable"):
            c.make_candidates(fixture()["vm"], 1, "win11_",
                              "192.0.2.0/24", "192.0.2.0", None, [])

    def test_cape_stale_registration_is_blocker(self):
        plan = c.generate_plan(fixture(), 2, source_snapshot="cold",
                               network_name="analysis", subnet="192.0.2.0/24",
                               first_ip="192.0.2.110")
        self.assertEqual(plan["status"], "BLOCKED_NOT_DEPLOYABLE")
        self.assertTrue(any("CAPE master" in x for x in plan["blockers"]))
        self.assertFalse(plan["clone_candidates"][0]["boot_allowed"])

    def test_nat_is_blocked(self):
        plan = c.generate_plan(fixture(), 1, source_snapshot="cold",
                               network_name="default", subnet="192.0.2.0/24",
                               first_ip="192.0.2.110")
        self.assertTrue(any("forwarding/NAT" in x for x in plan["blockers"]))

    def test_no_network_blocks_and_does_not_invent_ips(self):
        plan = c.generate_plan(fixture(), 3, source_snapshot="cold")
        self.assertTrue(all(x["guest_ipv4_proposed"] is None
                            for x in plan["clone_candidates"]))
        self.assertTrue(plan["blockers"])

    def test_rejects_large_clone_count(self):
        with self.assertRaisesRegex(c.InvalidInventory, "Count"):
            c.generate_plan(fixture(), 50, source_snapshot="cold")

    def test_capacity_guard(self):
        f = fixture()
        f["storage"][0]["filesystem_available_bytes"] = 150 * 1024**3
        plan = c.generate_plan(f, 3, source_snapshot="cold")
        self.assertTrue(any("free space" in x for x in plan["blockers"]))

    def test_memory_guard(self):
        f = fixture()
        f["host"]["MemAvailable"] = 5 * 1024 * 1024
        plan = c.generate_plan(f, 3, source_snapshot="cold")
        self.assertTrue(any("RAM" in x for x in plan["blockers"]))

    def test_invalid_inventory_schema(self):
        with self.assertRaisesRegex(c.InvalidInventory, "schema"):
            c.read_inventory  # parser tested separately by code path
            c.generate_plan({"vm": {"name": "win11", "uuid": "broken"}},
                            1, source_snapshot="cold")


if __name__ == "__main__":
    unittest.main()
