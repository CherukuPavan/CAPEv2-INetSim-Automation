"""Offline unit tests for Command 2 target-host preflight (no host operations)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_target_host_preflight as p

DISK_DIR = "/var/lib/libvirt/images/cape-analysis"
NVRAM_DIR = "/var/lib/libvirt/qemu/nvram"
NET = "192.168.240.0/24"


def profile(**changes):
    snapshot = {
        "reference_ssl55": False,
        "os": {"id": "ubuntu", "version": "22.04"},
        "architecture": "x86_64",
        "logical_cpus": 16,
        "vmx_svm_cpu_flag": True,
        "outbound_interface": "eno1",
        "kvm_character_device": True,
        "kvm_access_current_user": True,
        "tools_found": {"virsh": True, "qemu-img": True, "ip": True},
        "available_ram_mib": 65536,
        "disk_free_gib": 750.0,
        "nvram_dir_exists": True,
        "source_master_shutoff": True,
        "existing_domain_names": ["win11"],
        "existing_target_artifact_paths": [],
        "kernel_ipv4_routes": ["10.23.104.0/22", "172.18.0.0/16"],
        "kernel_ipv4_addresses": ["10.23.105.55/22"],
        "libvirt_ipv4_networks": ["192.168.122.0/24"],
        "template": {"visible": True, "qcow2_flat": True},
    }
    snapshot.update(changes)
    return snapshot


def evaluate(count=5, **changes):
    return p.evaluate(profile(**changes), count, DISK_DIR, NVRAM_DIR, NET)


class PurePreflight(unittest.TestCase):
    def test_good_target_host_is_still_not_authorized(self):
        result = evaluate()
        self.assertTrue(result["preflight_pass"])
        self.assertFalse(result["deploy_authorized"])
        self.assertFalse(result["host_modified"])
        self.assertFalse(result["ipv6_containment_checked"])
        self.assertEqual(result["storage_required_gib"], 350)
        self.assertEqual(len(result["planned_vms"]), 5)

    def test_ssl55_reference_host_denied_even_when_ample_resources(self):
        x = evaluate(reference_ssl55=True)
        self.assertFalse(x["preflight_pass"])
        self.assertTrue(x["ssl55_new_vm_prohibited"])
        self.assertIn("SSL55_REFERENCE_ONLY_NO_NEW_VMS", x["errors"])

    def test_live_route_overlap_is_blocked(self):
        x = evaluate(kernel_ipv4_routes=["192.168.240.128/25"])
        self.assertIn("ANALYSIS_SUBNET_OVERLAPS_ROUTES", x["errors"])

    def test_address_and_libvirt_network_overlaps_blocked(self):
        x = evaluate(kernel_ipv4_addresses=["192.168.240.2/24"],
                     libvirt_ipv4_networks=["192.168.240.0/24"])
        self.assertIn("ANALYSIS_SUBNET_OVERLAPS_ADDRESSES", x["errors"])
        self.assertIn("ANALYSIS_SUBNET_OVERLAPS_LIBVIRT_NETWORKS", x["errors"])

    def test_unavailable_route_inventory_fail_closed(self):
        x = evaluate(kernel_ipv4_routes=None, kernel_ipv4_addresses=None,
                     libvirt_ipv4_networks=None)
        self.assertFalse(x["ipv4_overlap_checked"])
        self.assertFalse(x["preflight_pass"])
        self.assertIn("MISSING_ROUTES_INVENTORY", x["errors"])

    def test_insufficient_resources_not_authorized(self):
        x = evaluate(disk_free_gib=96.11, available_ram_mib=12000)
        self.assertIn("INSUFFICIENT_CONSERVATIVE_DISK_CAPACITY", x["errors"])
        self.assertIn("INSUFFICIENT_AVAILABLE_RAM_FOR_COUNT", x["errors"])
        self.assertFalse(x["deploy_authorized"])

    def test_unverified_master_template_or_kvm_denied(self):
        x = evaluate(source_master_shutoff=False,
                     template={"visible": True, "qcow2_flat": False},
                     kvm_character_device=False)
        self.assertIn("UNVERIFIED_COMMAND1_MASTER_OR_MASTER_RUNNING", x["errors"])
        self.assertIn("TEMPLATE_METADATA_NOT_VERIFIED_FLAT_64G", x["errors"])
        self.assertIn("KVM_DEVICE_MISSING", x["errors"])

    def test_version_arch_and_tools_denied(self):
        x = evaluate(os={"id": "ubuntu", "version": "20.04"},
                     architecture="aarch64",
                     tools_found={"virsh": False, "qemu-img": True, "ip": True})
        self.assertIn("HOST_NOT_X86_64", x["errors"])
        self.assertIn("UBUNTU_RELEASE_NOT_IN_CANDIDATE_MATRIX", x["errors"])
        self.assertIn("MISSING_TOOL_VIRSH", x["errors"])

    def test_existing_target_vm_collides_and_refuses(self):
        with self.assertRaisesRegex(p.count_plan.PortablePlanBlocked, "VM collision"):
            evaluate(existing_domain_names=["win11", "win11_2"])

    def test_outbound_interface_discovered_dynamically(self):
        self.assertEqual(p.parse_outbound_interface(
            [{"dev":"enp0s31f6","dst":"1.1.1.1",
              "gateway":"10.0.0.1","prefsrc":"10.0.0.55"}]), "enp0s31f6")
        self.assertEqual(p.parse_outbound_interface([{"dev":"wlp2s0"}]), "wlp2s0")
        self.assertIsNone(p.parse_outbound_interface([{"dev":"lo"}]))
        self.assertIsNone(p.parse_outbound_interface([{"dev":"../bad"}]))
        self.assertIsNone(p.parse_outbound_interface([]))
        result = evaluate(outbound_interface=None)
        self.assertFalse(result["preflight_pass"])
        self.assertIn("DEFAULT_OUTBOUND_INTERFACE_UNAVAILABLE",result["errors"])

    def test_kernel_route_and_ipv4_addr_json_normalization(self):
        routes = [{"dst":"default"}, {"dst":"10.23.104.0/22"},
                  {"dst":"192.168.240.15", "type":"local"}]
        self.assertEqual(p.parsed_routes(routes),
                         ["10.23.104.0/22","192.168.240.15/32"])
        addrs = [{"ifname":"enp0s31f6","addr_info":[
            {"family":"inet","local":"10.23.105.55","prefixlen":22}]}]
        self.assertEqual(p.parsed_addresses(addrs), ["10.23.104.0/22"])
        self.assertIsNone(p.parsed_routes([{"dst":"not-cidr"}]))
        self.assertIsNone(p.parsed_addresses([{"addr_info":[
            {"family":"inet", "local":"broken"}]}]))

    def test_inactive_libvirt_subnets_count_as_collisions(self):
        xml = ('<network><name>test</name><ip address="192.168.240.1" '
               'netmask="255.255.255.0"/></network>')
        def mocked(*args):
            if args[-3:] == ("net-list", "--all", "--name"):
                return "default\nanalysis\n"
            if args[-2:] in (("net-dumpxml","analysis"),
                             ("net-dumpxml","default")):
                return xml
            raise AssertionError("Unexpected subprocess command")
        with patch.object(p, "run_readonly", side_effect=mocked):
            self.assertEqual(p.libvirt_nets(), [NET])

    def test_template_info_metadata_only_rejects_backing(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp)/"template.qcow2"
            img.write_bytes(b"not a real VM image")
            flat = json.dumps({"format":"qcow2",
                "virtual-size":64*p.GIB})
            backed = json.dumps({"format":"qcow2",
                "virtual-size":64*p.GIB, "backing-filename":"parent.qcow2"})
            with patch.object(p, "run_readonly", return_value=flat) as run:
                self.assertTrue(p.template_metadata(str(img))["qcow2_flat"])
                self.assertEqual(run.call_args.args[:3],
                                 ("qemu-img","info","--output=json"))
            with patch.object(p, "run_readonly", return_value=backed):
                self.assertFalse(p.template_metadata(str(img))["qcow2_flat"])

    def test_host_identity_normalization_blocks_campus_reference(self):
        with patch.object(p.platform, "node", return_value="CSE-SSL-55.campus"):
            self.assertTrue(p.local_ref_host())
        with patch.object(p.platform, "node", return_value="test-new-host"):
            self.assertFalse(p.local_ref_host())

    def test_read_only_subprocess_uses_no_shell(self):
        def fake_run(args, capture_output, text, timeout, check):
            self.assertFalse(check)
            self.assertIsInstance(args, tuple)
            return type("Result",(),{"returncode":0,"stdout":"[]","stderr":""})()
        with patch.object(p.subprocess, "run", side_effect=fake_run):
            self.assertEqual(p.json_command("ip","-j","-4","route","show"), [])


if __name__ == "__main__":
    unittest.main()
