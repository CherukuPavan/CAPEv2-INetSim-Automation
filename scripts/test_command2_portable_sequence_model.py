"""Pure Command 2 stage model tests; never contact a host or hypervisor."""
from copy import deepcopy
import unittest

import command2_guest_identity_blueprint as identity
import command2_portable_fresh_count_plan as count
import command2_portable_sequence_model as flow


def fixture(total=2):
    planned = count.plan_fresh(
        total, disk_dir="/var/lib/libvirt/images/cape-analysis",
        nvram_dir="/var/lib/libvirt/qemu/nvram",
        analysis_subnet="192.168.240.0/24", free_gib=2048,
        existing_domains=("win11",))
    preflight = {
        "result": "COMMAND2_READ_ONLY_TARGET_HOST_PREFLIGHT",
        "preflight_pass": True, "ssl55_new_vm_prohibited": False,
        "host_modified": False, "deploy_authorized": False,
        "planned_vms": planned["planned_vms"],
        "requested_vm_count": total, "analysis_subnet": "192.168.240.0/24",
    }
    return identity.blueprint(preflight)


def gate(stage):
    return dict.fromkeys(flow.REQUIREMENTS[stage], True)


class SequenceModelTests(unittest.TestCase):
    def test_start_two_guests_does_not_touch_host(self):
        v = flow.create_model(fixture())
        self.assertEqual(v["guest_count"], 2)
        self.assertEqual(v["guests"]["win11_1"]["stage"], "PLANNED")
        self.assertEqual(v["guests"]["win11_2"]["stage"], "PLANNED")
        self.assertFalse(v["network_attached"])
        self.assertFalse(v["deploy_authorized"])
        self.assertFalse(v["guest_ready_in_reality"])

    def test_cannot_attach_network_before_ipv4_ipv6_guards(self):
        v = flow.create_model(fixture(1))
        with self.assertRaisesRegex(flow.SequenceBlocked, "Stage order"):
            flow.advance(v, "win11_1",
                         "NIC_ATTACHED_TO_ISOLATED_NETWORK",
                         gate("NIC_ATTACHED_TO_ISOLATED_NETWORK"))
        self.assertEqual(v["guests"]["win11_1"]["stage"], "PLANNED")

    def test_reject_insufficient_guards_without_changing_source_model(self):
        v = flow.create_model(fixture(1))
        with self.assertRaisesRegex(flow.SequenceBlocked, "proof missing"):
            flow.advance(v, "win11_1", "IDENTITY_RESERVED",
                         {"exact_host_inventory_rechecked": True})
        self.assertEqual(v["guests"]["win11_1"]["stage"], "PLANNED")
        with self.assertRaisesRegex(flow.SequenceBlocked, "proof missing"):
            flow.advance(v, "win11_1", "IDENTITY_RESERVED",
                         {"exact_host_inventory_rechecked": 1,
                          "collision_free_reservation_durable": True})

    def test_order_until_guard_cannot_skip_egress(self):
        v = flow.create_model(fixture(1))
        for stage in flow.STATES[1:7]:
            v = flow.advance(v, "win11_1", stage, gate(stage))
        self.assertEqual(v["guests"]["win11_1"]["stage"],
                         "WINDOWS_HOSTNAME_VERIFIED")
        with self.assertRaisesRegex(flow.SequenceBlocked, "proof missing"):
            flow.advance(v, "win11_1", "NETWORK_CONTAINMENT_PROVEN",
                         {k: True for k in flow.REQUIREMENTS[
                             "NETWORK_CONTAINMENT_PROVEN"]
                          if k != "ipv6_negative_egress_verified"})
        with self.assertRaisesRegex(flow.SequenceBlocked, "Stage order"):
            flow.advance(v, "win11_1", "NIC_ATTACHED_TO_ISOLATED_NETWORK",
                         gate("NIC_ATTACHED_TO_ISOLATED_NETWORK"))
        self.assertFalse(v["network_attached"])

    def test_all_stages_are_simulation_not_live_certificate(self):
        v = flow.create_model(fixture(1))
        for stage in flow.STATES[1:]:
            v = flow.advance(v, "win11_1", stage, gate(stage))
        result = flow.simulated_progress(v)
        self.assertEqual(result["states"]["win11_1"],
                         "READY_FOR_APPROVED_BENIGN_ANALYSIS")
        self.assertFalse(result["real_guests_created"])
        self.assertFalse(result["physical_egress_verified"])
        self.assertFalse(result["real_checkpoint_restored"])
        self.assertFalse(result["operator_action_authorized"])

    def test_host_restriction_and_staged_inputs(self):
        with self.assertRaisesRegex(flow.SequenceBlocked, "SSL-55"):
            flow.create_model(fixture(1), reference_host=True)
        value = fixture(1)
        value["identities_reserved"] = True
        with self.assertRaisesRegex(flow.SequenceBlocked, "Expected unapplied"):
            flow.create_model(value)
        value = fixture(1)
        value["candidates"][0]["nic_attached"] = True
        with self.assertRaisesRegex(flow.SequenceBlocked, "Unexpected model"):
            flow.create_model(value)

    def test_double_advance_or_stage_jump_fails(self):
        v = flow.create_model(fixture(1))
        v = flow.advance(v, "win11_1", "IDENTITY_RESERVED",
                         gate("IDENTITY_RESERVED"))
        with self.assertRaisesRegex(flow.SequenceBlocked, "Stage order"):
            flow.advance(v, "win11_1", "IDENTITY_RESERVED",
                         gate("IDENTITY_RESERVED"))
        with self.assertRaisesRegex(flow.SequenceBlocked, "Stage order"):
            flow.advance(v, "win11_1", "FIRMWARE_TPM_STAGED",
                         gate("FIRMWARE_TPM_STAGED"))

    def test_per_guest_failure_retained_and_non_destructive(self):
        v = flow.create_model(fixture())
        v = flow.stop_for_review(v, "win11_2",
                                 "Simulated insufficient clone storage")
        result = flow.simulated_progress(v)
        self.assertEqual(result["states"]["win11_2"],
                         "STOPPED_MANUAL_REVIEW")
        self.assertEqual(result["states"]["win11_1"], "PLANNED")
        with self.assertRaisesRegex(flow.SequenceBlocked, "manual-review"):
            flow.advance(v, "win11_2", "IDENTITY_RESERVED",
                         gate("IDENTITY_RESERVED"))
        self.assertFalse(v["real_host_modified"])

    def test_corrupt_models_cannot_be_advanced(self):
        v = flow.create_model(fixture(1))
        for field in ("real_host_modified", "deploy_authorized",
                      "guest_ready_in_reality"):
            broken = dict(v, **{field: True})
            with self.subTest(field=field), \
                    self.assertRaisesRegex(flow.SequenceBlocked, "Unexpected"):
                flow.advance(broken, "win11_1", "IDENTITY_RESERVED",
                             gate("IDENTITY_RESERVED"))

    def test_invalid_count_names_and_duplicates(self):
        for total in (0, 17, True):
            broken = fixture(1)
            broken["requested_total"] = total
            with self.assertRaises(flow.SequenceBlocked):
                flow.create_model(broken)
        broken = fixture(2)
        broken["candidates"][1]["libvirt_uuid_candidate"] = \
            broken["candidates"][0]["libvirt_uuid_candidate"]
        with self.assertRaisesRegex(flow.SequenceBlocked, "duplicate"):
            flow.create_model(broken)
        broken = fixture(1)
        broken["candidates"][0]["libvirt_name"] = "win11_999"
        with self.assertRaisesRegex(flow.SequenceBlocked, "name"):
            flow.create_model(broken)

    def test_rejects_malformed_mac_uuid_and_ip_before_simulation(self):
        for field, invalid in (
            ("libvirt_uuid_candidate", "not-an-uuid"),
            ("smbios_generation_id_candidate", "invalid"),
            ("mac_candidate", "01:23:45:67:89:ab"),
            ("mac_candidate", "zz:zz:zz:zz:zz:zz"),
            ("guest_static_ipv4_target", "not-an-ip"),
        ):
            value = fixture(1)
            value["candidates"][0][field] = invalid
            with self.subTest(field=field, invalid=invalid), \
                    self.assertRaisesRegex(flow.SequenceBlocked, "invalid"):
                flow.create_model(value)

    def test_no_external_system_calls_in_stage_model(self):
        import inspect
        src = inspect.getsource(flow)
        self.assertNotIn("subprocess", src)
        self.assertNotIn("virsh", src)
        self.assertNotIn("os.system", src)
        self.assertNotIn("rclone", src)
        self.assertNotIn("qemu-img", src)
        self.assertIn('"real_host_modified": False', src)


if __name__ == "__main__":
    unittest.main()
