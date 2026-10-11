#!/usr/bin/env python3
"""Pure Command 2 multi-guest sequencing gates (NEVER executes host actions).

This is a design oracle for a future PORTABLE separate-host provisioner.
"evidence" below represents externally verified facts, but this module
does not collect/attest them; neither input nor output authorizes VM work.
In particular, NIC_ATTACH requires independently established IPv4/IPv6
egress containment plus persistent guards. It cannot run on SSL-55.
"""
from __future__ import annotations

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network
import re

class SequenceBlocked(ValueError):
    pass

STATES = (
    "PLANNED",
    "IDENTITY_RESERVED",
    "DISK_STAGED",
    "FIRMWARE_TPM_STAGED",
    "DOMAIN_DEFINED_ZERO_NIC",
    "ZERO_NIC_GUEST_BOOT_VERIFIED",
    "WINDOWS_HOSTNAME_VERIFIED",
    "NETWORK_CONTAINMENT_PROVEN",
    "NIC_ATTACHED_TO_ISOLATED_NETWORK",
    "STATIC_IP_VERIFIED",
    "CAPE_CONNECTION_VERIFIED",
    "COLD_CHECKPOINT_RESTORE_VERIFIED",
    "READY_FOR_APPROVED_BENIGN_ANALYSIS",
)
REVIEW = "STOPPED_MANUAL_REVIEW"
REQUIREMENTS = {
    "IDENTITY_RESERVED": ("exact_host_inventory_rechecked",
                          "collision_free_reservation_durable"),
    "DISK_STAGED": ("master_immutable", "disk_independence_verified",
                    "capacity_floor_maintained"),
    "FIRMWARE_TPM_STAGED": ("private_uefi_vars_verified",
                            "fresh_private_swtpm_verified"),
    "DOMAIN_DEFINED_ZERO_NIC": ("libvirt_uuid_unique",
                                "domain_xml_exact_and_zero_nic",
                                "domain_shut_off"),
    "ZERO_NIC_GUEST_BOOT_VERIFIED": ("no_nic_observed_live_and_saved",
                                    "guest_boot_verified"),
    "WINDOWS_HOSTNAME_VERIFIED": ("guest_hostname_unique_and_verified",),
    "NETWORK_CONTAINMENT_PROVEN": (
        "shared_host_firewall_not_disrupted",
        "ipv4_negative_egress_verified",
        "ipv6_negative_egress_verified",
        "isolation_guard_reboot_persistence_verified",
        "cape_positive_path_proven",
        "isolation_network_checked",
    ),
    "NIC_ATTACHED_TO_ISOLATED_NETWORK": (
        "exact_isolated_nic_only", "no_lan_or_default_nat_nic",
    ),
    "STATIC_IP_VERIFIED": ("guest_ipv4_exact_and_unique",),
    "CAPE_CONNECTION_VERIFIED": ("cape_agent_reachable",
                                 "cape_registered_vm_mapping_verified"),
    "COLD_CHECKPOINT_RESTORE_VERIFIED": (
        "clone_disk_nvram_tpm_cold_restore_tested",
        "guest_boot_identity_after_restore_verified",
        "network_containment_still_verified_after_restore",
    ),
    "READY_FOR_APPROVED_BENIGN_ANALYSIS": (
        "operator_benign_test_approval", "host_capacity_rechecked",
    ),
}
NAME = re.compile(r"^win11_([1-9][0-9]*)$")


def check(condition, message):
    if not condition:
        raise SequenceBlocked(message)


def create_model(candidate_blueprint, *, reference_host=False):
    """Build an in-memory gate model from unreserved identity candidates."""
    check(reference_host is False, "SSL-55 reference host prohibited")
    check(type(candidate_blueprint) is dict and
          candidate_blueprint.get("result") == "COMMAND2_CANDIDATE_IDENTITIES_ONLY"
          and candidate_blueprint.get("created_any_vm") is False
          and candidate_blueprint.get("identities_reserved") is False
          and candidate_blueprint.get("deploy_authorized") is False,
          "Expected unapplied candidate blueprint")
    rows = candidate_blueprint.get("candidates")
    count = candidate_blueprint.get("requested_total")
    check(type(count) is int and 1 <= count <= 16 and
          type(rows) is list and len(rows) == count,
          "Invalid requested model size")
    identities = set()
    macs = set()
    ips = set()
    guests = {}
    for index, item in enumerate(rows, start=1):
        check(type(item) is dict, "Invalid guest row")
        name = item.get("libvirt_name")
        check(name == f"win11_{index}" and
              item.get("windows_hostname_target") == f"WIN11-{index}" and
              item.get("nic_attached") is False and
              item.get("windows_identity_change_applied") is False and
              item.get("static_ipv4_applied") is False,
              "Unexpected model guest state or name")
        for field in ("libvirt_uuid_candidate", "smbios_generation_id_candidate"):
            ident = item.get(field)
            check(type(ident) is str and ident not in identities,
                  "Missing/duplicate guest UUID or generation ID")
            identities.add(ident)
        mac = item.get("mac_candidate")
        ip = item.get("guest_static_ipv4_target")
        check(type(mac) is str and mac not in macs and
              type(ip) is str and ip not in ips,
              "Missing/duplicate guest MAC or IP")
        macs.add(mac)
        ips.add(ip)
        guests[name] = {"stage": "PLANNED", "validated_gates": [],
                        "manual_review_only": False}
    return {
        "kind": "COMMAND2_IN_MEMORY_SEQUENCE_MODEL_ONLY",
        "guest_count": count,
        "guests": guests,
        "real_host_evidence_authenticated": False,
        "real_host_modified": False,
        "network_attached": False,
        "deploy_authorized": False,
        "guest_ready_in_reality": False,
    }


def advance(model, guest, next_state, evidence):
    """Pure transition; no side effects and no implicit skipping.

    Each required gate must be exactly True (not truthy). A future
    host collector, not this model, must authenticate all claims.
    """
    check(type(model) is dict and
          model.get("kind") == "COMMAND2_IN_MEMORY_SEQUENCE_MODEL_ONLY"
          and model.get("real_host_modified") is False
          and model.get("deploy_authorized") is False
          and model.get("guest_ready_in_reality") is False,
          "Unexpected live-deployment flag in sequence")
    rows = model.get("guests")
    check(type(rows) is dict and guest in rows,
          "Unknown or removed guest")
    current = rows[guest]
    stage = current.get("stage")
    check(stage in STATES and current.get("manual_review_only") is False,
          "Guest is in manual-review or invalid state")
    next_index = STATES.index(stage) + 1
    check(next_index < len(STATES) and next_state == STATES[next_index],
          "Stage order violated: " + str(stage) + " -> " + str(next_state))
    check(type(evidence) is dict and all(
        evidence.get(flag) is True for flag in REQUIREMENTS[next_state]),
        "Required proof missing for " + next_state)
    result = deepcopy(model)
    result["guests"][guest]["stage"] = next_state
    result["guests"][guest]["validated_gates"].extend(REQUIREMENTS[next_state])
    # A model cannot assert the physical guest has a NIC, even at this
    # conceptual stage; host state has NOT changed.
    return result


def stop_for_review(model, guest, reason):
    """On interruption, represent manual-review stop; never auto-rollback."""
    check(type(reason) is str and reason.strip() and len(reason) < 300,
          "A short non-secret reason is required")
    check(type(model) is dict and
          model.get("kind") == "COMMAND2_IN_MEMORY_SEQUENCE_MODEL_ONLY" and
          isinstance(model.get("guests"), dict) and guest in model["guests"],
          "Unknown guest for manual review")
    result = deepcopy(model)
    result["guests"][guest]["stage"] = REVIEW
    result["guests"][guest]["manual_review_only"] = True
    return result


def simulated_progress(model):
    """Summaries are explicit simulations, never approval certificates."""
    check(type(model) is dict and
          model.get("kind") == "COMMAND2_IN_MEMORY_SEQUENCE_MODEL_ONLY",
          "Unknown model")
    return {
        "result": "COMMAND2_SIMULATED_PROGRESS_ONLY",
        "states": {key: value["stage"] for key, value in model["guests"].items()},
        "guest_count": model["guest_count"],
        "physical_egress_verified": False,
        "real_checkpoint_restored": False,
        "real_guests_created": False,
        "operator_action_authorized": False,
    }
