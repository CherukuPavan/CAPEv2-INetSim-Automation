# Portable Command 2 — provisioning-state safety model

**Development-only dry-run contract. ZERO host operations. Do not use
SSL-55 for VM creation, cold backups, networking or scaled test runs.**

## What exists

- `scripts/command2_portable_sequence_model.py` models progress of
  `win11_1..win11_N` from proposed identities through no-NIC staging,
  Windows hostname verification, IPv4+IPv6 isolation proof, isolated NIC
  attachment, guest static IP, CAPE connection and cold restoration.
- `scripts/test_command2_portable_sequence_model.py` covers ordered
  transitions, impossible skips, missing proof, malformed UUID/MAC/IP,
  interrupt-to-manual-review behavior, guest isolation and explicitly
  nonauthoritative simulated result fields.
- Workflow `.github/workflows/command2-cold-checkpoint-offline.yml`
  is configured to execute this test module under Python 3.10/3.12.
  A CI conclusion is **not** a real guest or egress acceptance.

## Mandatory order and evidence classes

1. Proposed identities; recheck exact target libvirt inventory and persist
   collision-free reservations under an appropriate lock.
2. Independent verified clone disk, operating free-space budget.
3. Independent private UEFI VARS and fresh per-UUID swtpm.
4. Domain definition with **zero NIC**; saved XML and power state verified.
5. No-NIC guest boot and Windows hostname verified.
6. **Before connecting ANY interface**, prove host's firewall/bridge guard
   noninterference with campus/Docker, negative IPv4 egress, negative IPv6
   egress, reboot persistence and positive CAPE-isolated path.
7. Attach *only* intended analysis NIC with no default NAT or campus NIC.
8. Apply and verify unique guest IPv4.
9. Register CAPE and verify agent accessibility.
10. Independently restore the consistent disk + UEFI NVRAM + swtpm
    cold checkpoint and verify subsequent guest boot/identity/isolation.
11. Perform only explicitly approved benign tests; malware execution
    has separate containment, safety and operational approvals.

Each forward transition requires explicit evidence flags `True`, not
merely truthy integers. These flags are inputs to a **pure model**:
a test can fabricate them. Therefore even a simulated `READY` state
explicitly reports `real_guests_created: false`, 
`physical_egress_verified: false` and
`operator_action_authorized: false`. Never use that state as an
authorization certificate.

An interrupted guest becomes `STOPPED_MANUAL_REVIEW` and cannot resume
without an independent recovery/reverification path (not implemented).
This prohibits blind retry, deletion, rollback or overwrites.

## Remaining tasks / real-machine acceptance blockers

- Authenticated host-side evidence collectors for every gate, including
  IPv4/IPv6 guard persistence and negative egress tests.
- Durable, race-safe candidate identity reservations and interruption
  reconciliation. Current UUID/MAC values are unreserved random proposals.
- Portable guest copy/UEFI/swtpm staging on a separately authorized host;
  the older SSL-55 script is not a portable deployer.
- Windows hostname/static-IP automation, exact NIC adapter mapping and
  guard-ready no-egress isolation.
- Complete cold restore verification, two-VM parallel CAPE acceptance,
  error handling and target-machine resource-limit tuning.
- Fresh-host physical test and operator signoff. No extra SSL-55 VMs.

The scope intentionally prevents overstating mocked safety checks as
proof that an actual VM has been deployed safely.

## Count scaling beyond 16

The portable-only count planner now permits N > 16 (tested in
synthetic scenarios for N=32) while enforcing CIDR guest-IP capacity,
CPU/RAM/disk metadata gates and a defensive 4096-entry in-memory cap.
This does not alter the separate SSL-55 legacy stage command and never
provisions VMs on the reference host. Actual scaling ceilings must be
validated on the approved deployment machine; requesting 32 is not
proof that 32 guests can run in parallel.
