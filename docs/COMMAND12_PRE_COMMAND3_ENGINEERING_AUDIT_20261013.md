# Commands 1–2 — engineering audit before Command 3 (2026-10-13)

**Code branch:** `development` only. **Host operations:** NONE this review.
**Reference machine:** CSE-SSL-55 unchanged; protect original manually customized
`win11`, trial and `win11_1` with three existing internal RAM/OS/OVMF
snapshot records. Do not revert an SSL-55 checkpoint or modify TPM state.

## Operator's immutable requirements

1. Command 1 on a supported fresh Ubuntu system bootstraps the entire
   CAPEv2/INetSim host environment, imports the **operator's actual**
   manually customized Windows master including its Windows files/apps/
   registry (not a reconstructed installation), and produces a usable
   final running analysis snapshot that has demonstrably safe restore.
2. Command 2 prompts for **N additional Windows VMs** (1..16):
   `win11_1` through `win11_N`, each independent disk, domain UUID,
   machine generation identity, UEFI variable store, swtpm identity,
   NIC MAC, stable own IP, Windows hostname, elevated CAPE Agent and
   an individually captured **RUNNING** RAM/Windows disk/UEFI snapshot.
   At CAPE handoff, guests must be **SHUT OFF** so standard CAPE KVM
   revert can use each named captured-RUNNING baseline.
3. Do not touch `main`, turn on malware analysis, restore an existing
   reference snapshot or automatically deploy on SSL-55. User has
   deferred separate-machine acceptance until the Command 3 design phase.

## Verified from current development source

### Command 1: partial, **NOT a complete unattended fresh-host installer**

- `scripts/command1_pre_vm.sh` supports guarded missing-package,
  virtualization, source and optional-dependency components and
  diagnostics; it does **not** install/configure all CAPEv2 base,
  databases, INetSim, services and original custom QEMU/SeaBIOS.
- `command1_export_existing_master.py` flattens the original OFFLINE
  Windows QCOW2 backing chain, captures original shut-off guest XML,
  UEFI VARS and private master swtpm state in a root-only checksum-bound
  bundle. No user apps/registry values are guessed or recreated.
- `command1_import_existing_master.py` imports the byte-identical
  bundle on a separately authorized host, keeping the Windows master
  SHUT OFF. Host-actual Windows boot, firmware access, TPM/BitLocker
  and OS/Agent operation are **not** verified by import.
- No implemented Command 1 final verified running-memory/disk/UEFI
  **plus safely-restorable swtpm state** capture exists. That remains
  a development/physical-acceptance blocker.

### Command 2: guarded multi-stage components, **NOT a one-touch completion**

- `command2_from_exact_master_bundle.py` asks **additional count**,
  plans and (on an approved other host with typed approvals) invokes
  zero-NIC staging, persistent `default` NAT reservations, one e1000e
  NIC/guest and per-guest Windows configuration ISO creation.
- `command2_portable_zero_nic_entrypoint.py` now performs full
  immutable-source SHA/QCOW2/cleartext Windows volume/UEFI/VM-definition
  admission **BEFORE** writing the durable count/identity journal.
  This prevents a known incompatible/BitLocker-protected master export
  from wasting an exclusive journal and leaving a nonrecoverable partial
  stage **before any guest creation**. Such images are BLOCKED, not
  silently decrypted or altered.
- The same controller validates that **all N separate clone receipts**
  actually describe the correct names, zero NICs, independent shut-off
  states and expected count before calling the stage complete.
  The exact-master wizard now additionally binds the nested clone
  receipts, count of NAT DHCP reservations and individually published
  optical media to exactly `win11_1..win11_N` before proceeding.
- Trusted CAPE Agent transport, Windows hostname/DHCP configuration
  upload/execute/independent verification, first boot, matching QCOW2
  OVMF preparation, candidate running RAM/OS/UEFI snapshots and
  final graceful shutdown are separately guarded phases. They
  require per-stage receipts/approvals, and are **not yet one fully
  automatic Command 2**.
- `command2_portable_master_nat_final_shutdown.py` checks that all N
  guests have separately verified running checkpoints and Windows
  identity/Agent witnesses before sequential graceful SHUT OFF.
  Failures stop; no hard reset, snapshot deletion or implicit retry.
- `default` `virbr0` NAT is Internet-forwarding and **NOT** a safe
  live-malware analysis network. Prior targeted benign packet probes
  do not certify sustained containment. Never run malware on it.

## IP semantics: do not misdescribe current code

The exact-master NAT implementation reserves a **stable, unique IPv4**
for each VM through permanent libvirt DHCP MAC-to-IP reservation;
the Windows guest is configured to USE DHCP and DNS. This creates a
repeatable address, **not a manually configured static-IP setting in
Windows**. If the operator requires `DHCP Enabled: No` in Windows, that
is a distinct unimplemented guest-network profile and must not be
claimed as finished. CAPE machine IP mappings must use the actual
chosen topology, not the old isolated-network journal placeholder.

## Critical remaining engineering and acceptance gates

| Gate | Code status | Cannot be called passed yet because |
|---|---|---|
| Full fresh Ubuntu CAPEv2 + INetSim + DB + service installer | **INCOMPLETE** | Idempotent full host replacement for observed risky upstream installers not implemented |
| Imported exact Windows master boot + Agent + TPM + OVMF | **STAGED ONLY** | Must test target CPU/OVMF/libvirt/QEMU storage security access and Windows state |
| Original master cold export suitable for DIFFERENT TPM clones | **CONDITIONAL** | A genuinely BitLocker-encrypted OS clone may not boot with independent TPM; plaintext/decrypted approved clone source must be proven |
| N actual independently configured Windows boots | **COMPONENTS PRESENT** | No joined 1-prompt fully automatic Windows identity and NAT flow physically verified |
| Stable reserved IP for each NAT clone | **IMPLEMENTED / OFFLINE-TESTED** | Guest DHCP and real routed/agent behavior must be verified on other host |
| Native RAM+disk+OVMF running checkpoint candidates | **IMPLEMENTED / OFFLINE-TESTED** | QEMU/libvirt real snapshot and UEFI behavior unverified on target |
| Matched independent swtpm2 state recovery/revert | **BLOCKING GAP** | Libvirt ordinary internal running snapshot does NOT atomically restore external TPM persistent/volatile state; two physical benign consistent-revert cycles and supported recovery adapter are required |
| Final all-N CAPE handoff powered off | **GUARDED CODE PRESENT** | No actual multi-VM shutdown and repeated physical restoration test yet |
| Real malware-safe containment/INetSim path | **NOT RELEASED** | Permanent NAT permits Internet access; need demonstrably safe IPv4/IPv6/peer/host negative egress and positive INetSim paths |
| Concurrent safe CAPE jobs and machine configuration | **PENDING** | Operator-supplied Command 3 config and at least two parallel benign analysis/reset acceptances |

## Tested in this review

- Exact master preservation, firstboot/NAT/Agent, running-candidate
  checkpoint, final graceful stop and existing synthetic tests reviewed.
- Changes limited to `development`: clone-source pre-journal
  admission and strict all-N count-bound stage/NAT/ISO handoff.
- GitHub Actions Python offline suites and Windows PowerShell syntax
  are mandatory for **every** edited development commit. They validate
  code shape/mocks, not libvirt snapshot real restore, Windows boot,
  fresh-host install or actual firewall containment.

**Decision:** Command 3 may be **designed and developed next** without
waiting for physical other-machine acceptance, as the user requested.
However **Commands 1 and 2 are NOT fully implemented, release-ready or
equivalent to “only testing remains.”** Their critical blockers must be
implemented/validated before an end-to-end deployment can be certified.
Do not weaken security or claim closure to meet a schedule.
