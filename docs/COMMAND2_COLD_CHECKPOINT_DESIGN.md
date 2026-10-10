# Command 2 — restore-safe cold clone checkpoint design (2026-10-10)

**Status: DESIGN ONLY. No checkpoint, libvirt snapshot, disk copy, VM shutdown or restoration has been approved/executed.** Work ONLY on `development`. The shared SSL-55 host and original master `win11` are protected.

## Why the next checkpoint must be cold and multi-component

Actual operator report `CAPE_Command2A_SnapshotFeasibility_20261010_234638_eLxaAMp1.txt` confirms:
- Protected source master `win11` state/UUID passed, but original-master disk SHA/fingerprints NOT checked in this audit.
- `win11_1` UUID `732b2256-ee99-41fa-881d-fbf5c476d960`, running, no NICs, independent QCOW2 `/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2` (64 GiB virtual; on-host st_blocks allocated ~29.26 GiB, on-disk file size 31,538,872,320 B).
- Independent OVMF `/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd` (540,672 B).
- swtpm v0.7.3 directory `/var/lib/libvirt/swtpm/732b2256-ee99-41fa-881d-fbf5c476d960/tpm2`, with `.lock` (0 B) and `tpm2-00.permall` (9,234 B; UID/GID 105, mode 0600).
- No libvirt snapshot metadata; QEMU/qemu-img 9.2.2, libvirt 11.1.0.
- Available space **96.11 GiB**; previous conservative full-disk 64 GiB + 30 GiB reserve = **94 GiB**; only 2.11 GiB surplus under that high-water assumption.
- Report is read-only: no full-state checkpoint/restore, stable cold copy, swtpm state recovery or runtime egress isolation validated.

The presence of `tpm2-00.permall` **does not** prove the entire TPM state is immutable while the VM runs or restored merely by a QCOW2 snapshot. The presence of a dedicated UEFI VARS file likewise does not mean a libvirt disk snapshot captures it. The original Windows master has BitLocker recovery history; **NEVER touch it or its TPM/NVRAM/snapshots**.

Relevant upstream:
- libvirt domain format: https://www.libvirt.org/formatdomain.html (emulated TPM private state and UEFI VARS are separate artifacts).
- libvirt snapshot API: https://libvirt.org/manpages/virsh.html#snapshot-create-as (disk-only means no VM memory).
- swtpm state backend: https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod (directory-based swtpm state files, lock and backup semantics).

## Recommended engineering choice

**Prefer an isolated clone-only cold restore point over an unverified live disk-only snapshot.** Two designs are possible and not yet chosen for the implementation:

**A. Independent cold backup**: after explicit guest shutdown and host checks, save a separately named copy of the powered-off clone's QCOW2, exact OVMF VARS, and *all* relevant persistent swtpm state blobs (never merely the lock file), plus domain XML/manifest/checksums/ownership. A copy can consume ~29 GiB at the current allocation, or potentially approach the full 64 GiB if sparse handling/format changes; it will affect the space available for future VM clones. Never silently allocate a second disk image given current 96.11 GiB free.

**B. Cold external QCOW2 overlay baseline**: once the guest is fully shut down and libvirt/AppArmor external-backing semantics have been reviewed, freeze a clone-only immutable QCOW2 base and use a new writable QCOW2 overlay for future analysis runs; capture OVMF VARS and swtpm permanent state separately at the same cold boundary. This reduces initial storage use but adds complex disk-chain, AppArmor and restore logic. A libvirt disk snapshot alone does not establish a complete, reproducible swtpm/NVRAM checkpoint, nor is rollback verified. Existing boot helper hardcodes the clone's old standalone disk path; it must be adapted if the active layer changes.

Neither design should be executed on SSL-55 until rollback/partial-failure handling and storage margins are accepted. Do not rely on libvirt snapshot metadata alone as a recovery certificate. DO NOT take a live snapshot of TPM files by raw copying while swtpm is active.

## Mandatory plan/acceptance gates before any operation changes a VM

1. **Identity:** exact `win11_1` UUID and protected original/trial identities; original is shut off; no NIC in live and saved XML; `cape-analysis-isolated` inactive + no autostart; guard existence plus rule fingerprint checked separately. Refuse any unexpected device or changed disk.
2. **Windows clean shutdown:** user initiates **full Windows shutdown** inside `WIN11-1` (not Ubuntu reboot, not QEMU destroy). Host confirms `virsh domstate win11_1 == "shut off"`, and no active QEMU/swtpm process still owns the clone disk, NVRAM, or TPM state.
3. **Disk readiness:** validate exact image format, 64 GiB virtual size, no backing (at current stage), `qemu-img check` ONLY AFTER shutdown, and correct Windows identity from the previous operator screenshot. Reject in-progress snapshots/block jobs or unexplained storage links.
4. **NVRAM and TPM:** inspect exact and securely owned files, TPM backend state path, encryption-secret dependency (if any); do not assume only the single `*.permall` file persists forever. Require no active TPM process and an exact inventory manifest. Treat TPM files as sensitive secrets; reports show only metadata/hashes, no contents.
5. **Destination/capacity:** private root-owned directory, never master disk paths, no collisions or symlinks, exclusive creation, conservative min-free reserve before and during copy, abort safely on capacity drop, preserve partial artifacts for review, and do not automatically delete unknown files. Check space against **actual required allocations**, including future overlay growth and VM count.
6. **Atomic acceptance:** detached state manifest includes clone UUID, domain XML hash, exact disk/NVRAM/TPM artifacts + checksums, versions, original state, time, zero-NIC gate, and *current restore limitations*. Publish a checkpoint only after every component verifies. Do not claim restored/boot-tested.
7. **Restore testing:** after a separate independent approval, verify a controlled rollback **only on the clone**; cold complete-state reversion, AppArmor/hardware compatibility, no NICs, Windows boot + `WIN11-1`, Python, agent localhost `status:init`, Windows TPM ready and BitLocker state. Never overwrite another VM or alter master/trial.
8. **Future multi-VM:** independently cold checkpoint and validate each VM. Uniqueness must include UUID, swtpm state, UEFI VARS, Windows hostname, static IP and MAC. Do not bulk-stage N until storage budgets and safe network guards are accepted.

## Immediate next development actions (NO host modifications yet)

- Implement **plan-only** capture/restore manifest and storage strategy; add mocked tests for wrong UUID, running guest, changed TPM path, unexpected NIC, disk collision, insufficient storage, and interruption.
- Verify all active host-specific paths against captured operator results and refine rule design for clone-only overlay read/lock access if approach B is selected.
- Include one interactive, SHA-pinned host wrapper that generates **one TXT report** and does not shut down the VM without explicit operator approval.
- Make actual checkpoint capture a distinct explicit action, not a side-effect of a read-only plan.
- Continue networking isolation/fail-closed persistence work **without enabling a guest NIC** until independently verified.

## Existing clone-name collision: required future Command 2 behavior

The current `scripts/command2_stage_independent_clones.py` preflight
iterates `win11_1..win11_N` and rejects any existing domain or artifact.
Since `win11_1` now exists and is the accepted personalized guest,
re-running it with `--count 5 --mode stage` is NOT a way to add four
more VMs; it will fail at `win11_1` (correctly, without overwriting).
Future count-driven Command 2 must either:
- define `N` as **total desired clone count**, revalidate and preserve
  accepted earlier clones, and only stage missing `win11_2..win11_N`; or
- define `N` as **additional desired clone count** and explicitly
  allocate fresh safe names above the current highest index.

Do not mix these semantics. The user earlier requested
`win11_1..win11_5` for count 5, suggesting total desired count,
but this must be stated in the CLI. No extra guests should be staged
until the space budget and storage/TPM restoration gates pass.

**DO NOT RUN MALWARE OR CONNECT ANY ANALYSIS NIC**. This design is not a guarantee of restore or full Command 2 readiness.
