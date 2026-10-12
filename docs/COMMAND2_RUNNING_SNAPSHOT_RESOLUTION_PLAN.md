# Command 2: how we will achieve reliable RUNNING Windows state for CAPE

**Development plan; no live snapshot/VM edits authorized on SSL-55.**

## Requirement

Each independent `win11_N` must have a *captured while running* Windows state
with the CAPE Agent ready. CAPE's **standard KVM** machinery will only
start a machine that is **shut off**, and invokes libvirt
`revertToSnapshot(snapshot,flags=0)` to return it to the saved **running**
state. Consequently "snapshot created" is inadequate: a clean rollback
test with at least two benign iterations is mandatory for each guest.

As of 2026-10-12, **there is NO running snapshot on SSL-55 win11_1**.
All prior successful SSL-55 acceptance (one NIC, external TCP probes, nft,
bridge, clean independent boot, cold bundle) remains valid.

## Confirmed firmware/TPM blockers

The original SSL-55 pilot has a RAW UEFI OVMF variable store and an
emulated TPM2 (`swtpm`). Libvirt's 2024 native internal snapshot
improvement requires **QCOW2** UEFI NVRAM, and libvirt's earlier RFE to
support emulated TPM state in memory snapshots was ultimately marked
**CLOSED WONTFIX**, meaning we must not assume TPM state is captured
atomically even if the memory/disk snapshot reports success.

Converting RAW OVMF VARS to QCOW2 on a *running* VM is forbidden. Even
an offline conversion on an independently backed disposable VM does
not by itself solve swtpm restore. Never forcibly remove TPM from a
working Windows 11 guest or alter Secure Boot/BitLocker to make a
snapshot appear successful.

## Candidate A: standard CAPE KVM native libvirt snapshot

Only on the approved disposable **second machine**:
- Validate separate Windows boot/TPM identity, CAPE Agent, network
  isolation, and independent full cold recovery bundle.
- On disposable guest with deliberate approval, evaluate whether
  **QCOW2 NVRAM** is supported by its installed QEMU/libvirt/OVMF
  stack; refuse old libvirt versions with known snapshot revert bugs.
- Capture with the guest running and verify XML says running + both
  disk and memory snapshot state.
- Perform *multiple* real reverted boot cycles with witnessed benign
  Windows + TPM identity/UEFI/BitLocker tests and negative network tests.
- Only passing **full-state** reversibility permits CAPE registration.
  Snapshot metadata or QEMU command success alone does not pass.
- Any TPM state drift or incompatible restore => STOP; do not weaken
  TPM encryption, firmware or external network isolation.

## Candidate B: CAPE-specific full-state running-save adapter

Research alternate if native libvirt snapshots cannot revert TPM+UEFI:
- QEMU documents saving TPM state via migration; libvirt `virsh save`
  records **running RAM but NOT disk**, and stops the guest.
- After saving *only a disposable guest*, capture the exact stopped
  disk, firmware NVRAM and swtpm files with SHA256. Validate source
  unchanged and storage reserve maintained.
- A future isolated CAPE machinery adapter would restore **ALL**
  disk/NVRAM/swtpm first, then restore the saved running memory image.
  This must be tried repeatedly with benign guest state and confirmed
  swtpm migration consistency on the same QEMU/swtpm versions.
- This **is not** a libvirt `virDomainSnapshot`. Standard CAPE KVM
  machinery **cannot use it unchanged**. A separate, reviewed custom
  machinery implementation and acceptance are necessary. It must not
  be mislabeled a completed standard running snapshot.
- Never restore `virsh save` twice without also resetting ALL external
  storage to the exact saved epoch; libvirt explicitly warns that this
  risks corruption.

## Already implemented safety gates

- `scripts/command2_ssl55_running_snapshot_readonly.py`: exact host
  running-VM XML / disk / RAW vs QCOW2 NVRAM / TPM and cold-backup
  metadata. Read-only; does not create snapshot.
- `scripts/command2_running_snapshot_batch_gate.py`: each separately
  registered `cape_ready_win11_N` snapshot must be captured running with
  disk+memory and have full repeated benign TPM/UEFI/agent revert
  witness. Final VM is **shut off** for CAPE start.
- `scripts/command2_cape_registration_gate.py`: refuses CAPE config
  updates unless **every requested guest** passes the above gate and
  has its own snapshot name; makes rollback backup under approval.
- `scripts/command2_portable_cold_bundle.py`: preserves independent
  disk, NVRAM and TPM cold bundle on an approved other host. Real
  restoration remains an independent acceptance task.

## Operating constraints

- SSL-55 reference master and trial remain shut off and immutable.
- Only ~64.77 GiB free last observed on shared host, with a 40 GiB
  reserve. No new ~30 GiB clone or additional recovery copy.
- No guest malware execution before real IPv4/IPv6/L2 isolation and
  repeatable reset are approved and physically witnessed.
- End-to-end two-guest acceptance requires the separate Ubuntu/KVM
  machine the operator has made available. GitHub offline CI is not
  physical validation.

## Primary sources

- CAPE running snapshot: https://capev2.readthedocs.io/en/latest/installation/guest/saving.html
- CAPE KVM machinery semantics: https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/abstracts.py
- Libvirt UEFI QCOW2 requirement: https://lists.libvirt.org/archives/list/devel%40lists.libvirt.org/message/KGYWRVJ3MV6PTQU5MZ6ALNSM4STGDEVQ/
- Libvirt swtpm snapshot RFE status: https://bugzilla.redhat.com/show_bug.cgi?id=1855367
- QEMU swtpm migration support: https://www.qemu.org/docs/master/specs/tpm
- libvirt save/restore disk warning: https://www.libvirt.org/manpages/virsh.html

## 2026-10-12 implementation update — experimental native snapshot guard

Additional development code, **not executed on SSL-55 or the second host**:

1. `scripts/command2_snapshot_recovery_preflight.py`: hashes the
   ALREADY-CAPTURED independent full cold bundle including the separate
   `disk.qcow2`, `UEFI_VARS.fd`, and each swtpm private file, while the
   disposable guest is running. Requires root-owned private paths, exact
   guest UUID, stopped-at-capture manifest, and separately reviewed manifest
   SHA-256. It never touches live guest state. Its PASS is proof of backup
   byte integrity only; not proof recovery boot works.
2. `scripts/command2_native_snapshot_stack_guard.py`: rejects experimental
   native internal snapshot capture on the disposable other host unless
   the *running libvirt daemon* is >=10.10.0 (10.9 UEFI reversion bugs),
   the QEMU hypervisor is >=9.0, libvirt XML reports QCOW2 pflash NVRAM,
   `qemu-img info` confirms the NVRAM file is an independent QCOW2,
   swtpm2 exists, exactly one independent clone disk is present,
   and 40GiB shared reserve + >=2x guest RAM +2GiB margin remains.
   This is conservative; it does not promise that TPM snapshots work.
3. The existing OTHER-HOST-ONLY, operator-approved capture helper
   `scripts/command2_running_cape_snapshot_gate.py` now demands BOTH
   protections before even attempting a running snapshot; it recomputes
   the recovery hashes and rechecks stack admission after typed approval.
   Then it verifies the libvirt snapshot XML has `state=running`,
   precisely one internal disk and internal guest-memory state. A successful
   creation is **still an experiment, not CAPE-ready**; actual benign
   snapshot revert and repeated TPM+UEFI recovery remain blocking.
   Legacy capture callers without the required recovery-bundle and
   reviewed-manifest-SHA arguments now refuse.
4. `scripts/command2_windows_benign_snapshot_witness.ps1` provides read-only
   `-Mode Baseline` and `-Mode Verify`, plus separately typed-approved
   `-Mode Mark` that writes ONE harmless file to Public Documents.
   It records TPM, Secure Boot, BitLocker, Windows identity, host-only
   CAPE Agent response and IPv4/IPv6 routes. After a revert, marker absence
   plus matching off-guest baseline is disk state evidence, **NOT** itself
   proof of swtpm persistent state restoration. Preserve baseline off
   guest BEFORE taking the snapshot; snapshot/revert rewinds Windows disk
   reports and marker.
5. The full CI test set includes synthetic altered/stolen cold bundle tests,
   RAW-vs-QCOW2 NVRAM, libvirt/QEMU version checks, no-network-mutation
   safeguards, and Windows PowerShell syntax. CI run 38239479336 SUCCESS.

### Operator decision for canonical SSL-55 win11_1

The independent `win11_1` has working Windows + CAPE Agent + isolated
network and a full, SHA-verified cold bundle, but **no running snapshot**.
It currently uses RAW OVMF variables + swtpm2. Therefore no supported
generic snapshot command has been approved on SSL-55, and the new
OTHER-HOST experimental capture script forbids this machine outright.
The first next host action is a pinned, READ-ONLY compatibility audit
`command2_ssl55_running_snapshot_readonly.py` plus `virsh version --daemon`
into ONE TXT report. Do not call this result a snapshot creation.

For a true running snapshot with a Windows 11 TPM, validate on the
separately approved disposable second host first. A native
QCOW2-pflash/libvirt snapshot that passes one libvirt command but FAILS
repeated TPM/UEFI/BitLocker/Agent/isolated egress revert tests must NOT
be registered in CAPE. If it fails, design custom CAPE machinery for
same-epoch QEMU running save plus disk/OVMF/swtpm restore, rather than
misrepresenting a disk-only checkpoint as a running snapshot.
