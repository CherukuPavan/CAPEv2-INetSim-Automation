# SSL-55 BitLocker-protected Windows 11 master: clone-template recovery plan

**Status: DESIGN ONLY — NOT APPROVED FOR EXECUTION.**

Evidence from the operator's October 9, 2026 read-only reports:

- Master `win11` currently shut off on libvirt, current cold external
  snapshot `finalshutoffversion`; four QCOW2 layers.
- A fully flattened, independent 64 GiB copy exists at
  `/var/lib/libvirt/images/cape-clones-staging/win11_1.qcow2`.
  It is not defined as a VM and has never booted as a clone.
- The independent copy's main Windows partition is approximately
  62.9 GiB and **BitLocker**; its only plaintext NTFS partition is
  a recovery volume without a Windows SYSTEM hive. NBD was disconnected
  successfully after the read-only probe.
- Hivex dependencies were installed without changing QEMU 9.2.2 or
  libvirt 11.1; they **cannot** inspect or edit the encrypted Windows C:
  hive while the guest volume is locked.
- The operator **does not have a BitLocker 48-digit recovery key** but
  confirms that the **original Windows 11 VM normally boots into its
  desktop** with the already-paired virtual TPM.

## User-protection and operating constraints

1. **Never** boot the detached `win11_1.qcow2` in a new VM without
   the original TPM: a separately generated TPM is unlikely to unlock
   the OS volume and may demand an unavailable recovery key.
2. **Never** put the real recovery key, TPM private state, NVRAM secrets,
   or BitLocker credentials into GitHub, ChatGPT uploads, console logs,
   unattended scripts or audit TXT reports.
3. **Never** attempt to bypass BitLocker, alter original key protectors,
   or copy permanent TPM identity into clones.
4. Do **not** start the existing master on its current mutable QCOW2
   top merely to inspect BitLocker: Windows boot writes would alter the
   original cold snapshot's top disk state.
5. Do **not** alter the original libvirt domain snapshot chain, current
   snapshot pointer, original NVRAM/TPM, or host network without separate
   authorization and a tested restoration procedure.
6. The current `default` network uses NAT and has campus uplink
   connectivity. A benign recovery boot must be made without network
   egress, or with an independently verified containment method that
   cannot affect other host users. Do not run malware.
7. No `--apply` Command 2 run, CAPE configuration rewrite, Windows
   guest boot, NBD writable attachment or decryption until prerequisites
   have been explicitly reviewed.

## Proposed preservation-first process (not yet implemented)

**Phase A — read-only host and recovery inventory**

- Reconfirm shutdown of `win11`, intact four-layer cold snapshot, libvirt
  domain definition, UEFI NVRAM and emulator TPM pairing, resource and
  30+ GiB free-space reserve, and absence of concurrent users modifying
  those objects.
- Obtain backups of libvirt XML and snapshot metadata **without**
  exposing original TPM secrets. Validate a practical *offline*
  restoration method before starting a working layer.
- Verify the VM's intended virtual NIC can be temporarily isolated
  without altering the original disk and without risking a BitLocker
  TPM measurement change. Network containment must not be inferred
  solely from libvirt non-forwarding XML.

**Phase B — prepare a separately authorized writable working layer**

- Use a libvirt-supported external disk overlay for the original domain
  so that Windows boot and any decryption writes go to the **new
  overlay**, not the preserved cold snapshot image.
- Creating an overlay may change persistent libvirt domain disk pointer
  and snapshot metadata. It is a real host/guest-configuration mutation,
  requires consent and an explicit rollback/cleanup plan. Do **not**
  assume `virsh snapshot-revert` works on every external snapshot
  without a proved tested rollback.
- Preserve the original swtpm/NVRAM pairing during this one-time
  maintenance boot, and forbid using or distributing the TPM state as
  a general clone template.

**Phase C — Windows unlocked-volume check**

- Once Windows unlocks and reaches desktop inside the protected overlay,
  inspect in an elevated console:
  `manage-bde -status C:`
- This is **read-only** and reports conversion, protection, and lock
  state. Do not share any recovery keys or run
  `manage-bde -protectors -get C:` in captured logs.
- Prefer locally securing an available recovery protector with the
  authorized operator *before* encryption or boot configuration changes.
- If Windows is unlocked and the operator separately approves
  decryption of the *working overlay*, start
  `manage-bde -off C:` in an elevated console. This **writes**
  to the virtual Windows OS drive and changes BitLocker protectors.
- Do not detach, snapshot, forcibly stop or clone this working drive
  while decryption is ongoing. Wait for
  `manage-bde -status C:` to show **Fully Decrypted, 0% encrypted**,
  then shut down Windows cleanly. Confirm volume header via an
  independent read-only QCOW2 probe.

**Phase D — produce reusable, plaintext clone template**

- Export a **flattened independent disk** only from the verified
  fully-decrypted, powered-off working state.
- Verify the image is QCOW2/no backing chain, its C: is plaintext NTFS,
  independent static IPv4/hostname editing can read and round-trip
  Registry data on clone-only disposable files, and the guest boots
  with brand-new NVRAM and brand-new TPM state.
- Independent analysis network and negative egress checks are mandatory
  before any normal VM startup. Validate installed CAPE agent,
  ping/curl and snapshot rollback on a **benign disposable clone**.
- Fully isolate the reusable plaintext Windows template, because
  BitLocker no longer protects the copied OS contents.
- Revisit and implement actual Command 2 `--apply` handling of
  decrypted template; the BitLocker fail-closed guard on the original
  master **must not be bypassed** as a shortcut.

## Authorization checkpoint

User has confirmed **original Windows boots normally**, not that
master modification, a new external snapshot, decryption, TPM backups,
isolating the original NIC or template export are approved.

The next operation should be a **read-only feasibility and preservation
plan**. Make a concrete, tested restore procedure before requesting
consent to do any VM lifecycle or snapshot changes.

**Microsoft documentation:**
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-status
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-off
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide

## Operator decision and tested read-only safeguard — 2026-10-09

The operator confirms the original `win11` reaches the Windows desktop
normally using its existing virtual TPM, while a 48-digit recovery
password is unavailable. The operator has authorized the safest practical
path toward unattended analysis VM cloning but has **not** supplied any
BitLocker recovery credentials. We will not ask for, export or store them.

A dedicated read-only preservation audit is now in
`scripts/audit_win11_bitlocker_working_overlay.py` with synthetic
offline tests. It inventories the master cold snapshot, source backing
layers, firmware variable-store path, emulator TPM backend and NIC
configuration without reading TPM secrets or changing libvirt state.
This must pass on the real host before any overlay, guest boot, NIC
changes or decryption. Its output does **not** certify TPM restoration:
the swtpm state location requires explicit host-specific verification.

The desired maintenance stage is a temporary working overlay for the
original guest with its existing TPM, **not** automatic boot of the
detached `win11_1.qcow2`. Before maintenance, document an actually
reversible checkpoint of disk pointer, NVRAM and TPM state under a
root-private local location and verify that it can be restored.
Unexpected divergence or unavailable rollback is a **hard stop**.

Even with a rollback plan, Windows unlock on first maintenance boot
is an observed test, not guaranteed by the previously reported desktop
access. If BitLocker enters recovery, do not try random keys or alter
key protectors; stop and restore the previous known working state.

## SSL-55 real-host preservation report — 2026-10-09 22:22 UTC

The user completed the specifically requested **read-only** audit,
`CAPE_BitLocker_Master_Preservation_20261009_222228_TEsgeuHv.txt`:

- Original `win11` is shut off, current snapshot `finalshutoffversion`.
- The top disk is `/var/lib/libvirt/images/win11.finalshutoffversion`
  with **four** QCOW2 backing layers.
- Original OVMF variables file
  `/var/lib/libvirt/qemu/nvram/win11_VARS.fd` exists (**540672 bytes**).
- TPM backend: **libvirt-managed emulator version 2.0**. The standard
  swtpm root and UUID-specific state directory exist. No TPM contents
  were inspected or copied.
- VM interface is on libvirt network `default` with **NAT forwarding**.
  It is not an isolated malware-analysis network.
- Approximately **213.96 GiB** free. The independent encrypted 64 GiB
  `win11_1.qcow2` remains available.
- The audit performed **no** guest boot, snapshot revert, network,
  disk, NVRAM, TPM or BitLocker alteration.

**Remaining hard blocker:** existence of the TPM state directory does NOT
establish an offline backup or a verified restoration procedure. Without
the 48-digit recovery password, failure of the original TPM/firmware
pairing could prevent unlocking both the master and any derived image.
**Do not modify the domain disk pointer, create a working overlay,
boot Windows for decryption or detach/clone original TPM state until
its authorized, locally secured preservation and rollback have been
reviewed and tested.** Backup material must remain private on SSL-55;
it must never appear in report TXT, ChatGPT uploads or GitHub.

After local preservation is completed, a disposable external disk
working overlay under the *original domain* and existing TPM pairing
can be considered, with a NIC-down maintenance boot and post-boot
`manage-bde -status C:` check. None of those steps has yet been run.

## Metadata-only backup-readiness audit — 2026-10-09 22:27 UTC

The operator provided `CAPE_TPM_Backup_Readiness_20261009_222740_57HEArPQ.txt`:

- Original `win11` is shut off at `finalshutoffversion`.
- Standard UUID-scoped swtpm directory exists, owned by UID/GID
  `0:0`, mode `0711`. Two regular TPM-state files inside it are
  owned by UID/GID `105:105`. No symlinks or special files were found.
  Total reported directory size: **20 KiB**.
- Original UEFI NVRAM file exists, **540672 bytes**, UID/GID `0:1008`,
  mode `0600`.
- `/var/backups` parent is UID `0`, mode `0755`; this is an
  acceptable parent for a *new* UID 0, mode `0700` secret-backup
  subdirectory. Never store swtpm state directly in `/var/backups`.
- Available filesystem space: approximately **214 GiB**.
- No master boot, TPM read/export, snapshot, disk, network, or BitLocker
  change occurred. **Backup has not yet been created.**

Next approved milestone: a root-authorized, root-private, local-only
cold-state backup of the *original* domain XML, snapshot XML, NVRAM,
and original UUID-scoped swtpm directory while the VM remains shut off.
Backup scripts must not print/export private swtpm or UEFI bytes;
must not copy data to Github, ChatGPT, or user home; and must verify
the copies locally using silent comparisons and metadata checks.
This does **not** prove restoration is safe: a separate documented
recovery/rollback verification is still required before guest boot.

Official libvirt docs confirm emulator TPM state is private per VM and
swtpm state is held by the emulator backend. File ownership/modes and
the libvirt XML should be preserved rather than globally changing
permissions.
See https://www.libvirt.org/formatdomain.html and
https://www.qemu.org/docs/master/specs/tpm.html.

## Local cold-state backup verified — 2026-10-09 22:31 UTC

The operator executed the guarded local preservation command and uploaded
`CAPE_Win11_Preservation_Backup_20261009_223109_AKvulefU.txt`.
Result: **LOCAL PRESERVATION BACKUP VERIFIED**.

- Backup was created exclusively on SSL-55:
  `/var/backups/cape-win11-preservation/win11-state-92POdfNc`.
  This directory contains secret TPM state and MUST NOT be uploaded.
- The original domain XML and snapshot metadata were saved.
- The original UEFI NVRAM and swtpm state were copied with local
  ownership/permission-preserving operations and compared byte-for-byte
  to the originals, according to the host report.
- The VM was not booted, BitLocker unchanged, and no original QCOW2
  disk was copied. **No actual restoration test was performed.**

**Next independent, low-risk staging step:** create a fresh QCOW2 *working
overlay* over the original current cold disk, but **do not attach it to
libvirt or start Windows yet**. This differs from the separate flattened,
BitLocker-encrypted `win11_1.qcow2` disk created earlier. The overlay
allows future writes to live in a separate layer while retaining the
original four QCOW2 image files unchanged. QEMU documents that backing
files are not modified by ordinary overlay writes, but `qemu-img commit`
must remain forbidden for this protected master.

The new `scripts/prepare_win11_bitlocker_working_overlay.py` has a
default read-only `plan` mode and explicit `--mode create` to create
exactly one new, detached disk at
`/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2`.
It requires a shut-off original master, exact current snapshot,
consistent four-layer original disk chain, intact root-private backup
layout, free space for a 64 GiB growing overlay plus 30 GiB reserve,
and refuses any pre-existing overlay destination. It does not change
domain XML, snapshot metadata, UEFI NVRAM, swtpm state or BitLocker.
CI mocks verify that unexpected backing dependencies trigger refusal
and cleanup of the unfinished new file.

**Still blocked:** defining/starting the maintenance guest,
any TPM/UEFI restoration, changing guest NIC, and BitLocker decryption.
Those require separately reviewed original-domain XML update,
strictly disconnected guest NIC, and a genuine manual recovery plan.
A copied TPM backup is not a proven recovery procedure, particularly
without the recovery password.

Relevant upstream references:
- https://www.qemu.org/docs/master/tools/qemu-img.html
- https://www.libvirt.org/manpages/virsh.html

## Working maintenance overlay created — 2026-10-09 22:36 UTC

The operator uploaded `CAPE_Win11_Working_Overlay_20261009_223658_bjsYVWBj.txt`.
The guarded host command returned `FINAL_EXIT_STATUS=0` and reported
`WORKING OVERLAY CREATED SUCCESSFULLY`.

- New detached COW overlay:
  `/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2`.
- Expected source backing image:
  `/var/lib/libvirt/images/win11.finalshutoffversion`.
- `qemu-img check` and backing path validation passed.
- The original master remained shut off, cold snapshot unchanged,
  source top disk pointer unchanged, original TPM/NVRAM/network
  unchanged, and BitLocker remains enabled.
- The new overlay is **NOT yet attached** to `win11`. Do not boot it
  in a new VM or with a different virtual TPM.

### Next review gate before any maintenance boot

A temporary maintenance domain must preserve the **same original
win11 libvirt UUID, emulator TPM pairing, and original OVMF NVRAM
path**, redirecting *only* the writable disk to this working overlay.
For fail-closed network containment, **remove the guest network
interface entirely** from its temporary domain definition, not just
link-down on the NAT-connected interface; inspect the readback of
the proposed/offline and actual domain XML before guest start. The
original backed-up domain XML restores the original NIC later.

Do not use `virsh snapshot-revert` as a generic rollback mechanism:
snapshot revert is a destructive operation and its compatibility with
SSL-55 external snapshots has not been demonstrated. A defined,
offline XML redefinition must have verified restoration to the
original backing disk/NIC and must keep the VM shut off on failure.
Backups of TPM/NVRAM were bytewise verified locally, but actual
Windows unlock after firmware/TPM state restoration has **not** been
tested and cannot be guaranteed without a recovery password.

The next requested host action should be **read-only offline
maintenance XML-delta validation only**. No guest definition, boot,
BitLocker decrypt, or new network should occur in that check.

## Maintenance XML plan obstacle and approved resolution — 2026-10-09 22:40 UTC

The operator ran a read-only in-memory maintenance XML preflight and
uploaded `CAPE_Win11_Maintenance_XML_Plan_20261009_224049_4lNl5ao0.txt`.

- **PASSED:** original libvirt definition equals the local protected
  XML backup.
- **PASSED:** current snapshot metadata equals the local protected
  snapshot XML backup.
- **PASSED:** the detached maintenance disk's **five-layer** QCOW2
  chain (one new overlay plus four unchanged master layers).
- **BLOCKED SAFELY:** `Additional host-connected device requires
  review: redirdev`. The block occurred before any VM mutation.

The libvirt `redirdev` element represents host/client USB redirection,
typically `bus='usb' type='spicevmc'`; no USB redirect is required for
BitLocker maintenance. See
https://www.libvirt.org/formatdomain.html#redirected-devices and
https://spice.pages.freedesktop.org/spice-space/spice-user-manual.html.

The revised pure offline transformation,
`scripts/plan_win11_maintenance_xml.py`, retains the master name,
UUID, existing NVRAM path, and emulator TPM while selecting the already
created maintenance QCOW2 and **removing** the single NAT NIC,
`redirdev` USB redirects, optional `redirfilter`, and guest-integration
`channel` elements from the **proposed XML only**. Unexpected external
USB redirection types, host-device passthrough, filesystem-sharing,
VSOCK and externally bound graphics are fail-closed and require review.
The original domain XML stays in the private preservation backup.

GitHub CI covers expected SPICE USB redirection removal,
original UUID/NVRAM/TPM preservation, and negative fixtures for
non-SPICE USB, pass-through, extra NIC, nonlocal graphics, unusual disk
sources and QEMU command-line modifications. **This does not yet
authorize an actual redefinition, boot, Windows unlock, or decryption.**
The operator should run one revised **read-only** host validation and
return the output so we can confirm no additional host-connected
devices are present on this machine.

## Offline definition rollback report (2026-10-09 22:50 UTC)

The SSL-55 host report confirms that the inactive maintenance domain definition was accepted, contained no network interface/USB redirection/guest channels, and was immediately returned to the original backed-up definition. Current cold snapshot and TPM/NVRAM metadata remained unchanged; no Windows boot or BitLocker operation occurred. This proves an offline *domain-definition* roundtrip, not actual BitLocker recovery.

An additional development-only guarded startup component was drafted at `scripts/start_win11_isolated_bitlocker_maintenance.py`. It stages the same original-TPM/no-network working-overlay definition, checks the live domain while paused, and resumes Windows only after validation. It does not decrypt Windows. This new startup code has not yet been tested on SSL-55; all host deployment remains subject to review.
