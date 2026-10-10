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

## First isolated original-TPM Windows maintenance boot succeeded — 2026-10-09 22:58 UTC

Operator uploaded `CAPE_Win11_Isolated_Maintenance_Boot_20261009_225805_suxbkrGs.txt`
and confirmed the Windows 11 desktop/login screen appears in virt-manager.

Host log confirms:
- Temporary inactive maintenance definition accepted with no guest NIC.
- QEMU initially started paused, live XML was validated with **no network
  interface or USB redirection**, and Windows was resumed.
- Result `ISOLATED_MAINTENANCE_VM_RUNNING`.
- Working disk is
  `/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2`,
  backed by the unchanged original cold QCOW2 chain.
- Original virtual TPM and NVRAM pairing retained. The maintenance
  domain is **still defined**, so do not restore the original definition
  while the guest is running.
- No BitLocker changes were performed by the host script.

Next guest-side gate (read only): operator logs into Windows, opens
**elevated Command Prompt** and runs `manage-bde -status C:` to check
Conversion Status, Percentage Encrypted, Protection Status, and Lock
Status. No `manage-bde -off` until the user reports these values and
the decryption/write-capacity plan is confirmed. Do not request or
upload any BitLocker recovery key, TPM contents or private state.

**Critical state:** `win11` is now running **in maintenance mode**.
Do NOT reboot into NAT, restore the original libvirt XML live, run a
snapshot revert, delete the maintenance overlay or forcibly halt the
VM. The local root-private preservation backup remains intact.
Windows desktop appearance indicates TPM unlock may have succeeded
but does not yet establish the C: volume's actual BitLocker state.

## BitLocker fully decrypted on the maintenance overlay — 2026-10-10

The user provided a screenshot of Windows `manage-bde -status C:` inside
the still-running **no-NIC**, original-TPM maintenance guest:

- `Conversion Status: Fully Decrypted`.
- `Percentage Encrypted: 0.0%`.
- `BitLocker Version: None`.
- `Encryption Method: None`.
- `Protection Status: Protection Off`.
- `Lock Status: Unlocked`.
- `Key Protectors: None Found`.

**This is the guest-side completion evidence only.** The Windows machine
must be cleanly shut down before the Linux host reads or exports the
working image. Use a full Windows shutdown, `shutdown /s /t 0`, to
avoid Fast Startup/hybrid-hibernated NTFS. If it is already shut off,
do not start it again just to execute that command.
Microsoft documents full Shutdown.exe semantics:
https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail

The original four-layer encrypted master must never be overwritten,
committed, snapshot-reverted or used as the decrypted template.
`win11_1.qcow2` remains a distinct earlier encrypted copy.

The new `scripts/export_decrypted_maintenance_template.py` runs after
the guest is completely shut off. Its `--mode plan` performs a
read-only, fail-closed check of the existing snapshot and maintenance
XML, five-layer backing chain, crypto/NTFS boot-sector signature,
secure output directory and available space. Its separate, explicitly
authorized `--mode export` converts only the fully shut-off decrypted
maintenance overlay into the independent,
root-private `win11_decrypted_template.qcow2`. A second offline
crypto probe verifies the new flattened image has plaintext NTFS
before publishing it; source and master QCOW2 layers are fingerprinted
for unexpected concurrent modification. The template **does not**
contain a usable independently paired original TPM and is not yet a
personalized or verified CAPE analysis VM.

**As of this screenshot the VM shutdown, cold cleartext probe, export,
and final master definition restoration have not yet been confirmed**.
Do not mark Command 1 or Command 2 complete.

## Cold template export first attempt safely blocked — 2026-10-10 16:45

Operator uploaded `CAPE_Decrypted_Template_Export_20261010_164551_IUGydwjs.txt`:

- `PASS: Five-layer source and preserved master verified`.
- The next check failed at
  `BLOCKED: Block Incomplete disk sector read`.
- No conversion/export was started; no independent decrypted template
  was published. Master, snapshots and TPM backup remain unchanged
  by the export command.

**Cause found in the sector-probe implementation:** QEMU's
`qemu-img dd` computes the effective copy limit as
`count * block_size` before subtracting `skip * block_size`.
With `count=1 skip=1` the output image can be zero bytes. Our
previous sector reader used the conventional `dd` expectation that
count begins *after* skip. That expectation was invalid for this
QEMU behavior and resulted in the incomplete-read error.
See QEMU source `img_dd()` in `qemu-img.c` where count bounds
`size` before applying the skip offset:
https://qemu.googlesource.com/qemu/+/c28db9e0002df2abf88283b41dce0be17e8b0888/qemu-img.c

**Fix in shared `scripts/probe_cold_windows_volume_crypto.py`:**
For a window of `sectors` blocks starting at `lba`, call
`qemu-img dd bs=512 count=(lba+sectors) skip=lba`, which
requests an output of exactly `sectors * 512` bytes for the
QEMU implementation on SSL-55. Continue validating the exact
output length, GPT CRCs, Windows NTFS/BitLocker partition signature,
VM shutdown and protected source chain before exporting.
The regression mock now encodes QEMU's count-before-skip semantics,
including for nonzero GPT and partition LBAs. A complete host
integration probe is still necessary before attempting the long
standalone template export again.

**Do not interpret this blocker as Windows re-encryption.**
Windows previously showed Fully Decrypted/0.0% in the guest, but
offline plaintext NTFS verification is still required and has not
yet succeeded on the shut-off maintenance image. Do not
restart the guest or restore the original VM definition.

## Corrected offline decrypted NTFS verification PASSED — 2026-10-10 16:51 UTC

Operator uploaded `CAPE_Decrypted_NTFS_Verification_20261010_165138_aN8MkRL5.txt` (20 lines):
- Windows maintenance guest `win11` was **shut off**.
- The cold five-layer maintenance image chain verified.
- Corrected QEMU nonzero-sector reads passed.
- Protective MBR, primary GPT header and partition-array CRC passed.
- **Windows partition 3 was positively identified as plaintext NTFS**.
- `RESULT: READ_ONLY_PLAINTEXT_VOLUME_VERIFIED`.
- No VM boot, export, original-master modification or TPM change occurred.

This proves actual Linux-side plaintext readability following guest-side
`manage-bde -off`; it clears the Windows volume-encryption blocker for
making a standalone template. The original source QCOW2 chain remains
encrypted in its cold baseline; the decrypted Windows state is in the
independent COW maintenance overlay.

Next operation: **guarded cold standalone template export** to
`/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2`
using `scripts/export_decrypted_maintenance_template.py --mode export`,
or an equivalent fully reviewed local no-credential command if repository
checkout is not present. The export must preserve the four original
master QCOW2 files, original private swtpm/NVRAM backups, libvirt XML
and snapshots, must not overwrite an existing destination, and must
verify an unbacked QCOW2 + plaintext NTFS boot sector after conversion.

Success remains short of final four-command portability: the first
independent disposable Windows boot with fresh TPM/NVRAM, system identity,
static IPv4, CAPE agent, isolated network, and clean snapshot still
requires implementation and acceptance on SSL-55, then on a second
supported fresh Ubuntu machine.

## Independent decrypted Windows master template export verified — 2026-10-10 16:56 UTC

User uploaded `CAPE_Final_Plaintext_Template_Export_20261010_165626_IAA64zkw.txt`.
It confirms `RESULT: DECRYPTED_STANDALONE_TEMPLATE_EXPORTED`:

- New root-private independent flattened disk:
  `/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2`.
- **No QCOW2 backing file**; Windows source partition is verified
  **plaintext NTFS** after conversion; `qemu-img check` was run.
- Original master source files and protected TPM backup were untouched
  by the export command.
- No guest was booted and no clones have been personalized.
- The old detached `win11_1.qcow2` from earlier tests remains an
  **encrypted** standalone export and is NOT this new template.

The accepted next gate is **read-only** Windows Registry inventory from
the shut-off, trusted decrypted standalone template, using an available
free `/dev/nbdN` exported by QEMU `qemu-nbd --read-only` and a
`ntfs-3g -o ro,norecover,nodev,nosuid,noexec` mount of partition 3.
The `Windows/System32/config/SYSTEM` hive is inspected through the
installed `python3-hivex` library; output must contain only allowlisted
ControlSet/current interface GUID, static IPv4/subnet and basic hostname
fields. Unmount and disconnect on completion; no full registry,
recovery keys or TPM state may be uploaded. See new
`scripts/inspect_decrypted_template_network.py` and its fixture tests.

The existing `scripts/personalize_clone_windows.py` requires
`virt-win-reg` from libguestfs, which may conflict with SSL-55's held
custom QEMU packages. A separate tested portable clone-only Windows
customization implementation is therefore still needed; do not install
incompatible distro libguestfs packages or treat export success as
automatic hostname/static-IP provisioning.

Upstream:
https://www.qemu.org/docs/master/tools/qemu-nbd.html
https://manpages.debian.org/trixie/ntfs-3g/mount.ntfs-3g.8.en.html

## Standalone template Windows registry inspection safely blocked — 2026-10-10 17:06

The operator uploaded `CAPE_Windows_Template_Registry_20261010_170600_obPzzD1y.txt`.
The 64 GiB plaintext standalone QCOW2, no-backing property, and
read-only NBD/NTFS mount of Windows partition 3 all **passed**.
However, the inline Python Hivex inspection failed on
`node_get_value` with `RuntimeError: Success`, followed by an
attempted `.close()` that is unavailable in Ubuntu's generated
`hivex.Hivex` Python binding. The NBD was disconnected and the
command exited 1; no registry edits or template modifications occurred.

This was a script bug, not evidence of a corrupt Windows hive.
The new `scripts/inspect_standalone_windows_hive.py` uses the
`node_values` and `value_key` API to identify present optional
registry values without triggering missing-value exceptions,
handles DHCP and incomplete interface records in inventory mode,
and no longer calls `.close()`. Regression tests now simulate the
observed missing-value RuntimeError and prove graceful inventory
handling. `scripts/inspect_decrypted_template_network.py` uses this
corrected implementation.

Next host action: repeat the **read-only** trusted-template NBD +
hivex registry inventory only, verify the required Windows SYSTEM
ControlSet, static-IP interface GUID(s), subnet mask and DHCP states,
then detach NBD. No guest boot, no writeable filesystem mount,
no snapshot reversion or network changes. Do not mark clone
personalization or Command 2 complete until a disposable clone is
independently customized and boot-verified.

## Windows SYSTEM registry inspection succeeded — 2026-10-10 17:12

Operator uploaded `CAPE_Windows_Registry_v2_20261010_171228_67qcEsIP.txt`.
It verifies original `win11` **shut off**, the independent 64 GiB
standalone QCOW2 template, and a successfully read-only extracted
Windows SYSTEM registry hive. NBD `/dev/nbd0` was disconnected afterward.

`Current ControlSet = 1`. Three Windows NIC registry entries were
found: one DHCP enabled, one incomplete/unknown, and **one static IPv4**
interface with GUID
`{bd7aa820-47b9-4dd6-a85f-db3bd6d77e74}`, original
IPv4 `192.168.122.125`, subnet `255.255.255.0`.
`template_modified=false`. No guest VM boot or registry edit occurred.

**Important:** This GUID is a registry identity of the old VM.
Windows Plug and Play might create a *new* network interface GUID when
a cloned virtual NIC has a new MAC/PCI identity. Editing only this
registry key without verifying actual active guest NIC afterward would
not prove clone static-IP personalization is correct. Make a disposable
independent, **zero-NIC test clone** from the verified plaintext template,
with fresh libvirt UUID/swtpm and separate writable UEFI NVRAM, and
test independent benign boot before attaching only a reviewed isolated
network or performing targeted Windows clone-only registry edits.

Do not overwrite the existing earlier encrypted
`/var/lib/libvirt/images/cape-clones-staging/win11_1.qcow2`;
it is distinct from the exported plaintext template.
Do not reuse the original swtpm private identity or attach the clone
to libvirt's campus-connected default NAT network.

## First disposable clone stage prepared in development — 2026-10-10

A guarded `scripts/stage_first_no_nic_windows_clone.py` was created
and its synthetic XML/fail-closed tests passed in CI
(https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38071117993).

The first trial VM is named `win11_trial_1` to avoid overwriting the
previous unrelated encrypted `win11_1.qcow2`.
It is intentionally **not one of the production win11_N analysis VMs**.

Stage script:
- Confirms original master shut off, original cold snapshot metadata,
  protected private preservation backup and independent plaintext template.
- Clones `win11_decrypted_template.qcow2` into
  `win11_trial_1.qcow2` independently (no backing files).
- Initializes a separate **writable copy** of UEFI variables at
  `/var/lib/libvirt/qemu/nvram/win11_trial_1_VARS.fd`, not the original
  NVRAM file; VM UUID and Windows GenID are regenerated.
- Does NOT duplicate original swtpm private state. A new libvirt
  emulator TPM state should be initialized for the new UUID on first boot.
- Removes NIC, USB redirection and guest channels; local-only SPICE
  display. Does not connect to NAT/INetSim or start any guest.
- Creates the libvirt domain in **shut-off** state only after disk
  independent integrity/plaintext checks and preserved source stamps.
- No Windows hostname or static IPv4 personalization has yet happened.
  These are separate steps after independent benign boot and network
  identity validation.

Stage can be rerun only if no trial VM/disk/NVRAM destination already
exists; never overwrite. No VM boot until AppArmor swtpm and disk access
checks are complete, and live zero-NIC configuration is validated paused.
