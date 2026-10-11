# Command 2 — guarded first cold checkpoint implementation (2026-10-11)

**Development only. Not host-accepted. Capture and restore have NOT been run on SSL-55.**

## Verified baseline

The operator report CAPE_Command2A_SnapshotFeasibility_20261010_234638_eLxaAMp1.txt
identified the exact disk, OVMF VARS and clone-specific swtpm state but did
not create a snapshot or demonstrate restoration.

Clone: win11_1, UUID 732b2256-ee99-41fa-881d-fbf5c476d960.
Windows hostname WIN11-1, Python 3.10.11 and CAPE localhost status init
were guest-confirmed after restart. Live and inactive XML had zero NICs.
cape-analysis-isolated remains inactive/non-autostart. The prior storage
audit reported only 96.11 GiB free.

**The new capture gate requires at least 104 GiB available** on the
clone filesystem: 64 GiB worst-case copy + 30 GiB free-space reserve +
10 GiB shared-host operating margin. Thus the previous 96.11 GiB would
BLOCK capture. Do not delete or overwrite existing unidentified files
to satisfy this threshold; obtain approved extra capacity or redesign.

## New code and operator interfaces

- scripts/command2_cold_checkpoint.py:
  - PLAN (default): read-only; accepts running clone; verifies master,
    trial and exact clone identities, protected original master disk and
    snapshot, zero NICs, inactive lab, dedicated disk/NVRAM/TPM names,
    private modes, and free space. Does not read live QCOW2 contents.
  - CAPTURE: typed operator authorization plus exact shut-off clone.
    Refuses concurrent clone QEMU/swtpm processes, unexpected interfaces,
    snapshots, changed master, other domains sharing the same disk/NVRAM,
    incorrect QCOW2 or insufficient storage.
    Copies **clone-only** cold QCOW2, UEFI VARS, and swtpm state files
    excluding the transient lock file. Creates a private manifest with
    SHA-256 file hashes, original ownership/mode metadata and libvirt XML.
    Validates source stability and verifies the destination hashes.
    Incomplete copies remain private for review; never auto-deleted.
    Does not shut off, restart, restore or reconnect any VM.
  - VERIFY: read-only integrity check of a private published checkpoint,
    validating manifest, hashes, XML and offline QCOW2 format/check.
    Not equivalent to a successful guest restore.
- scripts/command2_continuation_plan.py --count N: PLAN ONLY for TOTAL
  desired guest count, not additional count; preserves existing win11_1,
  refuses other unverified domains/file collisions and lists missing
  names/IPs without staging. Count 5 => missing win11_2..win11_5;
  conservative missing-clone storage budget 4*64+30 = 286 GiB.
- scripts/command2_cold_and_count_plan_acceptance.sh [TOTAL]: single-TXT
  operator wrapper, offline regressions then two read-only plans.
- 3 new Python test modules: 22 local synthetic tests passed, including
  full simulated capture->verify, partial failure, changed source,
  unexpected guest NIC, TPM symlink, resource floor, name collision.
  Additional tests reject any other libvirt domain sharing clone disk
  or UEFI VARS. This is NOT equivalent to SSL-55 verification.
- .github/workflows/command2-cold-checkpoint-offline.yml: Python
  3.10 and 3.12 development CI. Actual run conclusion must be verified.

## Strict gates and unfinished engineering

DO NOT RUN CAPTURE until the read-only plan report is accepted, adequate
resources are available, and the operator has FULLY shut down only
win11_1 within Windows. The exact swtpm state may contain secrets;
never publish the backup or TPM authentication values.

A completed cold copy is still NOT a demonstrated rollback snapshot.
Before Command 2 completion, implement a non-destructive restore
architecture with clone-only pre-restore protection and rollback,
independently test restored Windows boot, hostname, TPM, Python and
CAPE localhost status, configure isolated static IPv4 and safe NIC
mapping, persist the dedicated guard without flushing Docker/libvirt,
run IPv4/IPv6 negative egress and positive CAPE reachability tests,
validate two simultaneous guests, and accept deployment on a fresh
supported host. No malware execution is authorized.

References:
- https://www.qemu.org/docs/master/tools/qemu-img.html
- https://www.libvirt.org/manpages/virsh.html
- https://www.libvirt.org/formatdomain.html
