# Command 2 — SSL-55 win11_1 snapshot decision (real host report)

**Observed:** 2026-10-12, operator-supplied
`CAPE_Command2_Win11_1_SnapshotReadiness_20261012_110035.txt`.
This is a completed READ-ONLY inventory, not a snapshot or firmware change.

## What SSL-55 actually has

- Libvirt daemon/library **11.1.0**; QEMU **9.2.2**.
- Independent `win11_1` (UUID
  `732b2256-ee99-41fa-881d-fbf5c476d960`) **RUNNING**;
  both protected `win11` and `win11_trial_1` **SHUT OFF**.
- One standalone Windows system QCOW2, virtual size 64 GiB; RAW
  `win11_1.command2_VARS.fd` **540,672 B**.
- swtpm2 private `tpm2-00.permall` **9,234 B**.
- No snapshots: `virsh snapshot-list --name` returned `[]`.
- Existing prior full cold backup **manifest present**; captured bundle
  previously SHA256 checked, but **restoration not witnessed**.
- Host free space **64.74 GiB** at report capture, shared-host reserve
  **40 GiB**. No additional full Windows clone or same-size cold-copy
  permitted under this reserve.
- Actual Linux bridge configuration+one TAP and benign Windows targeted
  IPv4/IPv6 negatives passed in earlier reports. End-to-end L2 peer
  packet test and full firewall packet negative path are still pending.
- Snapshot decision flags:
  `RAW_PFLASH_VARIABLE_STORE`,
  `SWTPM2_ATOMIC_CAPTURE_AND_REVERT_UNPROVEN`,
  `NO_VERIFIED_RUNNING_REVERT_CYCLE`.
  `snapshot_capture_attempted=false`,
  `running_snapshot_ready_for_cape=false`,
  `host_guest_modified=false`.

## Verified technical constraints

Libvirt v10.9 added internal live snapshots for UEFI guests with **QCOW2
NVRAM**, with reversion fixes in v10.10. SSL-55's daemon v11.1.0 and
QEMU v9.2.2 clear conservative version floors. **RAW pflash is still
unsupported for that native running-snapshot path.** emulated TPM2
state resides outside ordinary Windows QCOW2 storage; QEMU swtpm
migration facilities alone do **not** attest that libvirt
`snapshot-revert` restores TPM state. A libvirt snapshot's XML
`state=running` + internal RAM/disk is required but insufficient
to certify a repeatable complete Windows revert.

Primary sources:
- https://libvirt.org/news.html (v10.9 and v10.10 UEFI fixes)
- https://www.libvirt.org/manpages/virsh.html (snapshot/revert loss)
- https://www.qemu.org/docs/master/specs/tpm (swtpm QEMU migration)
- https://capev2.readthedocs.io/en/latest/installation/guest/saving.html

## Engineering committed on development after this report

The OTHER-HOST-only, fail-closed snapshot experiment now includes:

1. `scripts/command2_disposable_nvram_qcow2_prepare.py`: verify exact
   SHUT-OFF test clone, immutable complete disk+RAW OVMF+swtpm backup
   hashes with reviewed manifest SHA, no existing snapshots, and
   private headroom. Typed approval creates a **new and distinct**
   QCOW2 sidecar via `qemu-img convert -f raw -O qcow2`, then
   `qemu-img check` and exact `qemu-img compare`. Preserves
   original RAW file, disk, TPM, libvirt XML and VM state.
2. `scripts/command2_disposable_nvram_qcow2_activate.py`: separately
   require prior actual witnessed full cold disk/NVRAM/swtpm restore
   and Windows TPM/Agent boot on the disposable host, plus verified
   QCOW2 sidecar bytes, exact single isolated NIC and snapshot-free
   SHUT-OFF guest. Typed approval saves **original inactive domain
   XML** to a non-replaceable 0600 file, then defines exact revised
   saved XML with `nvram format=qcow2`, using the new sidecar.
   No boot, snapshot, swtpm, VM disk, firewall, or network changes.
   Interrupted/partially successful steps require inspection, not
   blind reruns. Post-change Windows boot remains unproven.
3. `scripts/command2_native_snapshot_stack_guard.py` and
   `scripts/command2_running_cape_snapshot_gate.py` now allow a
   separately reviewed `win11_N.command2_VARS.fd.qcow2` actual
   NVRAM path, but refuse RAW and require independently pinned
   full recovery, recent daemon/QEMU versions, guest CAPE Agent
   and offline acceptance evidence before any operator-approved
   running capture on that OTHER host.
4. `scripts/command2_running_snapshot_batch_gate.py` now refuses
   CAPE machine registration if **any** guest is still configured
   for RAW OVMF or points at the dormant original .fd rather than
   the active .fd.qcow2. Native running memory+disk snapshot and
   real repeated TPM/UEFI/Agent/network reversions remain mandatory
   **for every VM**, including the eventual SSL-55 clone.
5. Synthetic GitHub Actions suites test protected reference-host
   refusal, root-owned source and approval guards, untouched RAW
   file, no guest start, sidecar source/destination collision, missing
   TAP isolation or TPM restore witness, and no snapshot-release
   bypass by an unused QCOW2 file. These are offline tests only.

## Physical acceptance sequence — separate second KVM machine first

Use the spare machine with adequate free disk and a disposable
Windows 11 analysis VM. Stage with zero NIC, isolated network, unique
UUID, MAC, IP, private swtpm; install/test trusted Windows bootstrap.
Cold shutdown; create/hash full disk+OVMF+swtpm recovery bundle;
**restore to disposable VM and verify Windows+TPM+Agent first.**
Only then prepare sidecar and, after separate approval, switch
the OFFLINE test VM to QCOW2 OVMF XML. Boot; confirm Secure Boot,
BitLocker, TPM, Agent, isolation, and no unexpected network egress.
With explicit approval and fresh full-state backup, capture
`cape_ready_win11_1` while guest RUNNING. Shut off after snapshot;
test at least two real benign CAPE-style reverts with Windows/TPM/
UEFI and network verification. Repeat for `win11_2`. No samples.
The normal CAPE KVM machinery starts from SHUT OFF and reverts to
RUNNING saved snapshot; both metadata and reality must match.

**If swtpm/UEFI rollback fails:** STOP. Design and test a custom
same-epoch disk + OVMF + swtpm + running-RAM CAPE reset adapter.
Do not pretend a disk-only/RAW snapshot satisfies CAPE.

**Only after both disposable hosts' VMs prove full revert stability:**
review a separately guarded, cold/shutoff SSL-55 win11_1 transition
with existing backup protection. No live OVMF format conversion,
no force snapshot/revert on SSL-55, and never touch original master.
Command 2 is NOT production-ready until the end-to-end two-VM
CAPE + INetSim benign analysis and reset acceptance is witnessed.

## Status of implementation/tests for this decision

Development reference as of 2026-10-12: GitHub Actions workflow run
**38241761244** passed **both** the full Python offline test suite and
Windows PowerShell syntax, after hardening the disposable XML transition.
The tested code does **not** create a snapshot, boot any VM or change the
SSL-55 host. No second-host hardware validation has yet taken place.

The saved-XML transition now durably fsyncs its original XML backup
directory, uses `virsh define --validate`, and checks afterward that
the exact clone disk, isolated NIC, swtpm2 and shut-off state are retained.
Its recovery witness is operator-recorded evidence rather than a
cryptographically authenticated hardware TPM snapshot. Neither the
sidecar conversion nor XML switch is a substitute for real revert tests.

The portable count-driven initial stager still emits RAW NVRAM. This
requires intentional integration of QCOW2 from the beginning for
compatible disposable target hosts *after* physical validation.
Do not represent individual helper scripts as completed Command 2.
