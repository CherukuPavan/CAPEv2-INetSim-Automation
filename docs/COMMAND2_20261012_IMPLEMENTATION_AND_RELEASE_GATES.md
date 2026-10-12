# Command 2 implementation + production acceptance — 2026-10-12

**Development only.** No production release claim; **Command 3 remains locked**.
Only the `development` branch may change. Never use the SSL-55 pilot as
permission to run a multi-VM installation on a shared host.

## Real, witnessed SSL-55 acceptance (completed; do not re-run)

- Original `win11` UUID `289d89be-68ec-4c62-90e1-ea930849266f` and
  `win11_trial_1` UUID `e75f6fef-347d-462f-9738-4de3df6bfa74` stayed shut off.
  Preserve both, their storage sources, and the no-autostart lab policy.
- Real `win11_1` UUID `732b2256-ee99-41fa-881d-fbf5c476d960`
  boots independently from a flattened, self-contained 64 GiB virtual QCOW2.
  Both libvirt XML views are backing-free; no master image FDs remained
  in the live QEMU process; CAPE Agent v0.23 responds as administrator.
- Clean Windows shutdown created a checksum-verified cold bundle containing
  `disk.qcow2`, `uefi-vars.fd`, `tpm-tpm2-00.permall`, saved XML and
  manifest. Booting the existing original clone AFTER capturing this bundle
  succeeded. **RESTORING this bundle has NOT been tested.**
- Targeted Windows benign IPv4 and IPv6 egress test V2:
  `WIN11-1`, expected MAC `02:0a:30:6a:3f:50`,
  `192.168.240.101/24` without gateway; zero IPv4 and IPv6 default routes,
  4 separate public TCP connection attempts all `NetworkUnreachable`.
  Result `PASS_TARGETED_PROBES_ONLY`. This is **not** generalized external
  packet-path proof or inter-guest lateral isolation.
- Final host audit `CAPE_Command2_HostBridgeL2_Fixed_20261012_092812.txt`
  returned `SSL55_RUNTIME_ISOLATED_BRIDGE_POLICY_OBSERVED`:
  `cape-lab0` had only expected `vnet1`, kernel per-port isolation bit 1,
  no routable IPv6, active dedicated nftables guard with expected rule shape.
  Guest-to-guest probe is explicitly `false`.
- Current host free storage **64.77 GiB**, and the target minimum reserve
  is **40 GiB**. No second full ~30 GiB clone can be justified on this
  shared host without increasing free space or a separately approved test
  machine and admission calculation.

## Additional development code completed today

1. New `command2_portable_guest_identity_iso.py`, and unit tests, on
   `development`: takes exact, private reservation journal, per-VM JSON and
   shut-off zero-NIC VM; validates UUID/hostname/MAC/future-IP binding; builds
   one immutable `CAPE_CMD2` optical image with exactly
   `guest-config.json` and `guest-config.sha256`. **Identity phase only**:
   no network approval, no attach, no boot, no changes on SSL-55. It requires
   the **trusted SYSTEM startup task already installed in the Command 1
   master**. Only one VM per approved media operation; no batch/attach yet.
2. Portable `command2_isolated_network_xml_plan.py` now emits
   `<port isolated="yes"/>` and tests that the L2 isolation policy
   intended on SSL-55 is included in candidate isolated lab networks.
   XML by itself does not prove that the Linux kernel created isolated
   TAP ports or blocked actual peer traffic.
3. The portable stage entrypoint already guards candidate subnet overlaps
   against live target-host route/address/libvirt inventories, checks
   identity/IP collisions and re-evaluates changing resources before writing.
   It stages **zero-NIC shut-off clone definitions** on approved hosts only,
   not fully personalized, CAPE-registered analysis guests.
4. Separate guarded NIC attachment, cold bundle, running snapshot feasibility
   and CAPE configuration proposal helpers exist, but their **cross-module
   physical integration has not passed**.

## Mandatory remaining work before marking Command 2 complete

| Gate | Status | Required physical acceptance |
| --- | --- | --- |
| Fresh host dependency installer and exact total N | OPEN | Independently verified one-command preflight and count-driven staging on a supported fresh host, including real package installs where necessary. |
| Trusted Windows bootstrap | OPEN | Confirm and test preinstalled, SYSTEM-on-startup `command2_guest_startup_autoconfig.ps1` in a safe golden Command 1 Windows master; confirm UUID matches and config ISO is actually attached/read. |
| Unique IDs / guest network | OPEN | Boot two approved clones concurrently on a separate host with different Windows hostnames, libvirt UUIDs, firmware state, swtpm state, MACs and static IPv4 with no external gateway. |
| IPv4/IPv6 + lateral isolation | PARTIAL | Test real two-guest L2/IPv4/IPv6 negative paths and the intended CAPE/INetSim positive service paths, plus reboot persistence; verify no unrelated LAN/Docker/libvirt flows are altered. |
| Cold bundle restore | OPEN | Restore the whole independent disk + OVMF VARS + swtpm state to an approved disposable guest, then boot and verify its identity, network, BitLocker compatibility and CAPE Agent. Never overwrite the SSL-55 master. |
| Running snapshot + revert | BLOCKED | Real hardware proof of coherent Windows RAM + disk + OVMF VARS + swtpm rollback; or a separately engineered, CAPE-compatible cold-reset machinery. Neither is currently proven. |
| CAPE N-machinery and parallel benign analysis | OPEN | Correct snapshot mapping in `kvm.conf`, agent reachability and two simultaneous approved harmless sample jobs, with deterministic reset between submissions. |
| Portability and release | OPEN | A new supported host with adequate storage/RAM and an approved template; full end-to-end witness logs and safe interrupted-run recovery testing. |

## TPM / UEFI snapshot constraint

Current SSL-55 runs RAW OVMF pflash VARS and an independent swtpm state
file. A standard libvirt snapshot of disk and guest RAM is NOT automatically
proof that both independent state stores revert atomically. In 2024,
libvirt required QCOW2 NVRAM for newly supported internal pflash snapshots.
In 2020 libvirt maintainers specifically stated TPM state was not managed
as part of libvirt snapshots; QEMU describes separate swtpm migration
support. Feature existence does not attest a working CAPE snapshot/revert
on this hardware. Never change the original master to force a snapshot.

References:
- https://capev2.readthedocs.io/en/latest/installation/guest/saving.html
- https://www.libvirt.org/manpages/virsh.html
- https://www.qemu.org/docs/master/specs/tpm
- https://lists.libvirt.org/archives/list/devel%40lists.libvirt.org/message/KGYWRVJ3MV6PTQU5MZ6ALNSM4STGDEVQ/
- https://lists.libvirt.org/archives/list/users%40lists.libvirt.org/message/ONDDG6TMLDDISRAWV7SMADP53FOCAU5L/

**Operator rule:** do not proceed to unknown live snapshot/revert,
bulk clones or malware from the passing single-VM checks. At least one
separately approved physical host and security/rollback acceptance are
still required. Offline green CI is not a deployment certificate.


## Additional concrete CAPE machinery compatibility finding (2026-10-12)

The upstream CAPEv2 `modules/machinery/kvm.py` delegates the analysis-start
operation to `LibVirtMachinery.start()`. The upstream
`lib/cuckoo/common/abstracts.py` implementation selects a configured
libvirt snapshot and executes `vm.revertToSnapshot(snapshot, flags=0)`,
then waits for the guest to become RUNNING. That is why merely setting a
guest's IP/hostname or producing a cold backup cannot make a CAPE machine
ready for repeated analysis.

CAPE's own guest-saving documentation also requires capturing the prepared
guest with its agent running before relying on that snapshot. The VM's
existing RAW OVMF pflash VARS and swtpm2 persistent state are distinct
from ordinary disk+RAM. Libvirt release notes specify that internal UEFI
pflash snapshots require QCOW2 NVRAM; even then the swtpm revert semantics
must be independently demonstrated. No production-ready CAPE reset may be
inferred from offline green CI or a merely present snapshot label.

**Acceptable development next paths on the disposable, approved second host:**
(a) prove a specific compatible hardware/firmware+TPM arrangement actually
handles repeated running-memory/disk snapshot/revert and guest state,
**without changing the SSL-55 master**, or (b) engineer and test a separate,
explicit CAPE machinery adapter for restoring the complete cold disk +
OVMF + swtpm state prior to EACH analysis. Generic KVM `kvm.conf`
registration MUST remain gated until one path passes repeated harmless
analysis cycles. The latter adapter is a substantive Command 2 deliverable,
not a simple config toggle.

CAPE references:
- https://capev2.readthedocs.io/en/latest/installation/guest/saving.html
- https://github.com/kevoreilly/CAPEv2/blob/master/modules/machinery/kvm.py
- https://github.com/kevoreilly/CAPEv2/blob/master/lib/cuckoo/common/abstracts.py
- https://libvirt.gitlab.io/libvirt/news.html (libvirt v10.9.0 UEFI snapshot update)


## Mandatory FINAL running snapshot gate for EVERY Command2 VM

**Operator requirement (2026-10-12): CAPE must use a running guest snapshot
at the END of Command 2, per individual clone, not one shared snapshot.**
The snapshot phase may begin only after all that clone's identity, single
isolated NIC, static IP, CAPE Agent, no-egress tests, firmware/TPM state,
cold restore and network-reboot persistence gates have passed.

Development implementation:

- The pure `command2_portable_sequence_model.py` now has mandatory
  `RUNNING_CAPE_SNAPSHOT_REVERT_VERIFIED` between
  `COLD_CHECKPOINT_RESTORE_VERIFIED` and
  `READY_FOR_APPROVED_BENIGN_ANALYSIS`. It demands a running memory/disk
  snapshot AND at least two actual benign revert cycles with agent,
  Windows identity/IP, isolated network, OVMF and swtpm2 state inspected.
- New `scripts/command2_running_snapshot_batch_gate.py` reads the
  target host's exact approved private Command2 identity reservation,
  checks each running VM UUID/MAC/IP/network, snapshot metadata
  `cape_ready_win11_N` with `<state>running</state>` and BOTH
  `<memory snapshot="internal">` and one internal disk snapshot.
  Every VM must have its own approved private operator revert witness
  (`COMMAND2_RUNNING_SNAPSHOT_REVERT_WITNESS_V1`) including actual
  full-state TPM+UEFI restore and repeat benign cycle findings.
  **One passing VM never certifies the other.**
- This read-only gate cannot create snapshots or make mutable CAPE changes,
  does not cryptographically attest the operator witness and NEVER claims
  a libvirt snapshot alone restores swtpm or OVMF. A successful metadata
  and witness review still requires separate CAPE parallel-analysis
  acceptance and immutable template evidence before production release.
- `command2_running_cape_snapshot_gate.py` now correctly forwards
  target-host `--subnet` to plan mode (previously hardcoded the
  default subnet inadvertently).
- The existing candidate running capture helper **already refuses RAW
  pflash internal snapshots**. Avoid bypassing this guard; QEMU's ability
  to migrate swtpm does not establish atomic libvirt snapshot/revert.
  A dedicated disposable SECOND HOST is required for an approved
  firmware/TPM strategy evaluation and full-state benign revert tests.
- Standard CAPE KVM machinery expects a libvirt snapshot to revert at
  analysis start. `command2_cape_kvm_config_plan.py` remains **proposal
  only**: do not install or activate its configuration before the
  machine's own running snapshot/revert gate is truly witnessed.

Source guidance: [CAPE saving the VM](https://capev2.readthedocs.io/en/latest/installation/guest/saving.html),
[libvirt virsh snapshot/revert](https://www.libvirt.org/manpages/virsh.html),
[QEMU TPM emulator and migration](https://www.qemu.org/docs/master/specs/tpm),
[libvirt snapshot+swtpm limitation discussion](https://lists.libvirt.org/archives/list/users%40lists.libvirt.org/message/QGU2EQQSUC6X6CGK4QPTHH2EIWMOXHOP/).


## Portable Windows network authorization media stage (development)

New `scripts/command2_portable_network_approval_iso.py` and offline tests
bridge the previously missing step between attaching ONE host-approved isolated
NIC and Windows' SYSTEM-startup static-IP personalization:

- Preconditions: exact OTHER host, root-private journal/guest configuration,
  correct clone UUID/MAC/disk, VM SHUT OFF, one `cape-analysis-isolated`
  NIC already attached, one known identity ISO in the existing CD-ROM,
  and the `COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V1` root-private
  receipt accepted by the existing NIC gate. This receipt is only operator
  evidence; it MUST reflect actual independently witnessed packet tests.
- New immutable ISO has the **same** CAPE_CMD2 label for the Windows
  startup task, embeds the original `guest-config.json`+SHA256 and new
  `network-approved.json`+SHA256 bound to the exact VM UUID/MAC/name, and
  is built in the clone's libvirt storage directory.
- Explicit typed approval; saved-CD-ROM `virsh change-media --update
  --config` only, no boot/power changes, OS disk, NAT, firewall, interface
  attachment, or unapproved network routing. The previous optical ISO
  is retained untouched. Partial results must be inspected before retry.
- The Windows startup bootstrap still must be previously installed in a
  clean approved master and proved to run SYSTEM. The new ISO does NOT
  itself configure guest IPs; when the operator separately boots the
  prepared clone, the bootstrap consumes and verifies the new media before
  invoking the previously implemented Windows NIC/IPv4 personalization.
- The proposed phase is not a substitute for independently proving actual
  IPv4/IPv6 negative egress and L2 containment on the target host. The
  production release gate remains BLOCKED until those physical checks and
  repeated snapshot/revert with TPM/OVMF both pass for each guest.
