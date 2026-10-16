# STRICT OPERATOR UX: ONLY THREE TERMINAL COMMANDS (mandatory)

**Operator re-confirmation 2026-10-14 on NEW Ubuntu host `rakshati`.**

**Acceptance requirement:** On a supported clean Ubuntu 24.04 x86_64
computer ANYWHERE (including a village computer on a different network), the
operator must paste/execute **ONLY THREE commands**, one per stage. No separate
preflight script, GitHub clone, GitHub install, rclone install, cloud
setup, recovery baseline, package install, host doctor, firmware test or
configuration editing is requested as an extra terminal command.

The previous assistant's request for a separate GitHub checkout is **NOT**
a production acceptance workflow. No source host SSH/SSL46 LAN dependence
is allowed. Internal subprocess calls or prompts within one of the three
commands are permitted; they do **NOT** count as additional operator commands.
The three commands should be easy to copy-paste directly. All background
subprocesses and dependencies must be audited and captured in one private
report for each command. Never require the user to hand-run helper modules,
edit Python/bash files, or diagnose/install packages by themselves.

## Command 1 — Fresh host + exact master

A **single operator command** with a secure, independently verifiable
bootstrap must:
- verify supported Ubuntu, arch, VT-x/AMD-V, accessible /dev/kvm, disk, RAM
  and network; detect Wi-Fi/uplink dynamically rather than copy SSL55 names;
- obtain authenticated *pinned* private GitHub implementation without
  requiring a preceding `git clone`/GitHub CLI command, install/verify
  missing dependencies automatically, and preserve a root-private manifest
  of each resource's original state and every deployment-created change;
- install CAPEv2, required database/services, supported QEMU/libvirt/OVMF/
  swtpm stack and application dependencies; INetSim is expressly DEFERRED;
- download the encrypted **exact** SSL55 master from private Google Drive,
  regardless of target geography, without Google Drive folder public access
  or personal Google OAuth login on destination. **Secure authentication
  is still mathematically necessary**: the command may prompt for a
  machine-scoped restricted service-account credential/one-time approved
  grant. It must not leak secrets into shell history, argv, logs or Git;
- SHA-verify the complete master bundle, import independent disk/UEFI/TPM
  as appropriate, boot and verify Windows/CAPE Agent, produce its new
  RUNNING snapshot and validate recoverability of disk+UEFI+TPM;
- STOP without pretending success if any indispensable step cannot be
  safely completed, especially TPM-coherent restoration.

## Command 2 — Count-driven ready clones

A **single operator command** asks the user for N additional VMs (1..16),
automatically clones the **exact** imported master into `win11_1` to
`win11_N`, independently sets Windows hostname, NIC identity, IPv4,
UEFI, storage and swtpm, validates Windows Agent and protected networking,
captures each individual recoverable RUNNING snapshot, leaves final
analysis guests SHUT OFF and provides a single final private report.
No guest identity/input/setup task, report upload, manual snapshot or
manual network command is demanded. Refuse to mark success for merely
stored snapshot metadata without benign two-cycle real TPM-safe restore.

## Command 3 — CAPE integration

A **single operator command** installs/updates exact safe per-host CAPE
configuration for the master and all N clones, correctly binds unique
IPs and running snapshot names, validates network containment and routing
without exposing analysis VM traffic via the host's real uplink, configures
tmpfs and required services, restarts once in dependency-aware order,
checks active health and optionally executes benign end-to-end tests.
No separate `--plan`, `--configure`, `--restart` or `--verify`
terminal commands demanded from the operator. Internal checks and
individual authorization prompts are allowed. INetSim is deferred.

## Repair and deployment-only rollback

The user requires undo of **only** deployment changes, not an OS reinstall
or reset. Automatic baseline/provenance journal capture must be part of
Command 1 **before any mutations**, and every subsequent mutation must
record exact ownership and a durable before/after proof. Repair and rollback
must not depend on manually running a fourth `baseline` command.
Provide convenient authenticated repair/rollback entrypoints that use the
same persisted deployment transaction and refuse deletion of preexisting or
unproven resources. Current six-config-only repair and rollback are not
equivalent to full deployment undo.

## 2026-10-15 newly confirmed release blocker: Ubuntu Noble snapshot stack

The previous plan to silently invoke distro `bootstrap_virtualization_stack.sh
--apply` cannot satisfy the existing `command2_native_snapshot_stack_guard.py`
minimums for a real RUNNING pflash/TPM checkpoint. The release guard demands
**libvirt >=10.10.0 and QEMU >=9.0.0**. Official Ubuntu 24.04 (Noble)
packages provide **libvirt 10.0.0 and QEMU 8.2.2** (even after normal
security updates). Installing them can create cold VMs, but does not pass
the project's running-snapshot version admission.

A new no-write `scripts/command123_hypervisor_release_compat.py` checks
actual APT candidates and fails before attempting full-snapshot installation.
A new `--require-snapshot-stack` opt-in on
`scripts/bootstrap_virtualization_stack.sh` invokes this gate **before**
any APT changes. Never relax the minimums merely to make a CLI return zero.
Even future APT candidates meeting the version floor are **not approved**
for installation on Noble until a compatible, signed/pinned source and
reversible deployment provenance have been established. Candidate version
strings alone cannot authorize arbitrary PPA or mixed-Ubuntu-release APT
packages. The current full-snapshot gate deliberately exits nonzero.

Complete Command 1 must choose and implement a pinned, validated compatible
hypervisor source build OR an independently proven TPM-consistent running
checkpoint mechanism compatible with Ubuntu packages. The former's upstream
installer rewrites host packages, services, boot policies and dependencies
and cannot be invoked blindly without cross-command rollback attribution.
The latter must demonstrate real benign two-cycle restoration before
registering the resulting guest with CAPE.

Neither the presence of `/dev/kvm` on `rakshati` nor 1,500+ offline
regression tests can close that physical and integration gap.

## 2026-10-16 Windows TPM Platform Crypto Provider challenge

The disposable two-cycle sequencer now optionally accepts
`--prove-tpm-key`. It uses
`scripts/command2_disposable_tpm_key_marker.py` to create only a fixed,
nonexportable named CNG key using Windows' **Microsoft Platform Crypto
Provider** on the approved isolated disposable clone after snapshot
capture. After each real running-snapshot revert it queries the same
provider and refuses if the named key is still present. For a second
cycle it creates the fixed key again and verifies disappearance again.
The challenge NEVER clears a TPM, deletes an existing key, changes
BitLocker/Defender or exports any TPM secret. Pre-existing keys block
creation. CI tests cover unsafe guest IPs, exact fixed commands, response
validation, two cycles and failure to restore.

Important limitation: Windows may store Platform Crypto Provider key
metadata in its OS disk; restoring the disk alone can make a named CNG
key appear absent without proving swtpm's permanent or volatile state was
restored. Thus this is extra **guest-visible evidence**, not sufficient
proof of atomically restored swtpm TPM2 permanent+volatile blobs and
QCOW2 OVMF variables, or physical network containment. The
`TPM_UEFI_full_state_revert_proven`, `safe_for_malware` and
`production_ready` fields remain **false**, including on successful
synthetic CI. Real TPM-blob paired capture/replay acceptance is still
mandatory before final command release.

## 2026-10-16 disposable snapshot two-cycle implementation — NOT production acceptance

The development branch now includes
`scripts/command2_disposable_two_cycle_revert.py`, an operator-approved
two-cycle **actual** libvirt running-snapshot revert sequencer for one
disposable, independently validated Windows clone. Each cycle calls the
existing guarded restore and Agent health check, then requests a graceful
Windows shutdown without force. A new optional
`--prove-disk-marker` mode first boots the isolated guest and writes ONE
harmless, fixed-name marker through the existing CAPE Agent; after each
separate revert it verifies the marker disappeared. Root-private durable
receipts record partial or completed cycles and forbid blind retries.
`command2_disposable_guest_marker.py` accepts no arbitrary guest commands.

This **does not** prove coordinated swtpm persistent/volatile state and
OVMF variable rollback, Secure Boot/BitLocker key continuity or physical
IPv4/IPv6/L2 egress isolation, and it does not import the exact master on a
new host. The source VM and SSL46 backup are protected by host guards. No
physical disposable guest was operated in GitHub CI; the CI tests use
synthetic libvirt and Agent responses. Until real disposable-host tests
and TPM/UEFI continuity succeed for master and each clone, none of the
snapshot candidates authorize malware analysis or count as completion
of the strict three commands.

## Current implementation status (explicit, fail closed)

2026-10-16 implementation update: the development branch now has a
root-private host-bound active transaction pointer, durable per-file
prepare/seal receipts, a synthetic-test-covered missing-file repair and
guarded file rollback, and an APT prerequisite component recording
whole-dpkg before/after package snapshots. The partial Command1 base
prerequisite flow and the partial Command3 configuration flow can resolve
the active transaction internally. **This is NOT a deployable three-command
installer**: there is no vetted full install/VM/snapshot/routing/TPM
sequence, no deployment-wide package/VM/network undo, and no second-host
benign running-snapshot restore acceptance. There is no published ready
final three-command command set.

As of this specification, **THE THREE-COMMAND RELEASE IS NOT BUILT**.
There are numerous guarded subcommands and green offline tests, but:
- Command1 `scripts/command1_pre_vm.sh` is itself labeled partial:
  it does NOT install/configure the full CAPEv2 host or boot/capture the
  exact imported golden Windows master.
- Command2 `command2_exact_master_full_sequence.py` runs a guarded
  interactive sequence and has not proven TPM-coherent restored snapshots
  on a second physical host.
- Command3 `command3_from_operator_reference.py` needs separate modes
  to configure/restart, and unsafe Internet/virbr0 routing is blocked.
- Private GitHub and private crypt Google Drive inherently need
  authentication. The worldwide crypt reader helper currently needs a
  separately provisioned service-account key; it is **not** transparently
  bootstrapped from a truly clean host with no authorization setup.
- No complete cross-command resource ownership journal and
  deployment-only rollback implementation exists.

Until **all** these are implemented, a command advertised as
`three-command finished` would mislead. Offline code tests or the
hardware preflight on `rakshati` do not constitute deploy acceptance.
Never tell the operator to execute unreviewed partial installers as
the production 3-command solution. Do not modify SSL55/SSL46, their
protected Windows masters/snapshots, or GitHub `main`.
