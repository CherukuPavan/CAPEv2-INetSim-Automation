# CAPEv2 + INetSim Automation

> **2026-10-16 development update (NOT a final deployment):** the
> [transaction engine](scripts/command123_deployment_transaction.py) now
> creates a root-private, host-bound active deployment ID, tracks approved
> CAPE unit/configuration files, supports guarded missing-file repair and
> file-only rollback, and automatically hands its ID to later stages.
> [Tracked base APT](scripts/command123_tracked_prereqs.py) records ALL
> installed packages (including dependencies) before/after its reviewed
> Ubuntu prerequisite install. The internal
> [Command1 base stage](scripts/command1_tracked_prerequisite_stage.py)
> can create that receipt before any APT mutation. Command3 config
> can join the same active transaction. A new
> [attested base-package rollback](scripts/command123_tracked_apt_rollback.py)
> dry-runs exact-only APT removals and refuses any drift from the sealed
> dpkg state. The [scoped recovery controller](
> scripts/command123_scoped_recovery.py) performs attested file
> rollback first, then quarantine of a pristine, deployment-owned
> [pinned upstream CAPE checkout](scripts/command1_tracked_cape_source.py),
> then removal of permitted newly installed base packages, and final
> recorded-state checks. The upstream checkout now shares the Command1
> prerequisite transaction, is pinned to an exact commit, and has local
> Git fixture tests. Quarantined source remains preserved for safe disposal;
> pure-Python integrity checks work even if APT removed Git.
> The controller refuses any VM/network/account ownership entries and
> does NOT implement full deployment-wide recovery.
> Integrated offline tests passed; the fresh-host CAPE/Windows/TPM
> running-checkpoint deployment, foreign package dependency lifecycle,
> and deployment-wide VM/network/service-state undo remain UNIMPLEMENTED.
> **No final three-command installer is approved for use.**
>
> **2026-10-16 source acquisition now physically exercised in CI:**
> The GitHub source repository is public and supports a
> [token-free pinned checkout](scripts/command123_private_pinned_checkout.py)
> with a [single-paste public bootstrap emitter](
> scripts/command123_emit_public_bootstrap.py). A new GitHub Actions job
> on Ubuntu 24.04 downloaded an exact commit via public GitHub APIs and
> verified Git blob hashes, without a GitHub token. This is **only**
> source-code acquisition; it does not unlock the private encrypted
> Windows master, install CAPE, start Windows or certify TPM snapshots.
>
> **2026-10-16 additional rollback refusal coverage:** the guarded
> [zero-NIC clone reverse-stager](scripts/command2_portable_zero_nic_rollback.py)
> now checks independent QCOW2 metadata and foreign guests' full
> backing-image chains before allowing a never-booted clone to be
> undefined. The isolated [network rollback](
> scripts/command2_portable_network_rollback.py) also refuses removal
> while any foreign domain attaches its bridge directly or kernel TAP/veth
> ports remain enslaved to it. This preserves foreign disk and network
> dependencies; it does NOT unlock booted/TPM/snapshotted VM rollback.
>
> **2026-10-15 new host final-release stop:** Ubuntu 24.04's standard
> QEMU 8.2 / libvirt 10.0 packages do **not** meet the repo's native
> running-checkpoint guard (QEMU >=9.0; libvirt >=10.10). The new
> [candidate compatibility gate](scripts/command123_hypervisor_release_compat.py)
> and `--require-snapshot-stack` option on
> [virtualization bootstrap](scripts/bootstrap_virtualization_stack.sh)
> fail **before package installation** when full-snapshot support is
> requested. Both are offline-tested, but **a safely installable modern
> hypervisor and TPM-consistent RUNNING snapshot restore remain missing**.
> The private Google Drive service-account access grant and the
> deployment-specific full rollback journal also remain prerequisites.
> **Do not give or run three purportedly production-ready install
> commands; these are not implemented as an end-to-end product yet.**
> See [strict three-command contract](
> docs/THREE_COMMAND_STRICT_OPERATOR_CONTRACT_20261014.md). Source Windows
> and cloud backups stay protected. INetSim remains deferred.


> **Operator clarification: ROLLBACK means UNDO THIS DEPLOYMENT ONLY.**
> Do not reimage Ubuntu, delete unrelated VM disks, or reset the OS as a
> substitute. The intended `repair` checks and fixes resources *created or
> changed by Commands 1/2/3*; `rollback` reverses precisely those changes,
> restoring their pre-deployment settings and leaving pre-existing apps,
> packages, VMs, networks and data intact. See the
> [deployment-only repair/rollback contract](
> docs/DEPLOYMENT_SCOPED_REPAIR_ROLLBACK_CONTRACT.md). Today the guarded
> recovery code includes a new transaction-scoped, file-only
> repair/rollback implementation, plus the earlier six-config helper.
> Base package installation is now journaled, but removal/undo of packages,
> guest disks/TPM, services' running/enabled state and network resources
> are still UNIMPLEMENTED. A full-host image is
> optional test insurance, **not** the required rollback interface.

> **New-host audit / recovery utilities (2026-10-13):** The
> [repository-wide checker](scripts/repository_static_preflight.py) scans
> every tracked Python/Bash/PowerShell/YAML file, checked local imports and
> Markdown links. Its GitHub Actions job
> [repository-wide-preflight.yml](.github/workflows/repository-wide-preflight.yml)
> runs alongside the full existing synthetic test suite.
> [Read-only new-host doctor](scripts/command123_repair_doctor.py) checks
> installed packages, CAPE configuration/services, libvirt names and
> snapshot inventory. [Guarded configuration recovery](
> scripts/command123_repair_rollback.py) supports pre-deployment baseline,
> post-deployment seal, plan-repair, approved missing-file repair,
> plan-rollback and approved reversible rollback for **SIX tracked CAPE
> config files ONLY**, using root-private SHA256 receipts and quarantine.
> [Tomorrow's test and limitations](
> docs/NEW_HOST_REPAIR_ROLLBACK_AND_TOMORROW_TEST.md).
> **DO NOT call this universal whole-machine recovery**: package installs,
> systemd changes, VM disks/TPM, network/firewall and real host backups
> require a genuine OFFLINE full-system image taken before installation.
> This repo still does NOT contain a production-ready CAPE-only full-host
> installer, does not demonstrate TPM-coherent running-snapshot revert,
> and does not automatically create a verified three-command deployment.
> INetSim is now explicitly deferred by the operator.


> **2026-10-13 VERIFIED GOLDEN BACKUP / WORLDWIDE DEPLOYMENT UPDATE**
> The operator physically exported the original customized SSL55 cold
> Windows master to private SSL46 SSHFS storage and then completed encrypted
> private Google Drive upload. `CAPE_GoogleDriveUpload_20261013_124755.txt`
> ended **exit 0**, result
> `SSL46_STAGED_MASTER_PRIVATE_DRIVE_VERIFIED`, with
> `remote_bytes_compared=true`, `local_bundle_hash_unchanged=true`,
> source Windows/snapshots untouched and **no SSL46 deletion**. This supersedes
> older below-the-fold statements that the export/upload had not occurred.
> The operator requires **worldwide, different-LAN deployment** without a
> personal Google login on target. The new
> [root-private service-account Drive reader](scripts/command1_worldwide_drive_reader.py)
> and [deployment runbook](docs/COMMAND1_WORLDWIDE_PRIVATE_DRIVE_READER.md)
> support separately authorized **Viewer** access to only an encrypted
> Drive parent, plus identical crypt password/salt. Never make the Drive
> folder public or commit service-account keys/OAuth/crypt credentials.
> The new reader's actual other-host download is not yet tested.
> **INetSim is expressly deferred by the operator** (not implemented or
> implied functional). Fresh-host CAPE installation, personalized master
> Windows boot/running checkpoint, all-N clone firstboot, swtpm-coherent
> snapshot restoration, safe routing and three-command physical acceptance
> remain RELEASE BLOCKERS. Do not run malware on default NAT or claim all
> three commands completed merely because cold backup upload succeeded.
> Do not modify source SSL55 Windows, source snapshots or GitHub `main`.


> **2026-10-16 source-access correction — READ BEFORE NEW-HOST TEST**
> GitHub currently reports this automation **repository as public**.
> Source code can therefore be fetched without a GitHub login, but every
> deployment must pin and verify an exact reviewed `development` commit,
> not execute mutable branch-tip scripts blindly. Earlier instructions
> saying the code repository was private are outdated. **This does NOT
> grant access to the separately encrypted, access-controlled Windows
> golden-master backup in Google Drive**: the target still needs an
> approved unattended key-delivery and verification mechanism. Never
> commit crypt passwords, rclone keys, OAuth tokens, service-account JSON
> or Windows images. The [private master-access handoff](
> docs/PRIVATE_DEPLOYMENT_SOURCE_AND_GDRIVE_HANDOFF.md) describes the
> additional credential and master-image restrictions.
> [SSL55 report review](docs/SSL55_REFERENCE_EVIDENCE_20261013.md) documents
> the now-confirmed 48.41 GiB free space, active CAPE services,
> unknown custom QEMU/libvirt package provenance, no proven INetSim
> service and unavailable CAPE Git SHA. The new guarded source
> [reference evidence gate](scripts/command1_reference_report_gate.py)
> and [read-only deep host fingerprint](scripts/command1_ssl55_deep_fingerprint.py)
> are designed to resolve these before export or portable installation.
> **Source export storage solution:** the actual reference `win11`
> has a 64-GiB virtual disk and 3-layer QCOW2 chain. Its existing
> 94-GiB-free exporter cannot use SSL55's 48.41 GiB free. The user
> designated **SSL46 with ~340 GiB free on the same LAN** for
> temporary staging. New
> [SSL55→SSL46 private SSHFS golden stage](
> scripts/command1_ssl46_sshfs_master_stage.py) supports
> `plan/export/verify/upload`: flatten DIRECTLY onto approved remote
> storage, then source SHA and remote byte-check/private rclone crypt
> Google Drive upload from SSL55. No original VM, snapshots or backing
> chain changes, and NO SSL46 automatic deletion. Physical SSHFS/GDrive
> staging has not yet been performed; network peer credentials and
> mounted free space remain required. See
> [SSL46 storage handoff](docs/COMMAND1_SSL46_TEMPORARY_LAN_STAGING.md).
> [One-command read-only safe-space audit](
> scripts/command1_ssl55_safe_space_audit.py) and
> [review-before-cleanup guide](
> docs/SSL55_SAFE_SPACE_RECLAIM_PLAN_20261013.md) are committed.
> No user disk files were deleted by this development work.
> Your manually configured SSL-55 master is preserved. No code changes
> below have been applied to the original reference VMs.
>
> [Full integration regression](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38373563965):
> **1,542 synthetic tests passed in each Python 3.10 and 3.12.**
> [Latest full regression](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38389652055).
> [Command3 service restart](scripts/command3_cape_restart_verified.py)
> is now a guarded, operator-approved action reachable from the joined
> [Command3 entrypoint](scripts/command3_from_operator_reference.py)
> as `--mode restart`, after five-file and mounted-tmpfs gates. Its
> routing.conf step is still review-only and requires a separate
> approved routing decision. Never claim service status proves VM readiness.
>
> [Count-driven exact-master Command2 sequencer](
> scripts/command2_exact_master_full_sequence.py) and
> [private encrypted Drive download + import](
> scripts/command1_private_master_stage.py) are guarded developer-stage
> workflows. They have NOT physically booted/verified the new-host
> Windows master, recreated its running snapshot, or demonstrated
> swtpm-consistent snapshot reset. Full fresh-host CAPEv2/INetSim
> installation remains a gap. **This is not yet an accepted unattended
> three-command release**; see the
> [predeployment audit](docs/THREE_COMMAND_PREDEPLOYMENT_AUDIT_20261013.md).

> **2026-10-13 updated operator handoff — Command 3 MANUAL REFERENCE FINISHED.**
> SSL-55 now has all seven operator-requested CAPE configuration/restart
> steps completed. The uploaded post-fix systemd report verified **all
> five services active**, with CAPE waiting for tasks after a correctly
> mounted and owned `/mnt/tmpfs`. The operator's manual work is
> **finished**; do not rerun any installers or revert protected Windows
> snapshots on SSL-55.
>
> **NEW developer-stage integration:** [one-entrypoint Command 3
> plan/configure/verify](scripts/command3_from_operator_reference.py)
> joins the five supported config editors with count-bound real KVM
> guests, strict prechecks for enabled tmpfs, root-private backups,
> durable partial-step receipts and read-only routing/service checks.
> [Command 3 joined runbook](docs/COMMAND3_JOINED_AUTOMATION_HANDOFF.md)
> and [SSL-55 evidence](docs/COMMAND3_TMPFS_STARTUP_FAILURE_AND_REPAIR.md).
> The routing writer is NOT automated; a separately approved
> five-service restart mode is now available after config and tmpfs checks.
> Commands 1/2 installation, VM firstboot, TPM-safe snapshot restore
> and new-host integration remain outstanding. Offline
> GitHub CI passing does NOT establish portable production readiness.
> Earlier dated historical notes below, including claims that Command 3
> is locked/not started, are superseded by this updated status.
>
> **NEW Command 1 encrypted golden-master transfer component:**
> [private personal Google Drive rclone crypt transport](
> scripts/command1_private_drive_bundle.py) supports review/approval
> for copying exact SHA-verified COLD Windows/UEFI/TPM bundle files over
> client-side encrypted Drive storage, avoiding a second huge encrypted
> local archive. [Design/credentials/gates](
> docs/COMMAND1_PRIVATE_DRIVE_TRANSFER.md). No Drive credentials or
> Windows/TPM data are committed or uploaded by this repository.
> Source export/storage and new-host transfer/VM import are not yet
> end-to-end tested. The new guarded
> [private download -> exact master import entrypoint](
> scripts/command1_private_master_stage.py) now combines those stages
> with independent approvals, SHA256 verification and a root-private
> partial-state witness, without guest boot or snapshot operations.
> [Command1 staged import handoff](
> docs/COMMAND1_PRIVATE_MASTER_STAGE_HANDOFF.md).
> Neither joined component is a replacement for the unfinished
> fresh-host CAPEv2/INetSim installer or TPM-safe snapshot acceptance.

> **2026-10-13 Commands 1–2 source audit (development only):**
> The exact-master Windows bundle and guarded N-clone stages exist.
> New fail-closed admission verifies plaintext/standalone cloned Windows
> source *before* identity journal mutation, and exact N stage receipts,
> NAT reservations and Windows provisioning media are now cross-checked.
> Offline CI is not physical host acceptance. Complete fresh-host CAPEv2/
> INetSim installation, full one-prompt end-to-end guest provisioning,
> safe swtpm recovery/revert and malware containment remain **unfinished**.
> The NAT profile uses stable DHCP-reserved IPv4, not a Windows
> DHCP-disabled static IP. See the [Commands 1–2 engineering audit](docs/COMMAND12_PRE_COMMAND3_ENGINEERING_AUDIT_20261013.md).
> Command 3 is now under active development (see current handoff above).
> Commands 1 and 2 are not yet production-ready. Protect SSL-55 and `main`.

> **2026-10-12 development integration:** Windows startup now supports
> approved first boot with ONE pre-attached isolated NIC after exact trusted
> source-master bootstrap + independent host isolation receipt. The clone
> verifies guest UUID/MAC and optical hashes, performs Windows hostname
> rename/restart before applying static IPv4 with NO default route. The
> guarded `approved-firstboot-batch` checks N separate receipts/VMs and
> aggregate RAM, then executes approved starts sequentially. This is not
> Windows execution evidence or snapshot completion.
> [Details](docs/COMMAND2_UNIFIED_OPERATOR_WORKFLOW.md).
>
> **Current Command 2 snapshot status (2026-10-13): NOT TPM-RESTORATION VERIFIED.**
> SSL-55's actual `win11_1` has a permanent default-NAT Windows NIC,
> unique IPv4 `192.168.122.131`, verified CAPE Agent, and THREE recorded
> running RAM/Windows/OVMF internal snapshots (latest:
> `cape_one_nat_win11_1`). These are **not** evidence of atomically restored
> swtpm state. **Do not revert them, execute malware or change the protected
> master/guest on SSL-55.** Disposable OTHER-host full-state recovery and two
> benign revert cycles remain mandatory. The guarded all-N experimental
> snapshot + final graceful shutdown stages are development-only and do not
> authorize CAPE registration. [Exact master status](docs/COMMAND12_EXACT_GOLDEN_MASTER_MODEL.md)
> and [latest handoff](docs/COMMAND2_CURRENT_HANDOFF.md). Command 3 stays locked.

> **Command 2 development milestone (2026-10-11): 262 aggregate offline tests PASS.**
> [GitHub Actions evidence](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38146877542).
> [Detailed network/Windows/CAPE running-snapshot and full-cold-restore workflow](docs/COMMAND2_NETWORK_RUNNING_SNAPSHOT_INTEGRATION.md).
> Code for guarded isolated NIC attachment, CAPE agent probing, running
> snapshot capture/revert, cold QCOW2+UEFI+swtpm checkpoint/restore, and
> 1–16 guest KVM config generation exists on `development`.
> **DO NOT deploy yet:** the trusted Windows first-boot transport and
> real separate-host firewall, guest boot, snapshot/revert and parallel
> CAPE/INetSim acceptance are not complete. SSL-55's win11_1 now has one manually verified isolated NIC,
> but NO running snapshot; this historical milestone is superseded above. Command 3 stays locked.

> **No Command 3 until Command 2 has passed every real-machine gate.**
> [Command 2 production acceptance](docs/COMMAND2_PRODUCTION_ACCEPTANCE_GATES.md),
> [SSL-55 protected master network audit](docs/COMMAND2_SSL55_NETWORK_RECOVERY_READONLY.md),
> [isolated network XML plan](scripts/command2_isolated_network_xml_plan.py).
> None of these are permission to attach a NIC on SSL-55.

> **Command 2 (2026-10-11): developer-stage zero-NIC staging engine exists,
> but the complete two-command deployment is NOT ready.**
> [Integrated count entrypoint](scripts/command2_portable_zero_nic_entrypoint.py)
> can plan and (with explicit approval on a separate supported host)
> attempt a group of shut-off, networkless clones with individual
> UUIDs, disks, UEFI state and reserved Windows configs. It does NOT
> apply Windows hostnames or static IPs, attach safely isolated NICs,
> verify CAPE/INetSim, or restore full cold checkpoints. Do not run
> staging on SSL-55. [Safety/limitations](docs/COMMAND2_PORTABLE_ZERO_NIC_STAGER.md).

> **SSL-55 is reference-only.** Do not create any additional VMs or
> storage-heavy clone copies on SSL-55. Preserve existing `win11`,
> `win11_trial_1`, and verified `win11_1`. All count-driven multi-VM
> deployment belongs on a separate approved, supported machine with
> sufficient capacity. [Current Command 2 handoff](docs/COMMAND2_CURRENT_HANDOFF.md).
> No complete portable deployer is yet approved; the new
> [fresh-host count planning model](scripts/command2_portable_fresh_count_plan.py)
> creates no VMs.
> The [portable target-host preflight](docs/COMMAND2_TARGET_HOST_PREFLIGHT.md)
> now checks KVM, memory, storage, guest-name conflicts, local IPv4
> subnet overlap and discovers the host uplink dynamically. It is
> **read-only**, not a VM installer or isolation certification.

**Canonical operator target (2026-10-12): THREE externally invoked commands.**
1. **Command 1:** supported fresh Ubuntu + CAPEv2/INetSim prerequisites, usable CAPE service and one fully provisioned, verified Windows master with an installed trusted SYSTEM bootstrap.
2. **Command 2:** ask total desired Windows VM count, create independent `win11_1`…`win11_N`, automatically configure exact unique identity/static IP with proven isolated host networking and CAPE Agent, then create and **physically verify** each own CAPE running-memory/disk snapshot plus safe UEFI/swtpm restore. The VM must be SHUT OFF when handed to standard CAPE for running-snapshot revert.
3. **Command 3:** operator-supplied final CAPE configuration/file changes, then validate complete integration. The precise INetSim application phase must be reconciled to the operator's verified manual installation and must NOT silently disappear.

**Not achieved:** the repository is still a guarded development toolkit, not three complete executable commands. In particular, Command 1 lacks automated Windows master provisioning; Command 2 lacks end-to-end Windows guest acceptance and coherent TPM/UEFI running snapshot proof, including the existing SSL-55 `win11_1` snapshot. GitHub Actions synthetic PASS is NOT a fresh-machine acceptance.
[Historical four-command architecture](docs/FOUR_COMMAND_ARCHITECTURE.md) is retained only as an earlier design record, not the current operator-approved interface.
**[Reference guide reconciliation for Commands 1–2](docs/COMMANDS_1_2_REFERENCE_RECONCILIATION.md)** records which steps from the operator's supplied PDF are substantiated, and identifies Windows 10 vs Windows 11 differences. The new acceptance report script is [`audit_command12_acceptance.py`](scripts/audit_command12_acceptance.py).

**CURRENT STATUS: NOT A COMPLETED INSTALLER. Do not use for live malware.**
SSL-55 now has a **manually configured** Windows 11 master `win11` with
external snapshots (`Afterfull` → `basicinstallwinsnapshot` → `win11.qcow2`).
The AppArmor read/lock backing-image startup repair is verified on SSL-55,
including shutdown/restart; Windows guest rollback and CAPE integration are
**not yet independently verified**. INetSim and portable multi-VM deployment
are not finished; `default` libvirt NAT is not a safe analysis network.

## What exists today (manual Steps 1–11)

- [Exact automation coverage and outstanding errors](docs/AUTOMATION_COVERAGE_STEPS_1_11.md).
- [Canonical manual evidence](docs/STEP_LOG.md) and [roadmap](docs/ROADMAP.md).
- [Portability rules](docs/PORTABILITY.md).
- [Host containment policy](docs/LIVE_MALWARE_CONTAINMENT_POLICY.md).
- **Partial Command-1 entrypoint:** `scripts/command1_pre_vm.sh`.
  Its read-only audit covers Steps 1–11; it can explicitly install **only**
  basic missing Ubuntu prerequisites or verify/clone the upstream source.
  It **does not** rerun broad upstream hypervisor/CAPE installers, alter
  guest/host networking, install optional Python packages or create VMs.

```bash
# Run these only from this repo's development checkout:
bash scripts/command1_pre_vm.sh audit
bash scripts/command1_pre_vm.sh plan-prereqs
# On the completed local win11 master, create one private read-only host
# acceptance TXT report (run sudo -v first if required):
bash scripts/command1_pre_vm.sh host-acceptance --vm win11

# Changes system packages; explicit, optional:
# bash scripts/command1_pre_vm.sh apply-prereqs

# Fresh-user-owned source only (will refuse SSL-55's root-owned checkout):
# bash scripts/command1_pre_vm.sh bootstrap-source --revision FULL_SHA40
```

## Expanded automation modules (added after Step 11D review)

The partial Command-1 entrypoint also provides these modes:

```bash
bash scripts/command1_pre_vm.sh plan-virt
bash scripts/command1_pre_vm.sh audit-installers
bash scripts/command1_pre_vm.sh plan-optionals
```

- `plan-virt` evaluates a conservative distro QEMU/libvirt/virt-manager
  installation on Ubuntu 24.04. `apply-virt` explicitly installs only missing
  packages **if** no source-managed custom builds or APT removals/upgrades
  conflict. This is not a substitute for verifying CAPE/QEMU compatibility.
- `audit-installers` scans the locally edited upstream `kvm-qemu.sh`
  and `cape2.sh` for dangerous host-policy actions **without executing either**
  and produces a private JSON report.
- `plan-optionals` detects dependencies under the **actual** `cape` service
  account using the correct Poetry interpreter. `apply-optionals` is
  explicitly gated: it verifies the requirements SHA-256, runs pip
  `--dry-run` first, blocks core `poetry.lock` conflicts, and then uses
  the service-account interpreter. Do not run it without reviewing the plan.
  An install can still fail or leave partial pip changes.

**Still not implemented:** safe idempotent end-to-end replacements for the
custom QEMU/SeaBIOS/libvirt source build and the host-wide CAPE `base`
installer. The new code does not silently invoke either risky upstream
installer. Those two substantial gaps—and real-machine testing—prevent a
claim that Steps 1–11 are fully automatable on a fresh Ubuntu host today.
See [the detailed coverage ledger](docs/AUTOMATION_COVERAGE_STEPS_1_11.md).

Plan/audit modules either create a private report or print a sanitized summary; review for sensitive data before sharing. Inspect reports
for sensitive site values before uploading. Use `sudo -v` separately if
you need `audit` to inspect the `cape` service account's Python venv;
noninteractive permission failure is reported as **UNKNOWN**, not a broken
installation.

`python3 -m unittest discover -s scripts -p 'test_audit_pre_vm_stages.py' -v`
runs new offline regression tests. See the GitHub workflow for CI checks.
**Neither CI success nor fresh-host/SSL-55 validation is claimed without a
result.**

## External-snapshot access guard (development only)

The portable, non-destructive `scripts/guard_vm_backing_access.py` handles
per-destination QCOW2 chain discovery and narrowly scoped AppArmor `rk` backing
permissions. It has plan/apply/verify modes and offline tests. It is **not**
a clone creator or a containment-qualified VM starter. Read
[the design, safety limits and integration requirements](docs/VM_BACKING_ACCESS_GUARD.md).

## Configured Windows master → clone automation (in development)

The SSL-55 operator reports a completed/hardened `win11` master, verified
Ubuntu-to-guest agent connectivity, a CAPE running-state analysis snapshot
and a separate shut-off backup. A new **read-only** master-inventory helper
records current VM/snapshot metadata, network attachments, and allowlisted
CAPE VM mapping fields in one private TXT report:

```bash
sudo -v
python3 scripts/audit_clone_master.py --vm win11 \\
  --report "$HOME/win11_master_clone_inventory_$(date +%Y%m%d_%H%M%S).txt"
```

[Cloning workflow and remaining safety gates](docs/MASTER_VM_CLONING.md).

The supplied final master inventory now establishes a current **shut-off**
clone-source candidate with four QCOW2 layers, while also detecting legacy
CAPE machine registration and a NAT guest network. New offline development
modules:

- `scripts/plan_vm_clones.py`: accepts a user-specified VM count and
  proposes distinct names, identities and optional IP allocations; it flags
  resource, snapshot, network and guest-customization blockers.
- `scripts/export_cold_master_disk.py`: read-only preflight or explicitly
  requested offline export of one independent flattened QCOW2 disk. It
  **does not** create or start a guest.
- [Complete evidence, usage, safety gates and status](docs/MASTER_VM_CLONING.md).

**Do not start clones yet.** The offline Windows guest IP editor and
per-clone firmware/TPM/snapshot/agent pipeline have now been implemented
as **developer-stage drafts**, but need physical host testing. A verified
isolated analysis network and compatibility/recovery checks remain blockers.

## Command 2 — count-driven Windows clones (development implementation)

The operator has finished the manually configured `win11` master. The
current candidate source is the powered-off `finalshutoffversion`
snapshot with a **four-layer** backing chain. Command 2 now has a
count-prompt shell entrypoint:

```bash
bash scripts/command2_clone_vms.sh --plan
# DO NOT run --apply on SSL-55 until isolated network and offline Registry
# compatibility are verified and a protected deployment profile exists.
```

The guarded development sequence covers independent cold QCOW2 exports;
offline Windows static IPv4, gateway/DNS and hostname customization;
new libvirt UUID/MAC/NVRAM/TPM identity; clone definition; benign boot;
host ping and **actual curl** CAPE agent verification; analysis snapshot;
shutdown/restart and snapshot restore/agent checks; and a **Command 3
registration handoff**. Command 2 does **not** edit `kvm.conf` or restart
CAPE services. It logs every stage and preserves existing VMs on failure.
**This flow is not yet verified on physical SSL-55 or a fresh host.**

[Full Command 2 contract, limitations and remaining SSL-55 blockers](docs/COMMAND2_CLONING.md).

Current SSL-55 still has a separate `default` NAT libvirt network, but
its existing `win11_1` analysis NIC is on `cape-analysis-isolated`.
Full portable host isolation, verified fresh-clone Windows identity transport,
adequate target-host capacity and repeated snapshot revert tests remain
unproven. The script must **stop safely** in their absence,
rather than create analysis guests with uncontrolled connectivity. No
live malware execution is authorized by these development scripts.

## Workflow

The user has completed the reference Windows master and will resume manual
CAPE finalization only **after Commands 1 and 2 are implementation-tested**.
Current work is staged and CI-tested on **development**; nothing here
authorizes unattended changes on SSL-55. No work on `main` without explicit
approval. Commands 3 and 4 remain reserved until their manual reference
procedure is recorded.

See [WORKFLOW.md](docs/WORKFLOW.md).
