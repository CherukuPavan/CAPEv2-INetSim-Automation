# CAPEv2 + INetSim Automation

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
> The routing writer and five-service restart executor are **not**
> automated yet. Commands 1/2 installation, VM firstboot, TPM-safe
> snapshot restore and new-host integration remain outstanding. Offline
> GitHub CI passing does NOT establish portable production readiness.
> Earlier dated historical notes below, including claims that Command 3
> is locked/not started, are superseded by this updated status.

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
