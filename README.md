# CAPEv2 + INetSim Automation

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

Private **development** work toward a portable **four-command** malware-analysis lab:
1. **Host + first Windows master:** discover/bootstrap the host, configure CAPEv2 prerequisites and one Windows `win11` guest through its ready-to-clone snapshot.
2. **Clone N:** ask the count, produce `win11_1`…`win11_N` with unique guest IPs and identities, verify ping/CAPE agent and per-clone snapshots.
3. **CAPE finalization/UI:** update machinery and CAPE configuration, validate/restart services, verify the web UI and analysis readiness.
4. **INetSim:** separately configure the isolated network simulation components.

**[Current four-command design and actual completion gates](docs/FOUR_COMMAND_ARCHITECTURE.md).**
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

Current SSL-55 has a `default` NAT guest network; an approved isolated
network, verified Windows Registry personalization backend, adequate disk
capacity, and post-deployment negative egress tests are missing from
the provided evidence. The script must **stop safely** in their absence,
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
