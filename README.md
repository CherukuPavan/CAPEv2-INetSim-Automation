# CAPEv2 + INetSim Automation

Private **development** work for a portable three-command malware-analysis lab:
1. CAPEv2 with one Windows analysis VM.
2. Additional Windows analysis VMs for parallel analysis.
3. Separate Ubuntu INetSim VM and **independently tested, isolated** guest network.

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
- **New partial Command-1 entrypoint:** `scripts/command1_pre_vm.sh`.
  Its read-only audit covers Steps 1–11; it can explicitly install **only**
  basic missing Ubuntu prerequisites or verify/clone the upstream source.
  It **does not** rerun broad upstream hypervisor/CAPE installers, alter
  guest/host networking, install optional Python packages or create VMs.

```bash
# Run these only from this repo's development checkout:
bash scripts/command1_pre_vm.sh audit
bash scripts/command1_pre_vm.sh plan-prereqs

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

## Workflow

User manually performs each SSL-55 installation step, uploads one consolidated
log/report, and the assistant reviews findings and updates the **development**
branch. Nothing in this repository authorizes unattended changes on SSL-55;
the scripts here are drafts until tested on supported clean machines. No work
on `main` without explicit approval.

See [WORKFLOW.md](docs/WORKFLOW.md).
