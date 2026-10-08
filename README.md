# CAPEv2 + INetSim Automation

Private **development** work for a portable three-command malware-analysis lab:
1. CAPEv2 with one Windows analysis VM.
2. Additional Windows analysis VMs for parallel analysis.
3. Separate Ubuntu INetSim VM and **independently tested, isolated** guest network.

**CURRENT STATUS: NOT A COMPLETED INSTALLER. Do not use for live malware.**
No Windows VM or INetSim guest has been provisioned on the canonical SSL-55
reference host; `default` libvirt NAT is not a safe analysis network.

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

Each audit/plan saves one private TXT report in the user's home. Inspect reports
for sensitive site values before uploading. Use `sudo -v` separately if
you need `audit` to inspect the `cape` service account's Python venv;
noninteractive permission failure is reported as **UNKNOWN**, not a broken
installation.

`python3 -m unittest discover -s scripts -p 'test_audit_pre_vm_stages.py' -v`
runs new offline regression tests. See the GitHub workflow for CI checks.
**Neither CI success nor fresh-host/SSL-55 validation is claimed without a
result.**

## Workflow

User manually performs each SSL-55 installation step, uploads one consolidated
log/report, and the assistant reviews findings and updates the **development**
branch. Nothing in this repository authorizes unattended changes on SSL-55;
the scripts here are drafts until tested on supported clean machines. No work
on `main` without explicit approval.

See [WORKFLOW.md](docs/WORKFLOW.md).
