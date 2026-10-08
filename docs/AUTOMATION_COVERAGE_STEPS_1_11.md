# Automation coverage ledger — canonical SSL-55 manual Steps 1–11

**Branch:** `development`. **Checkpoint:** 2026-10-08/09, before first Windows analysis VM.

## Important truth about completion

**The full production three-command installer is NOT complete.** This branch now
contains a reusable **partial Command-1 pre-VM implementation** (read-only
audit + explicit base-prerequisite bootstrap + source-clone component), legacy
auditors for the risky Step 5–7 side effects, synthetic regression tests, and a
GitHub Actions offline check workflow. Neither these new components nor the
complete flow has been run against SSL-55 or a clean host. Do not call this
production-ready or malware-safe.

We did not silently auto-run upstream `kvm-qemu.sh all` or `cape2.sh base`:
these mutate global host state and previously produced observed errors. Replacing
them with safe, idempotent, compatible installers is still a separate task.

## What the scripts implement *now*

| Manual step | Observed user action / risk | Automated component in development | Actual status |
|---|---|---|---|
| **1** | Host, CPU/VMX/SVM, interfaces; dual campus uplinks, Docker bridges | `audit_pre_vm_stages.py`, `check_host_virtualization.sh`, `discover_host_uplink.py` | **AUDIT**, no changes; selected IPv4 route is not proof of Internet connectivity |
| **2** | `sudo apt install cpu-checker -y`, msr-tools dependency; duplicate APT sources | `bootstrap_pre_vm_prereqs.sh --plan/--apply` | **CONTROLLED INSTALL** for missing cpu-checker/msr-tools on Ubuntu only; never autoremove/edit APT sources |
| **3** | `lsmod | grep kvm`; `kvm-ok`; `/dev/kvm` | `audit_pre_vm_stages.py`, `check_host_virtualization.sh` | **AUDIT**; KVM checked, guest boot not proven |
| **4** | `sudo apt-get install git -y`; root-owned `sudo git clone` | `bootstrap_pre_vm_prereqs.sh`, `bootstrap_cape_source.sh` | **CONTROLLED SOURCE BOOTSTRAP** on fresh host as intended nonroot user; existing SSL-55 root-owned checkout must not be chowned/reset automatically |
| **5** | `acpica-tools`, DSDT extracted, nine `<WOOT>` edits | `bootstrap_pre_vm_prereqs.sh`, `prepare_acpi_replacements.py`, `audit_pre_vm_stages.py` | **CONTROLLED APT + AUDIT / GUARDED PATCH DRAFT**; heterogeneous QEMU/SeaBIOS field mapping beyond four-character BXPC still blocked, no universal automatic replacement |
| **6** | Libvirt/QEMU packages; `default` NAT `virbr0`; `INTERNET_IFACE` misidentified then corrected from route-to-target; source warnings | `audit_libvirt_cape_network.py`, `discover_host_uplink.py`, `audit_pre_vm_stages.py` | **AUDIT ONLY**; avoid host-specific interface, passwords, accidental NAT/forwarding |
| **7** | `sudo ./kvm-qemu.sh all charan` (source QEMU 9.2.2, SeaBIOS, libvirt); pip/dpkg/modprobe/sysctl/GRUB/power changes and mixed APT warnings | `audit_kvm_build_step7.py`, `audit_step7_postbuild.py`, `audit_kvm_modprobe.py`, `audit_sysctl_alias.py`, `audit_step7e_kvm_policy.py`, `audit_step7f_power_policy.py`, `audit_pre_vm_stages.py` | **AUDIT ONLY**; safe host-wide install/repair/reboot module NOT implemented. Upstream `--help` itself masked sleep targets; do not blindly rerun |
| **7A–F** | Manually corrected one malformed KVM line and restored TCP syncookies; other blacklist and four sleep masks persisted | Existing six Step 7 auditors, current audit service/target readings | **AUDIT / STATE TRACKED**, no unattended global policy change; reboot persistence not tested |
| **8** | virt-manager executable 5.1.0 present, source-installed; GUI not verified | `audit_pre_vm_stages.py` | **AUDIT** executable, not GUI access |
| **9** | `virsh -c qemu:///system list --all`, network `default` transient NAT, `virbr0` no carrier/no VMs | `audit_pre_vm_stages.py`, `audit_libvirt_cape_network.py` | **AUDIT / NAT BLOCK**, no VM creation or malware-safe isolation claim |
| **10** | `sudo ./cape2.sh base`, project `/opt/CAPEv2`, MongoDB custom `mongodb.service`, PostgreSQL, CAPE auto-restarting because `cuckoo1` absent, Suricata failed; dnspython RECORD conflict; missing `*.env` glob; timezone UTC | `audit_pre_vm_stages.py`; `docs/STEP10_BASE_POSTRUN_AUDIT.md` | **AUDIT ONLY**. The full base installation was user-executed; safe idempotent replacement with service sequencing and verified rollback still **NOT implemented** |
| **11** | User installed Ubuntu Poetry 1.8.2 and optional requirements as `charan`; CAPE services use Poetry 2.5.1 under `cape`; six sampled optional packages absent in actual cape venv | `audit_pre_vm_stages.py` service-account interpreter resolution, metadata check + regression tests | **AUDIT / CORRECT USER CONTEXT**; install-and-version-compatibility resolver for cape optional requirements **NOT YET IMPLEMENTED** |

## How to use these scripts (not the final 3-command deployment)

These are **developer-stage**, user-executed operations. No commands have
been run on SSL-55 by the assistant.

```bash
# From a clone of this automation repo on development:
bash scripts/command1_pre_vm.sh audit
bash scripts/command1_pre_vm.sh plan-prereqs
# Only as an explicit installation decision:
bash scripts/command1_pre_vm.sh apply-prereqs
# Only for a fresh/owned checkout (SSL-55's ~/CAPEv2 is root-owned):
bash scripts/command1_pre_vm.sh bootstrap-source --revision <VERIFIED_FULL_SHA40>
```

- `audit`: **read-only**, one new 0600 text report in the current user's home;
  attempts account-specific CAPE Poetry checks with `sudo -n`, yielding
  **UNKNOWN** if credentials are not cached; the script never prompts for
  permission or changes its own account.
- `plan-prereqs`: read-only package inventory, new private TXT report.
- `apply-prereqs`: installs only missing `python3`, `python3-venv`,
  `python3-pip`, `git`, `cpu-checker`, `msr-tools`, `acpica-tools`.
  APT may change globally installed packages; run only by user instruction.
- `bootstrap-source`: existing legacy draft idempotently verifies an owned
  CAPEv2 checkout, or clones as a non-root user. A root-owned checkout on
  SSL-55 is deliberately **not** forcibly chowned or made globally trusted.
- All original logs and diagnostic reports must be inspected for sensitive
  contents **before uploading or sharing**; do not commit to Git.

## Implementation extension — additional code written at user's request (2026-10-08/09)

**Implemented and committed on `development`:**

| New module | Exact function | Important limitation |
|---|---|---|
| `scripts/bootstrap_virtualization_stack.sh` | Ubuntu 24.04 x86_64 distro QEMU/libvirt/virt-manager/OVMF/SWTPM package plan and explicit apply, APT simulation, checks missing packages, fails on removals/upgrades | **NOT** source-built QEMU 9.2/SeaBIOS 1.16.3 parity; skips/blocks when source-managed binaries exist, must validate CAPE compatibility |
| `scripts/install_cape_optional_deps.py` | Discovers service Python as `cape`; reports optional versions; explicit `--mode apply` calls pip resolver `--dry-run --report`; compares proposal against locked Poetry core; requires exact requirements SHA and live-service acknowledgment | This part has **not been executed on SSL-55**, does not claim a transactional rollback; an actual resolver/build/package install still requires a controlled host test |
| `scripts/audit_upstream_installers.py` | Reads actual local `kvm-qemu.sh`/`cape2.sh` contents; scans and counts risky host-wide operations, computes hashes without displaying credentials | Deliberately **cannot invoke** upstream installers because the manually observed defaults can mask sleep, change timezone/sudoers/routing, disable AppArmor, purge/pin/overwrite packages, and expose insecure credentials |
| `scripts/command1_pre_vm.sh` | Exposes `plan-virt`, `apply-virt`, `plan-optionals`, `apply-optionals`, `audit-installers` in addition to prior audit/prereq/source commands | Modular partial entrypoint; not a finished 3-command malware lab deployment |
| New regression tests | `test_install_cape_optional_deps.py` plus `test_audit_upstream_installers.py`; CI syntax and offline unittest workflow expanded | Synthetic-only; no KVM guest, CAPE service, apt apply, package resolver or live-malware containment verification |

**Latest verified offline CI:** [GitHub Actions run #37859343037](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/37859343037) completed successfully after the prerequisite-bootstrap and staged Command-1 integration updates. The Step 11 optional module now enforces the `poetry.lock` constraints file **during actual pip installation**, not just during the resolver dry run; this was covered by offline regression checks. It still requires a real-machine application test before release.

**Critical remaining Step 7 and Step 10 gap:** A **safe, idempotent, machine-portable replacement** for the custom upstream `kvm-qemu.sh all` and `cape2.sh base` routines has **not** been coded end-to-end. Replaying those original scripts is not equivalent to a production installer, given observed host-wide policy changes and packaging errors. Even though the staged aptitude and Poetry operations above are executable, they **do not** reproduce the entire manual installation yet. Do not tell the user that *each and every step is automated* until those components are implemented and independently verified.

New plan commands, run from an automation checkout on `development`:

```bash
bash scripts/command1_pre_vm.sh plan-virt
bash scripts/command1_pre_vm.sh plan-optionals
bash scripts/command1_pre_vm.sh audit-installers
```

The first two are read-only plan operations; the third reads the original script files and writes a private report. The `apply-virt` and `apply-optionals` operations are **explicitly opt-in** and must be checked against the host plan and backed-up runtime, not run blindly on SSL-55.

## Regression coverage

- **Latest confirmed GitHub Actions run:** [pre-VM checks #37857879371](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/37857879371) on `development` completed **successfully** (Python compilation, offline unittest and Bash syntax). The tests are synthetic and do NOT prove installation, fresh-host portability or guest isolation.
- New offline regression tests in `scripts/test_audit_pre_vm_stages.py` cover
  libvirt NAT/route identification, absent forwarding **without promising true
  containment**, package state, custom MongoDB unit, service-account permission
  regression (the charan-vs-cape Step 11C bug), partially absent optional
  distributions, and nonready release gate.
- `.github/workflows/pre-vm-audit.yml` defines Python compilation,
  synthetic unit tests and Bash `-n` checks. **Creation/commit of a workflow
  file is not evidence that CI ran or passed.** Verify workflow status before
  claiming test success; tests must still be executed in separate test hosts.

## Errors, ambiguity, and corresponding automation behavior

- Duplicate/mixed Ubuntu package sources: report, **do not auto-delete** or
  `apt autoremove`; fail visibly if APT itself fails.
- Host uplinks: route-to-target may select the correct interface; no hardcoded
  `eno1` / `enp0s31f6`; interface identity is **not** guest networking.
- Root-owned Git source: limited `git -c safe.directory=<exact path>` for
  read-only audit; no global Git safety disabling or ownership rewrites.
- Machine-specific DSDT / `<WOOT>` patch: do not map storage/tablet and
  other identifiers from one Dell OEM field. Patch remains opt-in and gated.
- QEMU/libvirt upstream installation errors: custom-build pinning, package
  purges/holds, firmware overwrites, sleep masks, GRUB modifications, modprobe
  blacklists, TCP syncookies and stale reboot marker require **separate
  tested idempotent modules**, not blind replay or wide rollback.
- Service state: avoid treating `cape.service`/processor failure due to
  absent configured `cuckoo1` VM as a base reinstall requirement. CAPE Web
  can be active even after a transient database race; retest at readiness
  stage. `mongodb.service` may replace `mongod.service`.
- Suricata service failure: independent unresolved issue; do not declare
  engine healthy, and do not assume Windows guest creation will fix it.
- Missing `conf/default/*.env`: glob may have no matches; check actual
  required `conf/*.conf` presence, do not blindly create credentials.
- Two Poetry versions and private home directories: resolve executable and
  package metadata **under the service account** (`cape`) instead of
  invoking-user (`charan`) checks; never reinstall optional deps into the
  wrong user venv or silently upgrade core locked packages.

## Unfinished release blockers for Command 1–3

1. Tested, idempotent **safe replacement** for the broad source QEMU/libvirt
   and CAPE base installer operations, including clean Ubuntu dependency
   bootstrap when SSL-55 already has them, error reporting and service startup
   ordering.
2. Robust machine-specific ACPI/QEMU field mapping and upstream revision
   pinning without blind `<WOOT>` edits or raw host identifiers in Git.
3. Correct CAPE service venv optional-dependency install/compatibility
   resolution, with rollback plan and version-pinned lockfile validation.
4. First Windows VM, `cuckoo1` or configured equivalent, license/media,
   guest agent and required snapshot, CPU/RAM/disk sizing and idempotent
   libvirt definition.
5. Command 2: additional parallel Windows VMs, deterministic unique naming
   and snapshots, resource constraints, CAPE machinery mapping.
6. Command 3: Ubuntu INetSim VM and its services on a **dedicated nonforwarding
   guest network**, with host isolation (including host services), no other
   guest uplinks, verified firewall/routing/DNS paths, **negative external
   and internal egress checks for IPv4 AND IPv6**, positive INetSim simulation
   checks, and fail-closed status. `default` `virbr0` NAT must never be used
   for live malware.
7. Test harness results on SSL-55 and **independent clean supported Ubuntu**
   machines, including re-runs, partial failures, absent dependencies, mixed
   repos, different hypervisors, existing Docker/other student workloads and
   rollback. **No malware until containment is proven.**

**Next session:** First review the user's Windows VM commands/GUI instructions
and select the isolated guest networking approach **before creating a
guest attached to a NAT uplink**. Re-run read-only preflight on SSL-55 when
requested. Keep all work on `development`; never promote to `main`
without user approval.
