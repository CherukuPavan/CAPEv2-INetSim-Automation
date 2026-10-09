# Automation roadmap (provisional)

> **LATEST CHECKPOINT — PRE-VM STEPS 1–11D (2026-10-08/09):** The partial Command-1 entrypoint now contains host/runtime audit, controlled baseline Ubuntu prereq install, source checkout, Ubuntu 24.04 distro virtualization plan/install, correctly-targeted `cape` optional Python dependency resolver/apply with Poetry lock constraints, and static risk scanner for both original host-wide installers. Automated offline regression and Bash syntax checks run on **development**. These modules are **not equivalent** to complete automatic source QEMU/SeaBIOS/libvirt or CAPE `base` replacement, and have not been exercised end-to-end on SSL-55 or a clean machine. See [coverage ledger](AUTOMATION_COVERAGE_STEPS_1_11.md). The complete CAPEv2/QEMU/VM/INetSim deployment and portability release gates **remain incomplete**. Historical sections below retain their original step-time understanding; do not interpret them as current status.


The final target is a portable **three-command** workflow, derived from user-verified manual installation rather than guessed from an existing host.

1. **Command 1:** Bootstrap necessary dependencies and deploy CAPEv2 with the first Windows analysis VM.
2. **Command 2:** Ask for the number of additional Windows analysis VMs and provision parallel CAPE analysis.
3. **Command 3:** Deploy a separate Ubuntu INetSim VM and integrate all Windows guests using a tested isolated analysis network.

Cross-cutting requirements: Ubuntu compatibility checks; resources and CPU virtualization; permissions; reproducible configuration; safe re-runs; error detection; progress logs; secrets management; network isolation; validation tests; rollback and recovery.

## Current implementation status — 2026-10-08

- Canonical manual **Steps 1–7 recorded** in `docs/STEP_LOG.md`: host/interface baseline, installation of `cpu-checker`, KVM evidence, pre-existing Git availability, and successful CAPEv2 **source checkout**. A source checkout is not CAPEv2 installation.
- `scripts/check_host_virtualization.sh` is an **initial read-only draft**, not one of the three deployment commands. It does not install packages, modify networking or configure KVM.
- `scripts/bootstrap_cape_source.sh` is a **separate draft installer component**, not a final entrypoint: detect/install missing Git on an Ubuntu host, clone CAPEv2 as the intended non-root user, verify existing checkouts without replacing them, optionally pin a full commit SHA. It has not been executed on SSL-55.
- Draft underwent Bash syntax validation and a negative-path smoke test in a separate restricted environment; it has **not** been run or validated on SSL-55. The restricted environment lacks a usable KVM device, so it cannot establish host readiness.
- APT duplicate VirtualBox repository entry warnings were observed on SSL-55. **No source changes** have been authorized or made as part of our workflow.
- **No end-to-end deployment command is implemented or validated yet.** The CAPEv2 repository was cloned manually, but CAPEv2 runtime, Windows guests, INetSim VM, parallel analysis and network isolation remain to be manually verified and automated.

- Step 4 module tests: Bash syntax check and isolated local fixture tests using simulated Ubuntu metadata (successful first clone, idempotent rerun, rejection of remote/revision mismatch). **Actual Ubuntu host, missing-Git APT path and real upstream checkout were not tested**. The user's `sudo git clone` may leave a root-owned checkout; ownership and selected HEAD require later verification.

## Step 5 — ACPI-specific installer customization (draft, 2026-10-08)

- **Manual evidence:** `acpica-tools` installed; DSDT extracted/disassembled (with unresolved external-method warning); `DELL  ` OEM ID and `Dell Inc` OEM Table ID identified; nine CAPEv2 source placeholders changed to `DELL` in SSL-55's local `kvm-qemu.sh`. No compile/run validation yet. See [ACPI_REPLACEMENTS.md](ACPI_REPLACEMENTS.md).
- **Technical finding:** Upstream script has nine different QEMU/SeaBIOS device/firmware identifiers, not nine equal ACPI OEM fields. Hardcoding one machine's DELL/895C/PNP0 is invalid; assigning an ACPI identifier to unrelated storage/tablet fields without evidence is also invalid.
- **Draft module:** [`scripts/prepare_acpi_replacements.py`](../scripts/prepare_acpi_replacements.py) defaults to read-only; verifies raw DSDT header/checksum, chooses an unambiguous exactly-four-byte BXPC candidate, requires reviewed eight-field profile, source SHA pin and external backup before opt-in patch. No host-side automatic installation or modifications.
- **Tests:** 13 synthetic tests passed. Not tested against the actual SSL-55 file and DSDT binary; no fresh Ubuntu host test. Full machine-independent device/firmware profile discovery remains **unsolved** and is a release blocker for fully unattended deployment.


- **Supplemental Step 5 references reviewed (2026-10-09):** Screenshot methods `Custom` (six characters; not an eligible four-character token), `PNP0` (generic hardware-ID prefix; not OEM), and `CBX3` (model-specific Dell table ID) added to [ACPI_REPLACEMENTS.md](ACPI_REPLACEMENTS.md). Candidate extraction now blocks known generic/virtual markers. **Five new regression tests committed** (18 in the suite); nine targeted selector cases passed independently. Full updated suite, real firmware and QEMU/SeaBIOS integration remain unverified.

## Step 6 — Libvirt installation and network safety (2026-10-09)

- Manual installation evidence shows **51 newly installed + 2 upgraded packages**, active libvirt `default` network on `virbr0`, and upstream `cape2.sh` settings changed. The initial `INTERNET_IFACE=eno1` was **corrected by the user** to `enp0s31f6`, supported by the provided destination-specific `ip -4 route get 1.1.1.1` output. The configured password is **redacted** in project artifacts; this is not proof of general Internet connectivity.
- **Safety blocker:** libvirt's default network is ordinarily **NAT**, not safe malware isolation. XML/firewall and guest-negative-connectivity evidence have not been collected; do not use it as a live analysis network. A dedicated verified isolated network must be built separately and tested before any malware analysis.
- **System warnings:** APT mixed `noble`/`focal` sources, duplicated VirtualBox entries, and invalid `/etc/modprobe.d/blacklist-kvm.conf` contents reported by libkmod. No repairs, upgrades, firewall edits or network reconfiguration authorized or executed by us.
- **Automation:** [`scripts/audit_libvirt_cape_network.py`](../scripts/audit_libvirt_cape_network.py), read-only and password-redacting; **11 synthetic tests passed**. Real SSL-55 execution, fresh-host package bootstrap, actual bridge isolation, and installer integration are **untested**. Full details: [LIBVIRT_NETWORK_STEP6.md](LIBVIRT_NETWORK_STEP6.md).

## Dynamic network discovery — Step 6 correction (2026-10-09)

- [`scripts/discover_host_uplink.py`](../scripts/discover_host_uplink.py) was added as a **read-only preflight draft**, alongside [19 synthetic unit tests](../scripts/test_discover_host_uplink.py), all passing locally. It inspects selected routes, IPv4 source, interface existence/state, default route ambiguity, VPN/container links, policy rules and explicit overrides. Committed Git blobs were checked against tested files.
- A route-to-target candidate is **not evidence of Internet reachability** or safe guest networking. The CLI never changes routes, enables NAT/forwarding, or authorizes malware guest access. Its separate-environment smoke test is **not an SSL-55 verification**.
- Dedicated libvirt network auto-discovery, non-forwarded network provisioning, CAPEv2 guest-facing configuration and cross-VM/INetSim negative-isolation verification remain **not implemented/untested**, and are required release gates. Full requirements: [DYNAMIC_NETWORK_DISCOVERY.md](DYNAMIC_NETWORK_DISCOVERY.md).

## Step 7 — Custom hypervisor build (partial, unverified)

- User ran `sudo ./kvm-qemu.sh all charan 2>&1 | tee kvm-qemu-all.log`. Supplied **9,154-line log excerpt** begins mid-QEMU build, ends after virt-manager build/install output and lacks original installer exit status. Custom QEMU 9.2.2 and SeaBIOS 1.16.3 stages completed; libvirt-python 11.1.0 was installed; `kvm-ok`/many virt-host-validate checks passed. **Overall runtime success is NOT verified**.
- Source inspection showed `username=$SUDO_USER`, while reading `$2` for username is commented out. Non-root Ubuntu user must be explicitly validated by future automation. `--help` is **not a read-only operation** in this upstream installer: global sleep-target `systemctl mask` precedes command dispatch.
- **Serious blockers:** distro libvirt packages purged/held, malformed `blacklist-kvm.conf`, pip conflict uninstalling distro cryptography, DPKG force-overwrite of OVMF/QEMU firmware, cross-release Python 2 dependencies, SeaBIOS patch/build warnings and global GRUB/sysctl/power management changes. Do **not** rerun upstream `all`, reboot or automatically repair the host.
- New read-only [`scripts/audit_kvm_build_step7.py`](../scripts/audit_kvm_build_step7.py) and [10 tests](../scripts/test_audit_kvm_build_step7.py) committed; all synthetic tests passed and the real uploaded excerpt classified `UNVERIFIED_WITH_ERRORS` (nine distinct findings). **NOT** a production installer; no runtime checks on SSL-55. See [KVM_QEMU_STEP7.md](KVM_QEMU_STEP7.md).
- Future deployment needs controlled, version-pinned and idempotent QEMU, SeaBIOS, libvirt and virt-manager stages, dependency/ownership checks, validated effective username, `pipefail`/per-stage status, strict failure handling and tested host compatibility before promotion to main.

## Cross-machine release gate

Follow [PORTABILITY.md](PORTABILITY.md) for the dependency-by-dependency bootstrap contract and the fresh-machine test matrix. Completion requires supported-OS/hardware declarations, independent clean-host testing with dependencies absent, idempotent reruns, recovery from failures, protection of existing services, and verified network isolation. **Do not claim compatibility with every arbitrary machine.**

The initial `scripts/check_host_virtualization.sh` is deliberately **read-only**. Missing packages will be provisioned by future installer/bootstrap modules **after** sufficient manual evidence and design review; absence of an optional diagnostic tool does not automatically authorize installation during preflight.

## Step 7 post-build findings — 2026-10-09

- User's follow-up report confirms QEMU **9.2.2**, libvirt system API **11.1.0**, active `libvirtd`, and KVM acceleration. This is an important basic-runtime pass, **not** a complete guest VM test.
- **Blockers:** Existing `default` network became transient (`active / autostart no / persistent no`); KVM modprobe file malformed, active `blacklist kvm`; global SYN cookie setting disabled; power-management targets masked and reboot required. Existing login has not adopted `kvm`/`libvirt` memberships. Never claim the hypervisor is safe after reboot until these are resolved.
- Added [post-build technical report](STEP7_POSTBUILD_AUDIT.md), [read-only audit script](../scripts/audit_step7_postbuild.py) and [14 passing tests](../scripts/test_audit_step7_postbuild.py). Actual report classified `REVIEW_REQUIRED`. No host modification, service restart, reboot or malware/guest-network test performed.

## Step 7 — Confirmed default NAT and persistent host security findings (2026-10-09)

- The user completed the requested final read-only diagnostics. `virsh net-dumpxml default` **explicitly confirmed NAT** (`<forward mode='nat'>`) on bridge `virbr0`. `net-info` confirmed the network is active but **transient** and autostart-disabled. **Do not attach a live-malware Windows guest to it.** The dedicated isolated analysis network and guest-side negative connectivity test remain release blockers.
- `virbr0` reported DOWN with no guests defined; this alone is **not** proof of a broken virtual bridge. Ethernet and Wi-Fi both supply default routes (metrics **100** and **600**), consistent with Ethernet as the earlier destination-selected uplink while requiring multi-route checks on fresh hosts.
- Current login has not adopted the **already configured** `kvm`/`libvirt` supplemental memberships. Malformed KVM module config (`-e blacklist kvm_intel`; `blacklist kvm`), persistent `tcp_syncookies=0` and four masked power targets remain host policy issues. The two sysctl paths may point to the same underlying file and must be checked before any authorized modification. No reboot/repair performed.
- Detailed technical interpretation and approval-gated remediation plan: [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md). This is documentation and preflight design, not an executed fix or completed automation.

## Step 7A — Verified KVM configuration backup (2026-10-09)

- User made a protected root-only backup of `/etc/modprobe.d/blacklist-kvm.conf`; `cmp` and matching SHA-256 confirm it matches the 37-byte original. Modules `kvm_intel`/`kvm` remained loaded. The first line `-e blacklist kvm_intel` is malformed, while `blacklist kvm` is a **separate valid** directive.
- **Step 7B correction is now user-executed and verified:** the protected source/backup preflight passed, only the malformed first line was commented, valid `blacklist kvm` preserved, `root:root 0644` verified and `modprobe --showconfig` parsing passed without warnings. Loaded KVM modules remained present. **No reboot/module reload; blacklist policy review remains pending.**
- See [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md). Future portable installer must inspect machine-specific policy rather than hardcode SSL-55's backup, SHA or blacklist assumptions.

## Step 7B — KVM syntax repair verified (2026-10-09)

- User's report `SSL55_Step7B_KVM_Correction_2icT1bAB.txt` shows guarded precheck, exact first-line fix, unchanged `blacklist kvm`, `root:root 0644`, successful modprobe parse and loaded `kvm`/`kvm_intel`. **Step 7B complete; wider Step 7 host acceptance remains open.**
- New read-only KVM modprobe policy checker [`scripts/audit_kvm_modprobe.py`](../scripts/audit_kvm_modprobe.py) and [14 synthetic tests](../scripts/test_audit_kvm_modprobe.py) committed, hashes matching tested files. It correctly refuses to treat valid KVM blacklisting as automatically approved, and never edits configs or certifies post-reboot loading.
- Next independent blockers: inspect the remaining valid blacklist against intended admin policy, restore SYN-cookie protections with a verified sysctl alias/precedence plan, review masked sleep targets, and use a dedicated isolated analysis network rather than existing transient NAT default. See [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md).

## Step 7C — Verified sysctl symlink identity (2026-10-09)

- User-run read-only report confirms `/etc/sysctl.d/99-sysctl.conf` is a symlink to `../sysctl.conf`, and both paths have **one identical underlying device/inode**. The single persistent `net.ipv4.tcp_syncookies=0` assignment occurs at line 77 of the canonical file and is currently active. **No correction has been executed.**
- Step 7D proposes a guarded, **approval-required** single-line update and single-key runtime sysctl change, protected by backup and no-op/abort on unexpected host state; it must preserve all unrelated sysctl settings and the alias. Never run a global `sysctl --system` or edit both pathnames independently as an automation shortcut.
- Added [`scripts/audit_sysctl_alias.py`](../scripts/audit_sysctl_alias.py) and [15 tested synthetic cases](../scripts/test_audit_sysctl_alias.py); both Git blobs equal locally tested files. Fresh-machine sysctl-source discovery and safe persistent remediation still need integration/validation. [Full details](STEP7_SYSCTL_REVIEW.md).

## Step 7D — Cancelled first attempt (2026-10-09)

The user pasted the initial Step 7D correction using `bash <<'BASH'`, which passes the shell script through stdin. The same script attempted interactive `read -r -p 'Type APPLY ...' CONFIRM` from stdin. The terminal returned **`Cancelled. No changes made.`** and the shell prompt. No backup, sysctl file change, or runtime `sysctl -w` was evidenced; **Step 7D is still pending**. The paste also displayed garbled intervening text, so syntax-checking a saved script before execution is advisable.

**Safer procedure:** write the script to a user-owned temporary file using a quoted heredoc, `bash -n` syntax-check the saved file, execute it from its path, and read explicit approval using `</dev/tty`. Verify the original expected inode, metadata, line 77, symlink target and absence of independent sysctl overrides; require a root-only byte-verified backup and full narrow-diff check before single-key `sysctl -w` at runtime. Report failure without blind retry. This is an SSL-55-specific manual recovery pattern and not a production-ready bootstrap or general host template.

The completed read-only alias review in [STEP7_SYSCTL_REVIEW.md](STEP7_SYSCTL_REVIEW.md) remains valid, but the active/persistent kernel setting should not be claimed fixed until the user provides a successful post-change TXT report.

## Step 7D — Successful guarded SYN-cookie correction (2026-10-09)

- Initial approval-prompt heredoc attempt **cancelled without change** (historical, retained above). The user then executed the corrected procedure and uploaded `SSL55_Step7D_SynCookies_20261009_032549_1d5Iozfo.txt` confirming **PASSED** preflight/config sources, matching SHA-256 protected backup and exact persistent-file transformation.
- Active `net.ipv4.tcp_syncookies` is now **`1`**; the canonical persistent configuration was also verified as `1`. Report states no reboot or service restart. **Step 7D accepted; post-reboot persistence still untested**. See [STEP7_SYSCTL_REVIEW.md](STEP7_SYSCTL_REVIEW.md).
- **Remaining blockers:** valid `blacklist kvm` rule/boot autoload policy; four masked power targets; libvirt `default` remains active/transient/NAT, not an isolated malware network; Windows/INetSim and guest negative connectivity not tested. Neither the wider hypervisor build nor three-command deployment is production-approved.
- Current [read-only sysctl alias auditor](../scripts/audit_sysctl_alias.py) has 15 prior passing synthetic tests; it is **not** an automatic repair script or a post-change SSL-55 test.

## Step 7E — Read-only KVM policy diagnosis completed (2026-10-09)

- SSL-55 user supplied `SSL55_Step7E_KVM_Policy_20261009_032931_nSxfpAHQ.txt`. The modprobe parser, loaded `kvm`/`kvm_intel`, module availability, libvirtd and normal plus blacklist-aware dry runs all passed **current-state checks**, and `net.ipv4.tcp_syncookies=1` remains active.
- The **valid** `blacklist kvm` is still configured; `options kvm ignore_msrs=Y` and `report_ignored_msrs=N` need explicit compatibility/security review. No `/etc/modules` or modules-load entry was reported for KVM; that alone is not a failure. A dry run on already-loaded modules **does not prove cold-boot loading**, so leave the blacklist and reboot decision to reviewed host policy.
- Offline read-only [`scripts/audit_step7e_kvm_policy.py`](../scripts/audit_step7e_kvm_policy.py) and [14 synthetic tests](../scripts/test_audit_step7e_kvm_policy.py) were added; results classify the real report `BASIC_KVM_CHECKS_PASS_POLICY_REVIEW` with **no reboot/malware readiness claim**. Code and test blobs matched locally executed versions.
- The next user-led stage is **read-only power-management target inspection**. Existing `default` libvirt NAT and guest isolation remain unresolved, and no Windows/INetSim guest may run live malware on the present network. Details: [STEP7E_KVM_POLICY.md](STEP7E_KVM_POLICY.md).

## Step 7F — Persistent sleep masks and operator policy (2026-10-09)

- User-run power-management audit confirmed `sleep.target`, `suspend.target`, `hibernate.target`, `hybrid-sleep.target` all persistently **masked** via root-owned `/etc/systemd/system/* -> /dev/null` symlinks; no direct `/run` overrides reported. Local upstream `kvm-qemu.sh` line 76 contains the matching `systemctl mask` command. Reboot-required marker still present.
- **Step 7F diagnostic COMPLETE**, but whether SSL-55 should be always-on or restore normal desktop sleep is an **unresolved owner/admin decision**. Do not unmask or mask automatically. No power policy changes, restart, reboot or VM operations performed.
- New [`scripts/audit_step7f_power_policy.py`](../scripts/audit_step7f_power_policy.py) and [14 synthetic tests](../scripts/test_audit_step7f_power_policy.py) committed; hashes match locally tested files. The user report classified `PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED`, and the audit cannot authorize reboot, unmasking, or guest malware execution.
- Detailed record: [STEP7F_POWER_POLICY.md](STEP7F_POWER_POLICY.md). Network-isolation and boot-survivability gates remain open.

## Shared college host — new high-priority safety gate (2026-10-09)

- The user clarified that **SSL-55 is a college machine shared by students through multiple login accounts**, not a dedicated CAPEv2 appliance. Previous dedicated-machine assumption is invalid. This does not prove which other users are active right now or whether institutional admin authorization exists.
- **Pause host-wide edits/reboots/unmasking and further invasive installs** until college IT approves the use case, existing workloads/sessions are assessed, rollback backups are reviewed and a maintenance window is agreed. Avoid disruption to student sessions and lab operations.
- **Power mask policy:** Four persistent sleep/suspend/hibernate masks affect every login. Their restoration may be appropriate for normal workstation usage, but it must follow admin-approved baseline policy and a reviewed change plan; do not leave them disabled solely for CAPE by assumption, or unmask them blindly.
- **Malware boundary:** Do not run live samples on the shared college host or default NAT; require a college-approved dedicated or explicitly segregated analysis environment, verified negative guest egress and isolation, and no risk to student/LAN resources.
- Update future three-command installer preflight to detect/ask about **shared-host designation, multiuser sessions, authorization, existing workloads, rollback/reboot impact and power-management policy**, and fail closed if constraints cannot be met. [Step 7F context](STEP7F_POWER_POLICY.md).

## CAPEv2 installation permission clarified on shared SSL-55 (2026-10-09)

- User states CAPEv2 installation under **`charan`** is permitted at the college, with prior CAPEv2 installations on other machines. **Continue** the canonical manual CAPEv2 installation/evidence workflow on SSL-55; shared student logins do not automatically bar installation. Do not repeatedly ask whether CAPEv2 installation itself is permitted.
- **Separate blast-radius gates:** Assess existing users/processes and coordinate host-wide power, reboot, service, and network changes; do not change all four masks or run disruptive upstream `kvm-qemu.sh all` again without reviewed impact. No claim that such disruptions are authorized by the installation permission alone.
- **Malware-analysis gate:** The existing transient `default` libvirt network is NAT and not malware-safe. No live malware on SSL-55/college LAN until institution-approved containment and negative IPv4/IPv6 egress tests, preferably on a dedicated host, are independently verified.
- Preserve the existing Step 7F diagnostic outcome and continue toward the three-command portable installer, which must ask/detect shared-machine constraints on future hosts.

## Confirmed live-malware operating target and containment gate (2026-10-09)

The user explicitly confirmed that the objective includes **executing real malware in CAPEv2 Windows analysis VMs**. SSL-55 remains a **shared college host with other student accounts**; user permission for installing CAPEv2 with `charan` is confirmed, but institutional authorization for **live malware execution on that shared host** has not been separately confirmed.

- Continue the reference manual build and automation design with benign tests. **Block all real-sample execution** on SSL-55 until a college-approved physical/lab deployment, a separate dedicated non-NAT INetSim analysis network, guest/host hardening, and negative IPv4/IPv6 egress tests are verified. Existing transient `default` libvirt NAT is unsafe for this purpose.
- Incorporate a first-class, fail-closed **authorization-and-containment gate** into the planned three-command workflow (first VM, additional parallel VMs, separate Ubuntu INetSim VM). Every additional Windows guest must inherit the same validated network restriction, with no unexpected NIC, route or name-resolution path.
- Prefer a dedicated lab server physically/logically segregated from normal student workloads. VM network isolation alone does not eliminate host/VM escape or management-interface risk.
- See [LIVE_MALWARE_CONTAINMENT_POLICY.md](LIVE_MALWARE_CONTAINMENT_POLICY.md) for detailed release requirements and the outstanding institutional-authorization question.

## Step 8 — Existing Virt-Manager found; no reinstall (2026-10-09)

- User's Step 8 report found `/usr/local/bin/virt-manager`, `virt-manager --version = 5.1.0` and an active `libvirtd.service`; `dpkg-query` found neither `virt-manager` nor `ubuntu-desktop` package. The source/local install provides the executable despite package absence.
- **Do not execute** the proposed `sudo ./kvm-qemu.sh virtmanager charan`: it would rerun upstream source-installer/service/schema routines on a shared college workstation and invoke unconditional top-level power-target masking. Virt-Manager installation is **functionally present at CLI-level**, but the GUI and user-system libvirt connection remain unverified.
- Next user-performed safe check: launch the existing GUI as non-root to test the `qemu:///system` connection, without installing or creating guest VMs. For fresh machine automation, use functional+provenance detection, not `dpkg` presence alone. See [STEP_LOG.md](STEP_LOG.md).

## Step 9 — Existing libvirt system network and domain inventory (2026-10-09)

- From the normal `charan` login, `virsh -c qemu:///system list --all` returned **no defined domains**, and `net-list --all` returned an **active, non-autostart, transient** `default` network. The interface `virbr0` exists at `192.168.122.1/24`, flags `UP`/`NO-CARRIER` and operational state `DOWN`. Lack of attached virtual NICs can explain NO-CARRIER; do not restart the bridge solely based on that field.
- Prior independently verified `default` network XML includes **NAT** and is therefore **NOT** a safe live-malware network. Do not persist/start it blindly, or attach Windows/INetSim sample VMs to it. Continue toward a separate nonforwarding analysis network with independent firewall/IPv4+IPv6 egress checks.
- **Step 9 diagnostic complete, no change made**; normal-user read-only virsh access works. Virt-Manager GUI access, first Windows guest, separate Ubuntu INetSim guest and network isolation are still unverified. See [STEP_LOG.md](STEP_LOG.md).

## Step 10 — Base CAPEv2 installer command started (completion pending; 2026-10-09)

- User screenshot shows `sudo ./cape2.sh base 2>&1 | tee ~/cape2-base.log` running, with apt dependency installation in progress. **No success code, terminal prompt, full log or final checks supplied**. Do not label Step 10 complete or prescribe a second installer run.
- Inspected current upstream `cape2.sh` `base` implementation (blob `1bb76ccb84b5f67ca877ad863550b63687f51e37`): dependencies, MongoDB, CAPEv2, YARA, Suricata, systemd, jemalloc and cron stages. Some stages alter timezone and system services on the shared college workstation. Actual user-edited local script not yet verified as matching upstream.
- Post-completion evidence must include `sudo` side of pipeline exit status if still capturable (`${PIPESTATUS[0]}` immediately after pipeline), `~/cape2-base.log` diagnostics, actual CAPE install path and service/timezone state. Don't upload unsanitized credentials or campus identifiers to GitHub.
- Real samples remain blocked until the **dedicated isolated, nonforwarding, negative-egress-tested** Windows/INetSim analysis network is implemented. See [STEP_LOG.md](STEP_LOG.md).

## Step 10 — Installer finished, service health still unresolved (2026-10-08/09)

- User's read-only post-run audit records `~/cape2-base.log` as 4550 lines / 286097 bytes and ends `[+] cape2.sh - Done`, with separately captured exit-status `0`. **This is not proof of all component success**; pip and Suricata errors were logged while the script continued.
- `/opt/CAPEv2` and `pyproject.toml` present; `cape-rooter` active; CAPE, processor, web services **activating**; **Suricata failed**. `mongod.service` missing, but upstream `cape2.sh` intentionally manages **`mongodb.service`** instead, so check that before diagnosing MongoDB as absent. Installer source Git ownership query raised Git safety warning; UTC host timezone detected. Missing .env glob, dnspython uninstall RECORD error and prior packaging errors require targeted inspection.
- **Do not rerun full `base` command.** Obtain one read-only Step 10B service/journal/config/package report, then fix only proven blockers and re-audit. Step 10 status **installation finished / validation pending**. See [STEP10_BASE_POSTRUN_AUDIT.md](STEP10_BASE_POSTRUN_AUDIT.md).

## Step 10B — Main CAPE service errors are missing-VM setup dependencies (2026-10-08/09)

- User-uploaded Step 10B report confirms `mongodb.service` **active**, MongoDB **8.0.32** packages installed, PostgreSQL **accepting connections**, `cape-rooter` and `cape-web` **active**. `mongod.service` missing was a **service-name mismatch**, not a MongoDB installation failure. `suricata.service` **failed** independently and its specific startup cause remains unknown.
- Journals confirm both `cape.service` and `cape-processor.service` restart because configured Windows guest **`cuckoo1` does not yet exist** in libvirt. This aligns with Step 9's empty VM inventory. Proceed with first Windows VM and correctly named snapshot **only after selecting/validating isolated guest networking**; then re-test CAPE service stability. Do not reinstall packages or restart services merely to make an incomplete-setup symptom disappear.
- `cape-web` currently active but earlier PostgreSQL duplicate-key error occurred during initialization; retest database/web after setup. `conf/default/*.env` glob had zero matches while expected core `conf/*.conf` files are present. `dnspython` pip uninstall metadata warning is an installer hygiene issue, not confirmed MongoDB runtime failure.
- **Next:** User supplies next planned manual step/command; assistant reviews it against isolation and shared-host constraints. Independently revisit Suricata failure before full ready-for-malware certification. [Step 10B evidence](STEP10_BASE_POSTRUN_AUDIT.md).

## Step 11 — Optional requirements installed, CAPE runtime interpreter check pending (2026-10-08/09)

- User already ran `sudo apt install python3-poetry -y`, installing packaged Poetry 1.8.2 and 23 dependencies; then `poetry run pip3 install -r extra/optional_dependencies.txt` successfully built optional wheels and reported packages installed. No need to repeat these installer commands.
- The user-run command created a Poetry environment under `/home/charan/.cache/pypoetry/virtualenvs/non-package-mode-...`, while upstream CAPE/processor systemd units use `User=cape` and `/etc/poetry/bin/poetry`. **Do not assume the optional packages were installed into CAPE's service environment**. Read local unit executable/user paths and inspect optional package metadata for both interpreters before deciding whether any further install is needed.
- Future portable installer must choose/verify a single **intended runtime interpreter and service account**, distinguish distribution-installed Poetry from source-installed Poetry, and never interpret a successful separate user's `pip` session as CAPE service readiness. [Step 11 evidence](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

## Step 11A — Verified separate Poetry installers; cape environment indeterminate (2026-10-08/09)

- Read-only SSL-55 evidence confirms `/usr/bin/poetry` **1.8.2** under charan, and `/etc/poetry/bin/poetry` **2.5.1** used by all three CAPE systemd services as `User=cape`. Charan's private venv has six sampled optional packages installed with versions; a `cape` venv could **not be identified by the previous diagnostic** because its command stderr was suppressed.
- Do not mistake suppressed `poetry env info --path` failure/empty output for definitive absence of the service interpreter or a broken CAPE install. A system interpreter, unusual Poetry config or permissions could explain it. **No package reinstall** without demonstrating actual missing modules in CAPE's service Python.
- Next safe manual step: one concise, read-only Step11B which shows `cape`'s `poetry env info` output, exit codes, venv create/config and `/opt/CAPEv2/.venv` status, not `poetry run` (can create virtualenv). Continue then with next user-document installation stage if no immediate blocker. [Step 11](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

## Step 11B — CAPE's valid Python 3.12.3 Poetry environment identified (2026-10-08/09)

- The user ran the requested read-only diagnostics and proved `/etc/poetry/bin/poetry` **2.5.1** under `User=cape` selects a **valid** CPython **3.12.3** virtual environment at `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12`. Poetry `env info`, `env info --path` and `env info --executable` all exited 0. The previous Step 11A failure to identify it was a **diagnostic false uncertainty**, not missing software.
- `/opt/CAPEv2/poetry.lock` exists; in-project `.venv` absent, while `virtualenvs.create=true` and in-project preference `null`. This is compatible with the discovered cache-based valid environment. The user `charan` separately installed optional packages into another Poetry environment; **parity with service runtime remains to be checked**.
- Next safe read-only check: query package metadata with `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python -B` run as `cape`. If optional packages are absent, plan *targeted* install into that venv only after review; do not reinstall Poetry or alter systemd service users. See [STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

## Step 11C — Fix diagnostic permission context, not Poetry installation (2026-10-08/09)

- Step11C returned Poetry `env info --executable` **exit 0** with the cape Python path but skipped metadata checks due to `[ -x "$CAPE_PY" ]` run under **charan**. Permission/traversal restrictions on `/home/cape` could make that false. This was a bug in the **audit**, not proven damage to CAPE Python.
- Next read-only check must validate/execute the Python binary **as `cape`** and inspect six optional package versions with `importlib.metadata`, then proceed based on actual installed-state evidence. Don't reinstall Poetry, alter owner permissions or copy virtualenvs.

## Step 11D — Confirmed optional packages went to charan rather than cape (2026-10-08/09)

- Corrected audit executed the interpreter under **`cape`**, validated its access and **exit code 0**. In the service Python venv, **all six checked optional packages were absent**: ImageHash, deepdiff, binGraph, HTTPReplay, Socks5man and pyattck. These six had been installed under `charan`'s private Poetry 1.8.2 env, whereas CAPE's services run Poetry 2.5.1 under `cape` in a different venv.
- Do not misconstrue missing optional modules as a corrupt Python installation, a base-install failure or a reason to rerun `cape2.sh base`. **Do not bulk-install uncontrolled optional requirements into the CAPE runtime without checking locked core dependency compatibility first** (notably potentially incompatible new versions). Do not move/copy `charan`'s venv or weaken home directory permissions.
- **Next:** Continue the user's manual setup workflow and separately schedule a scoped **optional-feature enablement step** after reviewing requirements versus `poetry.lock` and tested package versions. For automation, package operations must execute as `cape` against the **verified service Python interpreter**, with explicit version/lock checks and post-install verification. Missing configured first Windows VM `cuckoo1` remains the current CAPE startup dependency; independent Suricata startup failure remains unresolved. [Step 11 details](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

## Step 12 — Candidate Windows download is third-party Canary-based 7z, not trusted analysis image (2026-10-09)

- User began downloading the **`[Windows X-Lite] Optimum 11 26H1 Pro v2.7z`** archive after clicking `https://windowsxlite.com/26H1Pro_V2` redirect/link to `https://pixeldrain.com/u/ZdPxkVmH`. The upstream site describes a **modified Windows 11 Pro 26H1 Canary build 28000.1** with SmartScreen removed and UAC disabled. **Download completion and contents have not yet been verified.**
- CAPEv2's guest-creation guidance recommends Windows 10 or Windows 11 23H2; do not silently treat a modified 26H1 Canary image as the canonical malware-analysis guest. A reputable source and validated guest agent/monitor runtime are crucial to defensible analysis results. Prefer genuine Microsoft media and licensing; any version outside documented CAPE compatibility must pass guest monitoring tests.
- Next: record downloaded archive file signature/type, size, SHA256 and safe 7z member listing **without extracting/executing**, then decide whether to use an officially sourced alternative. **No guest boot/NAT connection/Windows install** until VM and isolated networking plan reviewed. Add read-only artifact provenance module; hashes are identities, not assurances of trust.

### Step 12 automation — candidate media provenance, not permission to boot

- Added `scripts/inspect_windows_media.py` plus offline tests and `command1_pre_vm.sh inspect-media FILE`. These calculate SHA256, file size and magic for a completed local archive/ISO and write a restricted JSON report **without decompressing, mounting or executing downloaded data**.
- **Limit:** No archive-listing or publisher-authenticity proof is implied; a matching hash against only an untrusted publisher remains insufficient to prove Microsoft image authenticity. Candidate Windows X-Lite 26H1 Canary media is **not approved** as the first CAPEv2 guest; choose trusted Windows media and validate CAPE monitor version before VM creation.

### Step 12 updated — Microsoft official ISO chosen over Windows X-Lite (2026-10-09)

- User supplied screenshot of Microsoft's official Windows 11 download page `https://www.microsoft.com/en-in/software-download/windows11`; selected the **multi-edition Windows 11 ISO for x64 devices** and chose to download it instead of the modified third-party X-Lite archive. Do not infer completed download or ISO validity from the screenshot.
- Continue only after the official download completes and file signature/size/local SHA-256 are checked against Microsoft's `Verify your download` information for that exact ISO; no extraction required. ISO will be selected as VM install media in the future libvirt/virt-manager provisioning stage, with UEFI/TPM support if required and CAPE agent/monitor validation post-install.
- Maintain strict analysis-network gate: never attach live malware VMs to libvirt `default` NAT; verify dedicated isolation including IPv4/IPv6 before real samples. Avoid hardcoded expiring Microsoft download URLs; future automation accepts the local verified ISO and stores digest/provenance, not copied full media.

### Step 12A — Original Microsoft ISO downloaded, authenticity verification pending (2026-10-09)

- User reports the official Microsoft Windows 11 x64 ISO download is complete and the local file was renamed `Win11.iso`. Location, size and SHA-256 not yet evidenced. Renaming doesn't modify the bytes; the trust gate is unchanged.
- One read-only report command has been given to locate the file under `$HOME`, inspect `file` output, test ISO9660 descriptor identifier `CD001`, and calculate SHA-256. User will upload the resulting TXT. The committed `inspect_windows_media.py` now records PVD detection and source-file stability with unit-test fixtures; it cannot prove Microsoft origin independently.
- Follow-up: verify checksum against the official Microsoft expected digest for the selected ISO, then build the first Windows analysis VM only on a reviewed isolated network. Missing `cuckoo1` is still the main cause of CAPE/processor auto-restarts, and Suricata remains separately unresolved.

### Step 12A official media integrity verified — ready for pre-VM planning (2026-10-09)

- User's read-only report identifies `/home/charan/Downloads/Win11.iso`, **9,047,330,816 bytes**, ISO9660 bootable volume `CCCOMA_X64FRE_EN-US_DV9`, `CD001` signature, SHA-256 `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`.
- **Official Microsoft Windows 11 English x64 verification table matched that digest exactly** at `https://www.microsoft.com/en-in/software-download/windows11`. This verifies media integrity/authenticity relative to the published English x64 ISO digest for this acquisition, **not** Windows analysis-guest compatibility or lab containment. No need to repeat download/hash for this exact file.
- **Next:** Read-only pre-VM capacity and UEFI/TPM/libvirt storage/guest/network topology checks, then review dedicated isolated non-NAT networking BEFORE VM definition. Only after resource/isolation/compatibility plan, create `cuckoo1` and a clean snapshot. Suricata and optional CAPE Python dependencies remain separate follow-ups.

## Step 12B — Host capacity sufficient; staged VM preparation blockers identified (2026-10-09)

- User-supplied read-only Step12B report: 13th-gen Core i9-13900, **32 logical CPUs**, **62 GiB RAM/56 GiB available**, **289 GiB free** on filesystem containing libvirt images. QEMU **9.2.2**, libvirt **11.1.0**, `virsh`/`virt-install`/`virt-manager`/`qemu-img` installed; OVMF UEFI firmware present; `virtqemud` active while legacy `libvirtd` inactive (not itself an error).
- **Gaps:** `swtpm` missing (software TPM 2.0 for supported Windows 11); verified ISO under `/home/charan/Downloads/Win11.iso` but `/home/charan` has 0750 permissions and QEMU service user access not tested; **zero VMs** and no `cuckoo1`; `default` libvirt network is now **active, persistent, autostart YES, NAT forwarding** and remains unsafe for malware-analysis guests.
- **Next user action:** User wishes to follow their VM installation document step-by-step. No need for additional generic terminal diagnostics now. Review each proposed VM command/GUI action, plan nonforwarding dedicated analysis networking before attaching guest NICs, allocate vCPU/RAM/disk conservatively, support EFI/TPM, stage ISO with limited permissions if necessary, define guest and verified snapshot, test CAPE instrumentation, eventually negative egress/IPv6 containment.
- **Automation:** New read-only `scripts/audit_windows_vm_preflight.py`, synthetic tests and `command1_pre_vm.sh preflight-windows`, all on `development`. Static audit will not install swtpm, copy ISO, create VMs, alter services or claim malware-safe readiness. Current step does not establish complete automated Windows provisioning.

### Step 12C — Windows Setup reached edition selection; NAT connection needs correction (2026-10-09)

- User's screenshots verify manual virt-manager VM creation and Windows 11 installer boot: guest named `win11`; **4 vCPU**, **4096 MiB** RAM, **64 GiB** virtual disk `/var/lib/libvirt/images/win11.qcow2`; **Q35/UEFI**, ISO `/home/charan/Downloads/Win11.iso`; guided wizard had **`Virtual network 'default': NAT`** and NIC attached. User reached **Select Image** after choosing to install and bypassing entry of a product key. **Not yet a completed Windows OS installation or active CAPE guest.**
- Recommendation: select **Windows 11 Pro (standard, non-N)**; product key can be deferred for install but proper licensing/activation is a later responsibility. Validate guest compatibility, firmware/TPM and required CAPE software.
- **Network safety regression:** GUI default NAT was accidentally selected; since this is only booting clean official Microsoft media, no malware event is reported, but the domain is **not isolated**. Before preparing/running analysis, detach/replace the NAT NIC and use a separately defined validated nonforwarding guest network; keep shared `default` unchanged. Test IPv4 and IPv6 paths, host firewall, absence of unintended NICs, positive INetSim access and negative external access before any malware samples.
- CAPE expects `cuckoo1` but the guest is named `win11`; choose an intentional renaming or matching machinery-config update prior to registration and snapshot. Initial VM may not have software TPM (`swtpm` missing in Step12B); guest Windows hardware requirements still need verification.
- Update portable automation acceptance: programmatic guest definition must **fail closed if NAT selected**, avoid cloning accidental GUI defaults, and enforce explicit guest naming, CPU/RAM/disk sizing, UEFI/TPM compatibility, machine snapshot and containment checks. No VM creation automation is yet deployed or tested.

### Step 12D — Windows 11 Pro TPM2.0 blocker and permanent win11 VM identifier (2026-10-09)

- Screenshot shows standard **Windows 11 Pro** selected in the setup image chooser, then Windows Setup blocked with **`The PC must support TPM 2.0`**. First guest `win11` has not yet completed installation. Earlier Step12B had `swtpm` missing; fixing this is the immediate next manual prerequisite.
- User explicitly wants VM name **`win11`** retained. Do **not** rename it to `cuckoo1` as previously assumed. CAPE guest machinery configuration, snapshot name and guest IP will have to be explicitly reconciled to `win11` later; do not automatically edit CAPE yet.
- Recommended recovery: shut off guest at installer stage; install Ubuntu `swtpm` and `swtpm-tools`; attach **Emulated TPM version 2.0** via virt-manager hardware settings while guest is powered down; reboot installer and proceed without bypass. Confirm actual setup result after user reports back.
- Development branch package automation and read-only Windows guest preflight now include `swtpm-tools`/`swtpm_setup`; no host scripts or actual VM modifications have been executed by the assistant.

### Step 12E — SSL-55 software TPM packages installed, add TPM in virt-manager next (2026-10-09)

- User successfully ran `sudo apt-get install -y swtpm swtpm-tools` on SSL-55; both Ubuntu Noble packages version **0.7.3-0ubuntu5.24.04.1** configured, `swtpm --version` shows emulator **0.7.3**. No package-manager install error; ignore the non-actionable automatic dependency removal suggestion for now.
- Screenshot confirms existing `win11` guest is powered off (`Shutoff (Destroyed)`), still Q35/UEFI, and **does not yet show TPM** in hardware devices. Next reviewed GUI action: Add Hardware → TPM → Emulated → Version 2.0 → compatible TIS/default model → Finish. Record the resulting device screenshot before restarting installer.
- This exact `swtpm` + `swtpm-tools` dependency requirement is **already included in `scripts/bootstrap_virtualization_stack.sh`**, with inventory, simulation, explicit apply and post-APT verification; `audit_windows_vm_preflight.py` checks emulator/setup helper. Do not claim guest TPM provisioning automated until separately implemented and tested.

### Step 12F — win11 TPM 2.0 hardware present, swtpm_setup startup fails (2026-10-09)

- User screenshot verifies TPM **Emulated, TIS, Version 2.0**, and virt-manager's boot error `Could not run '/usr/bin/swtpm_setup': exitstatus: 1`, with exact error log **`/var/log/swtpm/libvirt/qemu/win11-swtpm.log`**. Earlier `swtpm`/tools Ubuntu package installation succeeded, so **do not re-run APT blindly**. Root cause **unknown until actual TPM log and virtqemud journal read**.
- User has a single private read-only Step12F diagnostic command, which captures the exact error log, TPM-only domain XML, package versions and relevant directory metadata. Added equivalent `scripts/diagnose_swtpm_startup.sh [VM_NAME]` in **development** and Bash syntax CI. Do not attempt automatic repair without evidence; especially don't weaken system-wide AppArmor or remove saved virtual TPM data.
- **Immediate next:** Wait for Step12F user TXT report; then choose the narrowest fix, verify guest can boot, continue Windows 11 Pro installation. Preserve guest name `win11` as requested; no completed guest, snapshot or CAPE machinery registration yet.

### Step 12F root cause found — tss cannot read/write /var/lib/swtpm-localca (2026-10-09)

- User Step12F TXT establishes `win11` TPM `tpm-tis`, `backend type=emulator version=2.0`, `swtpm`/tools available and `virtqemud` active. The real `swtpm_setup` failure log repeatedly says **`Need read/write rights on statedir /var/lib/swtpm-localca for user tss.`** (six attempts). Key generation began; local CA authoring failed because `tss` could not access that state directory. This is a focused host file-access issue, not an indication that Windows ISO, QEMU, or TPM packages need reinstallation.
- **Residual ambiguity:** the first audit examined `/var/lib/libvirt/swtpm`, **not the failing** `/var/lib/swtpm-localca`. Root reason of permission denial (absent path, owner/mode, parent traversal, ACL, or related) still requires metadata. Avoid broad/recursive chown or chmod and avoid deleting CA state shared by other VMs.
- Committed `scripts/audit_swtpm_localca_access.sh` to `development`, along with shell syntax validation; it produces a private single read-only report of effective `tss` access and directory metadata without exposing CA key contents. Next obtain that short report; then choose a **minimal state-preserving permission fix** and verify win11 starts. Guest name remains `win11`.

### Step 12G — TPM CA owner swtpm blocks tss; Step12H guarded repair (2026-10-09)

- User's Step12G report establishes exact CA state: `/var/lib/swtpm-localca` has **`swtpm:root:750`**, empty top-level listing; effective `tss` read/write/execute checks all fail. This reproduces the precise Step12F swtpm_localca failure. Parents are root-owned/traversable. Unlike earlier ambiguity, the **wrong owner of an empty statedir is now evidenced**.
- Provide one cautious repair only when `win11` shut off, `tss` account exists, path is real directory not symlink, owner/mode exactly match baseline and directory still empty: nonrecursive `chown --no-dereference tss:root /var/lib/swtpm-localca`, preserve 750, verify `tss` rwx. No service restarts or TPM state removal. Do not claim fixed until user supplies report.
- Implemented portable companion `scripts/repair_swtpm_localca_owner.sh` in `development` (read-only `--plan`, explicit gated `--apply`, idempotent no-op if already corrected). CI validates Bash syntax; real SSL-55 and clean-host correctness not tested. After repair, reattempt boot and resume Windows 11 Pro; keep guest `win11`.

### Step 12H verified — swtpm-localca directory owner corrected as tss (2026-10-09)

- User-supplied Step12H execution report confirms the guarded, **nonrecursive** owner change for **`/var/lib/swtpm-localca`** from **`swtpm:root:750`** to **`tss:root:750`**, retaining group/mode; `tss` read/write/traverse all **PASS**. VM `win11` remained shut off; **no services or VM restarted, no CA files deleted**. This resolves the verified original `swtpm_localca` directory-access condition, but **does not yet prove swtpm_setup completes**.
- Future automation's guarded `scripts/repair_swtpm_localca_owner.sh` is already implemented; its Bash syntax passed CI, while executing that specific script against SSL-55 or on clean hosts remains untested. Avoid repeating any `chown` now, especially after CA files are created at first successful boot.
- **Next:** Start existing VM `win11` in virt-manager once; if the emulator initializes, resume Windows 11 **Pro (non-N)** Setup. Capture new TPM errors verbatim if failure remains. Do not recreate the VM or alter unrelated host configuration.

### Step 12I — New socket access denial after CA repair (2026-10-09)

- Virt-manager screenshot now reports `qemu-system-x86_64` cannot connect to `/var/run/libvirt/qemu/swtpm/9-win11-swtpm.sock`: **Permission denied**. This differs from the earlier `swtpm_localca` error, whose directory access was corrected in Step12H.
- Read-only Step12I report shows **`/run/libvirt/qemu/swtpm root:tss 0770`**, parent `root:libvirt 0755`; failed guest launch leaves no socket or running swtpm/qemu process. The report did not identify effective QEMU identity or socket file mode at time of failure, and no AppArmor DENIED lines in selected kernel excerpt cannot rule out confinement.
- Related upstream issue `stefanberger/swtpm#840` shows root cause can involve a socket file mode 0600, not just directory traversal. Thus don't blindly change folder ownership/groups or disable AppArmor. Next: Step12J read-only host identity/access check for libvirt-qemu, qemu, tss, actual qemu.conf overrides and AppArmor status; inspect follow-up before choosing exact narrow repair.
- Added `scripts/audit_swtpm_socket_access.sh` to the **development** branch and wired Bash syntax CI. No VM recreation or package reinstall needed based on current evidence; `win11` remains stopped.

### Step 12J — qemu users absent, tss socket directory access passes; check security profile (2026-10-09)

- Step12J user report confirms no `libvirt-qemu` or `qemu` Unix accounts, `tss` exists (UID/GID 105), and `/run/libvirt/qemu/swtpm` is `root:tss 0770` with `tss` read/write/traverse **PASS**. This does **not** establish QEMU's actual effective UID/GID or prove AppArmor denial. No live socket survives failure for mode/owner observation.
- Focus on documented alternative causes rather than modifying shared host directories: libvirt-generated guest AppArmor rules sometimes reference `/var/run` while the actual socket resolves under `/run` (2025 upstream discussion); swtpm socket 0600 can deny access despite shared directory/group (swtpm#840). Neither cause has been proven on SSL-55.
- User given a short read-only Step12K collector, and `scripts/audit_swtpm_socket_security.sh` committed to `development` and CI. It checks the exact `win11` dynamic AppArmor profile's TPM socket rules, run alias, QEMU config and filtered local kernel/libvirt errors. No QEMU restart, AppArmor disablement, ownership edit or malware execution. Await user-provided report, then pick narrow host fix compatible with parallel student workloads.

### Step 12K — swtpm socket mode=0600 verified, cause still split between DAC/AppArmor (2026-10-09)

- User Step12K TXT: `win11` shut off; `security_driver = "apparmor"`; `/var/run -> /run`; VM generated profile present but grep showed no TPM socket rule and `.files` companion absent after failed boot; kernel denial excerpt empty (non-exhaustive). Local guest log confirms `swtpm socket ... mode=0600` followed by QEMU `-chardev ... Failed to connect ... Permission denied`.
- Hypotheses remain (1) QEMU differs from swtpm socket owner and POSIX mode 0600 blocks it, per [swtpm #840](https://github.com/stefanberger/swtpm/issues/840); or (2) host AppArmor guest rules were generated for `/var/run` and real kernel path is `/run`, per [2025 upstream libvirt proposal](https://lists.libvirt.org/archives/list/devel@lists.libvirt.org/message/RTL4QWDH5PH2AQUSES32Y4AANCMSDHZR/). This is *not* evidence to globally disable AppArmor or broaden permissions.
- Implemented new **explicit single-attempt diagnostic** `scripts/probe_swtpm_socket_start_once.sh` in `development` and Bash syntax CI. It requires user initiation, verifies `win11` is shut off, samples live transient socket owner/mode, QEMU UID/GID/AppArmor profile, triggers exactly one `virsh start win11` and saves a private report. A successful VM remains running. Await user report before any targeted security-policy or socket fix. No OS installation yet.

### Step 12M — Check effective QEMU DAC override without host changes (2026-10-09)

- Step12L evidence established socket `tss:tss 0600`, QEMU effective UID `0` and GID `1008`, AppArmor guest profile **enforce**, and repeated socket `Permission denied`. Because QEMU has UID0, the effective **CAP_DAC_OVERRIDE** bit must be observed before attributing this specifically to POSIX DAC. The presence of AppArmor enforcement and a known libvirt `/var/run` versus `/run` profile mismatch also makes LSM path denial plausible. No `apparmor="DENIED"` audit record was captured; absence of such a log is not a definitive clearance.
- User given one-shot Step12M capability capture command and matching `scripts/probe_qemu_caps_start_once.sh` on `development`, added Bash syntax CI. This attempts **one start of the trusted Windows Setup VM** to sample `/proc/<QEMU_PID>/status` (UID/GID, effective capabilities), without changing AppArmor, user permissions, services, packages or VM definitions. If it unexpectedly boots, it remains running.
- A proposed local AppArmor abstraction allowance would, even if win11-path-limited, be included by all libvirt guest profiles on this shared host. **Do not apply a shared AppArmor exception until DAC-vs-LSM root cause is sufficiently distinguished and the cross-VM consequences reviewed.** Do not disable AppArmor or relax all socket directory permissions.
- Await user Step12M TXT. Continue with guest `win11` only after the narrow root cause is verified; no Windows installation success yet.

### Step 12M verified — QEMU DAC override rules out basic tss 0600 as sole cause (2026-10-09)

- User Step12M evidence: QEMU **EUID 0**, effective **CAP_DAC_OVERRIDE YES**, enforced AppArmor `libvirt-<win11 UUID>`, and socket connection still reports `Permission denied`. This makes ordinary socket filesystem mode `0600` insufficient by itself to explain the failure; a profile path mis-match is now the strongest lead. Libvirt upstream's February 2025 patch documents `/var/run` vs `/run` symlink canonicalization causing an identical AppArmor `connect` denial.
- Any workaround through `/etc/apparmor.d/local/abstractions/libvirt-qemu` changes a common abstraction **included by every VM profile**, even if the allow rule's filename is win11-specific. On shared SSL-55, require explicit review/authorization and a conservative backup/revert process; do not disable global AppArmor or widen all TPM socket permissions. Future production installer should inspect libvirt version/compiled runtime path and use upstream-supported persistent remediation.
- No Windows installation or malware execution yet; `win11` remains shut off. Source: `SSL55_Step12M_QEMUCapabilities_cACMdKWR.txt`.

### Step 12N — AppArmor guard stopped without change, inspect actual include syntax (2026-10-09)

- Uploaded `SSL55_Step12N_AppArmorFix_bZURWcKz.txt` shows `win11` shut off and only one VM, but `STOP: Local abstraction inclusion not verified.` The guest's static `libvirt-qemu` AppArmor abstraction did **not match the narrow include pattern** assumed by the proposed workaround. **No policy was modified or reloaded and the VM was not started.**
- Official Ubuntu libvirt documentation identifies the common static abstraction and local override; other builds may include `abstractions/libvirt-qemu.d`. The correct override mechanism on SSL-55 must be read directly before considering a narrowly scoped change. Prior workaround `--apply` should not be rerun.
- Committed `scripts/audit_libvirt_apparmor_includes.sh` in `development` and CI Bash syntax check. It collects only include lines from existing static abstraction and domain template plus override path metadata, with zero mutations. Await Step12O user TXT and plan a reversible fix only once the correct include structure is established.

### Step 12O — Actual libvirt-qemu.d AppArmor include discovered; guarded drop-in ready to test (2026-10-09)

- User read-only Step12O confirms **`include if exists <abstractions/libvirt-qemu.d>`** at line 282 of system static `/etc/apparmor.d/abstractions/libvirt-qemu`; the `TEMPLATE.qemu` domain template imports that abstraction. Both potential local override locations were absent before remediation. The Step12N guard stopped because it expected the wrong include path; **no policy changed**.
- Corrected `scripts/guarded_win11_tpm_apparmor_rule.sh` on **development** to use `/etc/apparmor.d/abstractions/libvirt-qemu.d/90-cape-win11-swtpm`. Default plan, guarded opt-in apply; file grants only `/run/libvirt/qemu/swtpm/*-win11-swtpm.sock rw,` to the static libvirt abstraction. Includes AppArmor syntax validation with skip kernel load and cleanup if validation fails. No global disable/restart and no automatic VM start. CI Bash syntax passed; **actual SSL-55 application and success still untested**.
- CA owner `tss:root:750` was already corrected in Step12H. User should not repeat ownership fix. One VM `win11` remains not installed and shut off. After guarded drop-in is applied, boot guest once to see whether the swtpm AppArmor socket-path denial is resolved; preserve reports, do not broaden permissions on failure.

### Step 12P — Guarded AppArmor override installed on SSL-55; VM boot not yet verified (2026-10-09)

- User report `SSL55_Step12P_AppArmorFix_iAEYrJBS.txt`: safety checks passed, installed narrow path-specific libvirt AppArmor drop-in for win11's swtpm Unix socket, and `apparmor_parser -Q -T -K` validation **PASSED**. AppArmor stayed active. No service restart or VM launch took place during the fix.
- **Do not conflate syntax-pass with boot success**. Next is **Step12Q one supervised start** of existing `win11` via virt-manager. If successful resume Windows 11 Pro Setup and capture screenshot; if failure capture exact permission or policy denial, no broad changes.
- The new drop-in resides under `/etc/apparmor.d/abstractions/libvirt-qemu.d`, an include shared by libvirt guests; filename match restricts its scope to `*-win11-swtpm.sock`. This is a pragmatic host-specific workaround, not yet a verified portable upstream fix. Explicitly test on clean supported hosts before considering production.

### Step 12Q — first successful win11 software TPM boot, installer at 10% (2026-10-09)

- User's screenshots confirm the original `win11` KVM guest **started successfully with TPM 2.0** after the guarded AppArmor drop-in from Step12P. Windows 11 installer sees the **64 GB unallocated virtual disk** and proceeds to **Installing Windows 11, 10% complete**. TPM launch and QEMU connection problem **resolved for this VM at this stage**; desktop/OOBE completion still unverified.
- Do **not** re-run TPM ownership/AppArmor adjustments, reinstall packages, rename guest or recreate its disk. User should let Windows Setup automatically reboot as needed and not press a key to boot the ISO again; send next setup screenshot for guided OOBE. Windows Pro non-N was selected before TPM troubleshooting.
- Keep future portability work separate: the swtpm CA permissions guard and limited AppArmor drop-in need generalized, tested and rolled back cleanly on a genuinely fresh supported machine, with shared libvirt policies considered. This success does **not** prove generalized three-command automation, snapshot readiness, CAPE guest configuration, or network containment.

### Step 12R — Windows 11 reached desktop in win11; guest preparation next (2026-10-09)

- User screenshot of `win11 on QEMU/KVM` shows a functioning Windows 11 desktop after guest installation and initial setup; **Windows OS installation is complete**, and Step12H/12P TPM/AppArmor repairs allow this specific VM to boot. The guest remains named **`win11`**.
- **Next immediate check:** Windows Settings → System → About → Windows specifications, screenshot edition/version/build; expect Windows 11 Pro from installer choice. This is read-only and does not require terminal commands.
- **Not yet done or demonstrated:** CAPE agent and Windows guest preparation, guest tools/snapshot, reconciling CAPE machinery config's `cuckoo1` with real `win11`, parallel VMs, separate INetSim guest, malware-network isolation, or verified three-command automation on fresh hosts. Avoid claims that full CAPE deployment is ready. Keep user workflow manual-on-SSL-55 and record validated steps in `development`.
