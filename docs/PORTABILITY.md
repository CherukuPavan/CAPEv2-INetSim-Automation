# Portability, dependency bootstrapping and fresh-machine acceptance criteria

**Status:** Architecture and acceptance requirements, not a claim of finished automation or verified compatibility.  
**Reference:** SSL-55 is the **canonical source of manual procedure**; its preinstalled software is **not** the baseline assumed on a fresh host.

## Support contract (must be established and tested)

Target a documented, explicit compatibility matrix of **supported fresh Ubuntu releases, architectures, hardware and virtualization stacks**. Exact supported Ubuntu versions, kernel combinations, CAPEv2/INetSim releases, VM hypervisor versions and minimum resources remain **to be confirmed** from manual evidence plus compatibility testing. Do **not** promise success on every arbitrary computer, unsupported Linux distribution, conflicting virtualization stack or machine without CPU virtualization.

The script must report unsupported/incompatible conditions precisely **before making risky changes**. Some conditions cannot be installed away: disabled firmware virtualization, lack of nested virtualization on a hosted VM, inadequate resources, unavailable licensed Windows installation media, untrusted/blocked package repositories, hardware-specific limitations and missing authorization.

## Core automation rule

For **every required** tool, system package, Python module, kernel capability, service, configuration file, VM dependency and runtime component:

1. **Discover:** Determine whether it is present, including OS release and architecture, which package or version provides it, and required privileges.
2. **Validate:** Check the installed version and actual functionality, not merely whether an executable exists. Distinguish mandatory and optional dependencies.
3. **Resolve:** If a compatible component already exists, **reuse it** without destructive upgrade or reconfiguration. If missing or incompatible, choose an explicitly supported installation path, check for conflicts, and provision only what is necessary through the approved bootstrap stage.
4. **Install safely:** Check package manager/repository readiness, locks, network/download requirements, package authenticity and integrity, free disk space, and interactive/noninteractive constraints. Obtain privileges appropriately. Do not blindly run `apt upgrade`, `dist-upgrade`, `autoremove`, reset APT sources, disable host security, or replace user software.
5. **Verify after installation:** Assert supported version, executable behavior, service health, VM health or connection test as appropriate. A package-manager exit code by itself is **not** final proof.
6. **Proceed or stop safely:** Continue only after required invariants pass; otherwise stop the affected operation with a clear cause, non-destructive recovery instructions and consolidated logs. Never skip a failed mandatory dependency.
7. **Record:** Keep original manual commands separately from improved portable automation equivalents. Log observed versions, decisions, changes and results without committing secrets or institutional topology.

Example: the manual Step 2 installed `cpu-checker` on SSL-55 and Step 3 ran `kvm-ok`. A future installer should first check if a supported `cpu-checker` is installed; install the package only when needed, verify `kvm-ok`, and then check the **actual KVM device/capability**. It must never equate `cpu-checker` being installed with hardware virtualization being available.

## Separation of responsibilities and execution stages

- **Read-only preflight/diagnostics:** May run on hosts without dependencies and report what is missing. Must **never** install packages or alter SSL-55 on its own. Existing `scripts/check_host_virtualization.sh` is an early *read-only draft*, **not** the finished bootstrap installer.
- **Authorized installer/bootstrap:** An eventual deployment command may install missing prerequisites as part of the user's explicit decision to run that deployment. It must clearly announce planned changes and avoid interfering with existing workloads.
- **Configuration:** Generate host-appropriate, validated settings, using configurable users, paths, virtual network CIDRs, VM quantities and credentials stored safely outside source control. No SSL-55-specific hardcoding.
- **Post-install checks:** Verify each subsystem, including services, VM functionality, integration and the guest isolation boundary. Guest malware execution is disallowed until isolation checks pass.

The eventual public **three-command entrypoint** may internally invoke many modular, versioned, tested steps. The number of entrypoint commands is not a justification for skipping preflight, logging, dependency checks or recovery.

## Fresh-host inventory before provisioning

Check and record (while redacting sensitive information in shared logs):
- Ubuntu release, architecture, kernel, supported repositories, package manager, required privileges, time/DNS/download reachability when relevant.
- CPU flags, VMX/SVM availability, BIOS/UEFI or nested virtualization blockers, usable `/dev/kvm`, guest hypervisor backend, user permissions and potential conflicts with existing virtualization software.
- Physical and available CPU, RAM, storage and usable free space; projected resource demand for requested Windows VM count and one separate INetSim VM.
- Existing packages, interpreters, modules, Git, Python/virtual environment, virtualization stack and other actual required software **once established by the manual build**.
- Existing bridges, Docker, host firewall, NetworkManager, routing, DNS, MongoDB, other services and occupied subnets. Protect unrelated workloads.
- Input artifacts, Windows licensing/media, verified hashes or signatures where provided, credentials/secrets storage, installation and recovery paths.

## Dependency design requirements

- Maintain a **dependency manifest** or equivalent declarative inventory mapping component -> required version range -> detection/check -> installation method -> post-install validation -> optional/mandatory -> recovery.
- Classify system packages separately from Python packages, kernel/firmware capabilities, guest artifacts and operating-system configuration; their installation semantics differ.
- Pin or constrain versions where interoperability demands it, while retaining a supported-version matrix; don't blindly reproduce one host's package revision.
- Support fresh hosts that lack `cpu-checker`, Git, Python toolchains, virtualization packages and other subsequently discovered dependencies. Bootstrap code must use only tools guaranteed by the supported base environment, or bootstrap those tools first.
- Avoid installing or mutating components during observation-only checks.
- Handle stopped/partially installed services, interrupted downloads, failed repository access, APT locks, signature errors and repeated invocations. Where safe, re-run must converge without duplicate networks, VMs or configuration entries.
- Use backups and a durable operation journal for files/services changed; distinguish recoverable operations from inherently non-transactional system package installations. **Do not claim automatic perfect rollback.**

## Network and operational safety — mandatory acceptance gates

- Use a dedicated guest-analysis network with independently **verified** isolation from host management interfaces, institutional/corporate networks, other VMs, Docker bridges and the public internet.
- Configure only the intended INetSim service paths; validate guest DHCP/DNS/routing, forwarding, firewall policy, service responses and **negative connectivity tests** from the guest perspective.
- Fail closed if isolation is uncertain. Do not run live malware before the test evidence is satisfactory.
- No blind host firewall resets, network interface renaming, third-party repository removal or changes to existing Docker, MongoDB and unrelated services.
- Install guest resources and parallel analysis modules only after enough CPU/RAM/storage and per-VM isolation is confirmed.

## Automated test matrix — required before production-ready claims

1. Clean **supported** Ubuntu host missing all provisionable dependencies.
2. Clean supported host with some dependencies preinstalled.
3. Correct existing versions; incompatible existing versions; absent mandatory component.
4. KVM present/usable; KVM unavailable; virtualization disabled or unsupported CPU.
5. Insufficient CPU/RAM/disk, privilege errors, conflicting hypervisor and overlapping network ranges.
6. Broken/duplicate APT configuration, unreachable download source, APT lock, failed install and interrupted execution.
7. Second and third re-runs after successful provisioning (idempotence); restart after a mid-install failure.
8. Existing Docker, NetworkManager, firewall, MongoDB and unrelated user workloads preserved.
9. One Windows analysis VM, additional parallel VMs, INetSim VM, and their service integration.
10. Positive simulated-service connectivity and **negative external/network-leak tests**, including host LAN and internet routes.
11. Logs and diagnostics collected in a single sanitized TXT/ZIP report; failure explains the specific action and recovery.
12. At least one end-to-end build on an **independent fresh machine** in every claimed supported platform combination.

**Release gate:** Manual success on SSL-55 alone does **not** establish portable automation. Only independently tested deployment and isolation evidence can justify describing a supported configuration as production-ready.

## ACPI-specific machine variation discovered in Step 5

See [ACPI_REPLACEMENTS.md](ACPI_REPLACEMENTS.md). The manual SSL-55 substitution of nine `<WOOT>` values with `DELL` is **not** a universal mapping: source inspection shows different fields for tablet, disks, SeaBIOS and ACPI. `BXPC` can be derived cautiously from a four-character ACPI candidate when one is unambiguous; the other eight fields require verified contextual replacement values. A production-grade fully automatic profile selection remains to be designed and validated. The guarded Python module is an early tested **draft**, not the final no-input installer. The Ubuntu fresh-host bootstrap must check/install Python 3 and `acpica-tools` where actually needed; raw DSDT header reading is possible without disassembly, so do not force unnecessary packages.


**2026-10-09 supplementary examples:** The supplied screenshots confirm variable-length DSDT fields (`Custom` is six characters), generic `PNP0` hardware IDs, and different four-character OEM ID/Table ID values (`DELL` versus `CBX3`) on some Dell models. The early draft rejects generic/virtual four-character markers and stops on competing candidates instead of inventing precedence. Five regression cases were added; selector rules passed nine targeted synthetic cases. This **does not** complete automatic hardware-profile discovery or establish fresh-machine support. See [ACPI_REPLACEMENTS.md](ACPI_REPLACEMENTS.md).

## Step 6 — libvirt host and network portability warning

See [LIBVIRT_NETWORK_STEP6.md](LIBVIRT_NETWORK_STEP6.md) for the complete manual evidence and verified upstream configuration variable uses. The standard libvirt `default` network is NAT, **not** isolated malware traffic; CAPE analysis Windows guests and INetSim must use a separately verified isolated network with guest-negative connectivity checks. Do **not** auto-start, auto-destroy, or auto-reconfigure an unrelated default network, or allow libvirt XML alone to satisfy the release gate. Unknown `INTERNET_IFACE` values like the observed `eno1` must be flagged; discover interfaces and default routes on the actual host rather than hardcoding them.

Check/repair missing or unsuitable libvirt packages only as part of an authorized installer after APT source/OS and version/conflict audits. SSL-55's APT lists mixed `noble` and `focal` repositories and a malformed KVM module configuration, requiring diagnosis before sensitive virtualization operations. Protect passwords supplied in installer settings: never include them in source control, logs, shell history or diagnostics; rotate any exposed value.

The read-only [`scripts/audit_libvirt_cape_network.py`](../scripts/audit_libvirt_cape_network.py) is a **draft** with 11 synthetic tests passing; it never certifies live malware safety. Fresh Ubuntu, SSL-55, kernel, firewall and guest tests are pending.

## Dynamic networking adjustment after Step 6 (2026-10-09)

The user corrected the previously hardcoded/nonexistent `INTERNET_IFACE=eno1` to `INTERNET_IFACE=enp0s31f6` on SSL-55 after verifying that the IPv4 route to `1.1.1.1` selects the Ethernet interface. This is **route selection evidence only**, not confirmed Internet connectivity or guest isolation. See [DYNAMIC_NETWORK_DISCOVERY.md](DYNAMIC_NETWORK_DISCOVERY.md).

Our [read-only route detector](../scripts/discover_host_uplink.py) now validates destination-specific routes, host interface state and IPv4 source, multiple default route entries, policy routing, VPN/virtual links and conflicting operator override. **19 synthetic tests passed** and the files committed on `development` match the tested Git blobs. It does not install packages or change SSL-55. A fresh-machine bootstrap must check `python3`, `iproute2` and virtualization dependencies as required, installing only missing supported components once authorized.

**Not yet implemented:** Dynamic selection/provisioning of the final non-NAT libvirt analysis network, guest-facing `NETWORK_IFACE`/`IFACE_IP` mapping, and guest isolation/INetSim verification. These must be designed from verified manual steps, executed safely, and tested before release; simply detecting a working host uplink never grants malware guests external access.

## Current status

- Steps 1–6 (host checks, packages, Git/CAPEv2 source, ACPI source edit, libvirt install and CAPE settings) have user-supplied terminal evidence.
- The existing host/KVM script is read-only and remains an unverified draft on SSL-55.
- `scripts/bootstrap_cape_source.sh` is a separate **installer draft**: it bootstraps a missing Git package on an Ubuntu host, clones with normal user privileges, checks Git origin and HEAD and rejects unexpected pre-existing state. Its unit-like tests used a synthetic Git repository with simulated Ubuntu metadata, **not** SSL-55 or a verified clean Ubuntu test host. The missing-Git APT path remains untested.
- The original SSL-55 `sudo git clone` may produce a root-owned checkout. Future automation will not assume user ownership or silently change it.
- CAPEv2 source checkout has been reported, but **no full dependency bootstrap, VM deployment, CAPEv2 runtime installation, INetSim deployment or three-command system exists yet.**
- This document records requirements for future implementation, not actions performed on SSL-55.

## Step 7 — Hypervisor build portability gate (2026-10-09)

The upstream source installer uses `SUDO_USER` as its target username; its positional second-user-argument handler is commented out in the inspected revision. Validate the existing non-root Ubuntu account and execution identity explicitly. Do not hardcode SSL-55's login.

The user-supplied Step 7 log shows a QEMU/SeaBIOS/libvirt build with several unresolved package and configuration errors. On a fresh host, a safe installer must check existing package ownership and compatible versions before changing system components. It must not blindly repeat source-installer operations, overwrite distro-owned firmware, globally override Python packages, or change boot and service policies without review.

Use isolated, testable build stages with captured exit statuses, dependency checks, configuration backups and post-install functionality checks. The read-only audit module and tests are linked in [KVM_QEMU_STEP7.md](KVM_QEMU_STEP7.md). The current log is not evidence of a fully verified deployment.

## Step 7 verified host state and persistence requirements

The user-generated post-build report establishes that source-installed QEMU/libvirt can function even when `libvirt-clients` and `libvirt-daemon-system` are absent as Ubuntu packages. Prefer **functional checks plus executable/library/package provenance**, not just `dpkg-query` existence. An active monolithic `libvirtd` service can also legitimately coexist with inactive modular daemons.

The report also exposes **a transient/non-autostart libvirt network**, **account groups listed in the database but not in the current login session**, a **malformed KVM modprobe file and a separate blacklist directive**, disabled TCP SYN cookies, masked sleep/suspend targets and a pending reboot. These are critical post-install invariants for a fresh host. Detect and report unsafe or nonpersistent state, but never automatically destroy/restart networks, remove blacklists, unmask host sleep policy, modify security sysctls or reboot without a separately reviewed and authorized change plan.

See [STEP7_POSTBUILD_AUDIT.md](STEP7_POSTBUILD_AUDIT.md). Read-only post-build parser [`scripts/audit_step7_postbuild.py`](../scripts/audit_step7_postbuild.py) has **14 passing synthetic tests** and classified the report as `REVIEW_REQUIRED`. Real guest networking and reboot survivability remain untested.

## Step 7 — Confirmed NAT/alias-aware persistent state (2026-10-09)

The final SSL-55 read-only report conclusively shows `<forward mode='nat'>` on the **active but transient** libvirt `default` network. The bridge `virbr0` is down without attached guests; this observation by itself is **not** a failure. Future automation must distinguish defined/active/persistent/autostart, forwarding modes, link/carrier lifecycle and guest isolation tests; no single libvirt bridge status can certify containment. Never persist/start default NAT merely to satisfy a deployment gate for malware analysis.

The host has Ethernet and Wi-Fi default routes with different metrics, so discover egress from real routing context and explicitly resolve ambiguity while keeping malware guests without real-world egress. The account's supplemental group memberships and the current login session's credential groups differ: verify both, and refresh only through the user's approved session handling rather than repeated `usermod`.

Detect host-security regressions including malformed modprobe directives, potentially intentional KVM blacklists, `net.ipv4.tcp_syncookies=0` and masked power targets. Check whether persistent sysctl paths like `/etc/sysctl.conf` and `/etc/sysctl.d/99-sysctl.conf` are aliases/symlinks or multiple distinct precedence layers **before** backing up and changing any file. Preserve user host policy unless an explicit approved remediation is available; neither a reboot nor a network reset is an automatic fix.

User evidence, precise boundaries and approval-gated remediation proposal: [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md). End-to-end automated guest isolation and host security restoration remain **unimplemented and untested**.

## Step 7A — Modprobe backup and policy-safe repair strategy

User-run SSL-55 diagnostics confirm a root-only, byte-identical backup with matching SHA-256 before modifying malformed `blacklist-kvm.conf`. See [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md). The first line `-e blacklist kvm_intel` is invalid and ignored; the second line `blacklist kvm` is valid and may affect module autoload. A future fresh-machine installer should inspect existing modprobe syntax and effective rules and **must not remove valid administrative blacklists automatically**. Require version/platform-specific capability checks, precise expected-state guard, secure backup, narrow diff, unchanged metadata and post-change verification. Plan an independently approved reboot check. The user subsequently completed the Step 7B first-line repair with exact-content, metadata and `modprobe --showconfig` verification; the valid blacklist was intentionally preserved.

## Step 7B — Verifiable syntax correction versus boot policy

SSL-55's user-executed Step 7B shows a guarded repair of one malformed modprobe directive, with its backup intact and the existing valid `blacklist kvm` retained. A clean parser and loaded KVM modules are **not** proof of reboot-time autoload. [`scripts/audit_kvm_modprobe.py`](../scripts/audit_kvm_modprobe.py) implements read-only detection of malformed configuration and valid targeted blacklists; **14 tests passed** on synthetic fixtures, and committed blobs match tested versions. The release installer must detect actual effective policy across **all** modprobe files, consider `kvm_intel`/`kvm_amd` for hardware, and require a reviewed change before overriding institutional policy. Follow [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md).

## Step 7C — Alias-aware sysctl review and prospective repair

The SSL-55 read-only report proves that the two paths `/etc/sysctl.conf` and `/etc/sysctl.d/99-sysctl.conf` are **the same underlying file**: the latter is a symlink `-> ../sysctl.conf`, with matching stat device/inode. The current single persistent `net.ipv4.tcp_syncookies = 0` is a security regression. It must not be treated as two separate files or edited twice. No user-executed corrective modification has been reported yet.

A proposed correction to `1` must be approved and limited to one guarded canonical-file edit with checksum/backup, preserved ownership/mode, restored setting and exact runtime `sysctl -w` for this key alone. Do not run wholesale `sysctl --system` on machines with mixed or unsafe unrelated settings, overwrite administrator policy, break links, or imply reboot readiness from one corrected sysctl.

New [read-only symlink-aware audit](../scripts/audit_sysctl_alias.py) and [15 synthetic tests](../scripts/test_audit_sysctl_alias.py) committed and hash-verified; **not** executed on SSL-55. On different hosts, discover the actual effective sysctl source hierarchy: do not assume Ubuntu alias, file line 77 or SSL-55 values. See [STEP7_SYSCTL_REVIEW.md](STEP7_SYSCTL_REVIEW.md).

## Step 7D — Successful guarded SYN-cookie correction (2026-10-09)

The user supplied an executed follow-up report verifying that Step 7D **passed**: a protected root-only canonical sysctl backup with matching SHA-256, confirmed symlink/source identity, one narrowly scoped edit of `net.ipv4.tcp_syncookies` from `0` to `1`, verified unchanged unrelated contents and file permissions, and read-back of active `net.ipv4.tcp_syncookies=1`. No system-wide `sysctl --system`, reboot or service restart. See [STEP7_SYSCTL_REVIEW.md](STEP7_SYSCTL_REVIEW.md).

This fixes the **current** SYN-cookie protection setting and the persistent file (reboot survival not yet tested). The initial cancelled approval attempt remains documented as a distinct prior event, not the current state.

**Portability requirement:** Different machines may not use SSL-55's exact sysctl file, inode, alias, line number or source precedence. The final installer must inspect runtime and persistent effective values, backup/verify canonical sources, refuse conflicting independent assignments, and apply only approved precise values rather than copying hardcoded paths/inodes from the reference machine. `scripts/audit_sysctl_alias.py` is currently **read-only**, with 15 prior synthetic tests; complete automated remediation and cross-machine validation remain pending. KVM blacklist, power management and dedicated isolated guest network are separate release gates.

## Step 7E — Current KVM checks versus cold-boot behavior

SSL-55's manual Step 7E shows loaded `kvm`/`kvm_intel`, present modules for the running kernel, active libvirt and successful regular and blacklist-aware `modprobe --dry-run` checks, alongside **one valid `blacklist kvm`** in effective configuration. This indicates **present KVM functionality**, not automatic cold-boot module loading or universal permission to remove a valid blacklist. The user also confirmed `net.ipv4.tcp_syncookies=1` again.

The effective configuration has `options kvm ignore_msrs=Y` and `options kvm report_ignored_msrs=N`; these may affect guest behavior and diagnostic coverage and must be reviewed per supported guest/host/version. Cross-host automation must detect vendor driver (`kvm_intel` or `kvm_amd`), kernel modules and built-in variants, effective directives across applicable config trees, any other blacklists/install actions, and the intended admin/guest policy. Do not equate no entry in `/etc/modules` to broken autoload. Reboot is separate and requires user approval, recovery plan and post-boot KVM/libvirt tests.

[`scripts/audit_step7e_kvm_policy.py`](../scripts/audit_step7e_kvm_policy.py) is an **offline report checker**, not a host-mutation script; 14 synthetic tests passed, and the actual SSL-55 report classified `BASIC_KVM_CHECKS_PASS_POLICY_REVIEW`, always refusing to certify reboot safety or guest isolation. See [STEP7E_KVM_POLICY.md](STEP7E_KVM_POLICY.md). Dedicated isolated analysis networking is still a blocking release gate.

## Step 7F — Persistent sleep masks and operator policy (2026-10-09)

SSL-55's current `sleep.target`, `suspend.target`, `hibernate.target` and `hybrid-sleep.target` are all **persistently masked** through `/etc/systemd/system/<target> -> /dev/null`; the inspected local upstream source script includes a top-level command to apply these masks. A fresh Ubuntu desktop, server or analysis workstation may have a different approved power policy. Do **not** copy the upstream behavior into the final three-command automation as an unconditional default.

The installer must detect current systemd unit state, persistent and runtime mask provenance, pre-existing administrative overrides and actual host role. It should ask for explicit user/admin policy confirmation before any host-wide power change. A verified analysis host may intentionally remain awake, but a user's ordinary workstation should not lose suspend/hibernate by surprise. Preserve unrelated unit configuration, maintain reversibility, and verify user-approved results.

[`scripts/audit_step7f_power_policy.py`](../scripts/audit_step7f_power_policy.py) is a **read-only offline report parser** with 14 passing synthetic tests. It classified the user report as `PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED`, deliberately never authorizes unmasking or asserts malware isolation. See [STEP7F_POWER_POLICY.md](STEP7F_POWER_POLICY.md).

## Shared host or institution-managed workstation — mandatory preflight gate (2026-10-09)

The SSL-55 owner clarified that this is a **college-managed host with other student login accounts**. This is NOT a dedicated malware lab, and the assumption that masking all power-management targets is acceptable for unattended analysis is no longer valid. Systemd target masks, QEMU/libvirt replacements, kernel/GRUB changes, sysctls, package-manager operations and networking affect **all users**, including student accounts that are not currently logged in. Administrator/sudo privilege alone does not demonstrate authorization under college policy.

A production workflow must first identify whether the host is shared, what workloads and networks it serves, and whether the institution explicitly authorizes host-wide virtualization changes and controlled malware analysis. Require backups and approved maintenance/recovery; stop before global changes if unapproved or if existing student service impact is unknown. Do not automatically mask or unmask sleep/suspend/hibernate: compare an approved baseline, make minimal reversible adjustments only with authorization, and verify no unrelated users are disrupted.

**Live malware analysis must not run on this shared host or use the ordinary libvirt default NAT**, absent an independently approved dedicated containment environment. Prefer an isolated institution-approved host/lab with controlled networking, verified no-LAN/Internet egress over IPv4/IPv6 and coordinated operators. Continue SSL-55 only for safe diagnostic/manual documentation work while authorization and design remain open. [Step 7F](STEP7F_POWER_POLICY.md).

## Shared machines can permit CAPEv2 installation: distinguish permissions (2026-10-09)

The user clarified that **CAPEv2 installation with the `charan` college login is permitted**, consistent with prior college deployments. A host being multiuser is **not by itself** a prohibition on authorized software installation; continue the user's staged, manual CAPEv2 installation on SSL-55 with the established verification/backup workflow.

The final installer must distinguish (a) permission to install/operate CAPEv2, (b) permission to change system-wide power, kernel, reboot, shared services, and networks, and (c) separate operational authorization and **demonstrated containment** before using real malware samples. These are distinct gates; do not infer one from another. Check for student-session/workload impact, use maintenance/recovery planning for disruptive operations, and never route uncontained malware over the ordinary institution LAN or NAT. Do not assume the existing masks should remain or be removed without knowing institutional policy.

## Real malware operating mode and host eligibility gate (2026-10-09)

The user clarified that the software is intended to run **actual malware samples inside CAPEv2 Windows VMs**, potentially on a college-owned shared Ubuntu host. Permission to install CAPEv2 through `charan` does **not** by itself confirm approval for the distinct high-impact activity of executing live samples on a multi-user college workstation.

The eventual installer must discover host role, accountable administrator, shared users/workloads, network segments, hardware virtualization controls, firmware/QEMU/libvirt provenance, reboot and cleanup constraints; **fail closed** when risk/approval is unresolved. Prefer college-approved dedicated hardware for real samples. Do not ship a workflow that implicitly assumes a normal NAT libvirt network, a host-only bridge with unrestricted host services, or an unverified INetSim guest is isolated.

Every analysis VM, including parallel guests, must use only an explicitly approved dedicated nonforwarding analysis network; INetSim must not have a fallback uplink. Enforce and test IPv4 **and** IPv6 negative reachability to Internet, campus gateways/student networks and management-plane services, accounting for actual routing, firewall, Docker bridges, WiFi, VPN, unintended secondary NICs, DNS/proxies and host-side forwarding. Validate safe snapshots/rollback and host recovery. Nonmalicious functional tests may continue separately from real-sample release.

See [LIVE_MALWARE_CONTAINMENT_POLICY.md](LIVE_MALWARE_CONTAINMENT_POLICY.md). No change to SSL-55 was performed by this documentation update; existing real-sample isolation gate is **not passed**.

## Step 8 — Detect existing source-installed Virt-Manager (2026-10-09)

SSL-55 already provides working `virt-manager --version = 5.1.0` under `/usr/local/bin/virt-manager`, while `dpkg-query` finds no `virt-manager` package or `ubuntu-desktop` metapackage. **Functioning executable presence and package registration are different checks**; do not replace source-installed GUI tools simply because the distro package database lacks the package, and do not treat absence of the Ubuntu desktop metapackage as conclusive headless status.

The inspected upstream `kvm-qemu.sh` `all` action conditionally compiles/installs Virt-Manager only when `ubuntu-desktop` is listed, and its standalone `virtmanager` action can rebuild from sources, change system desktop schemas, and enable/start services. Top-level power masks also occur even for commands that should be read-only. The future 3-command automation must detect and validate existing GUI, pinned dependencies, `qemu:///system` access, user-session groups and provenance **before** any authorized install/reinstall step. Source-installed GUI remains only CLI-level verified on SSL-55 until normal-user GUI connection is tested.

## Step 9 — Non-root libvirt access, transient NAT and no-guest baseline (2026-10-09)

From the actual `charan` user session on SSL-55, `virsh -c qemu:///system list --all` returned **no defined VMs**, while `net-list --all` returned `default active, autostart=no, persistent=no`. Its `virbr0` interface shows `192.168.122.1/24`, `UP` plus `NO-CARRIER`/`state DOWN`; with no VMs attached, this alone is not evidence of network failure. Non-root listing indicates current-session **read-only** libvirt system access but does not prove write privilege or a working GUI.

Earlier network XML directly confirmed `default` has `<forward mode='nat'>`. A portable security preflight must examine actual libvirt XML, forward mode, guest NICs, firewall/forwarding rules and egress, not infer containment from interface names, carrier flags or whether a network is active/persistent. **Do not automatically persist or autostart NAT `default`** or assign analysis guests to it. Treat empty domain inventory as a normal first-install baseline. See [STEP_LOG.md](STEP_LOG.md) and [LIVE_MALWARE_CONTAINMENT_POLICY.md](LIVE_MALWARE_CONTAINMENT_POLICY.md).

## Step 10 — Evidence-based post-install health, not installer exit only (2026-10-08/09)

An actual SSL-55 `cape2.sh base` run finished with a final `Done` message and captured `0`, yet **`suricata.service` was failed**, three CAPEv2 services were only `activating`, and a `dnspython` pip uninstall conflict occurred. Future automation must use `set -o pipefail`, independently preserve each child-process status and verify every postinstall package, dependency and service. Never equate installer `Done` or `tee` exit with runtime health; classify warning-like signatures separately from actionable failures.

Upstream `cape2.sh` MongoDB installation can replace **`mongod.service`** with **`mongodb.service`**; detect actual configured service and executable rather than hardcoding a distro-default unit name. Inspect Python package-manager environment/metadata instead of retrying global pip actions. An absent `*.env` glob may be an optional placeholder, but validate actual required config files rather than suppressing all copy errors.

Original `~/CAPEv2` Git clone is root owned and triggered `dubious ownership` under `charan`; do not globally weaken Git safety or `chown -R` a potentially shared tree. Host timezone became UTC through installation; any portable workflow must obtain consent before changing global timezone, power-management, package system, services, crontab or user/group settings on shared machines. Emit a private, scrubbed report and perform targeted verified remediation rather than a full source-installer rerun. See [STEP10_BASE_POSTRUN_AUDIT.md](STEP10_BASE_POSTRUN_AUDIT.md).

## Step 10B — Distinguish expected VM provisioning stage errors (2026-10-08/09)

SSL-55's Stage 10B evidence demonstrates why **intermediate service states cannot be judged without the provisioning phase**: `cape.service`/`cape-processor.service` emit `CuckooStartupError` because CAPEv2 is configured for `cuckoo1`, which does not exist before first Windows guest and snapshot setup. Treat this as **expected incomplete provisioning**, not evidence that CAPEv2 needs a full reinstall; after correct VM/snapshot configuration, require independent steady-state health checks.

The correct `mongodb.service` is active with `mongodb-org-server` 8.0.32; PostgreSQL responds to `pg_isready`; `cape-rooter` and `cape-web` are active. `mongod.service` not-found is consistent with upstream's custom MongoDB unit. **Suricata startup remains FAILED**, independent of missing Windows VM, so do not automatically mark the whole deployment ready. A previously logged PostgreSQL duplicate-key error while cape-web currently runs deserves postprovisioning verification. The `conf/default/*.env` glob has zero matching files, explaining the noncritical-looking `cp` message without proving a required env file is missing. Debian-managed dnspython uninstall conflict should be examined by isolated dependency health checks rather than bulk pip repair.

Future three-command automation should phase service startup: configure and validate first guest, snapshots, isolation, and required DBs **before** declaring CAPE/processor running; report expected state as `AWAITING_FIRST_VM` rather than infinite restart loops, avoid global service thrashing, and continue fail-closed on unsafe default NAT for real malware. Read-only `git -c safe.directory=<exact validated checkout path>` can query a root-owned source tree without changing global Git trust, but do not generalize to untrusted directories. [Step 10 record](STEP10_BASE_POSTRUN_AUDIT.md).

## Step 11 — Prevent split Poetry virtual environments (2026-10-08/09)

The user's Ubuntu Noble `apt install python3-poetry` installed version 1.8.2, and `poetry run pip3 install -r extra/optional_dependencies.txt` reported success **after creating a new `charan`-owned Poetry venv** under `~/.cache/pypoetry/virtualenvs`. Upstream CAPE and processor systemd files use `User=cape`, `WorkingDirectory=/opt/CAPEv2` and `/etc/poetry/bin/poetry`, so separate `charan` and `cape` environments are a likely functional mismatch. Local unit definitions and cape's actual interpreter still need a verified host read-only check.

**Portable acceptance gate:** Determine the exact Poetry path/version, account, workdir, actual interpreter, pip target and installed optional package versions **from real service configuration**. Never infer service package availability from an `apt` install, a Poetry command run under another login, or pip's success alone. Before installing optional dependencies, assess required vs optional features and reproducible pins; install only into the intended isolated venv via its interpreter, with approval and rollback, without upgrading global Python or swapping service accounts. The user need not rerun a successful package install until a missing runtime dependency is demonstrated. See [STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).
