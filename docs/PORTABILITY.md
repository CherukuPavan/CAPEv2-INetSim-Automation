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
