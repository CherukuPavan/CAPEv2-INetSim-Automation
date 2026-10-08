# Automation roadmap (provisional)

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
