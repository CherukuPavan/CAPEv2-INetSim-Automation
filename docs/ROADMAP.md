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
