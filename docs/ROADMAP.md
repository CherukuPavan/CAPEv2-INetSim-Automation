# Automation roadmap (provisional)

The final target is a portable **three-command** workflow, derived from user-verified manual installation rather than guessed from an existing host.

1. **Command 1:** Bootstrap necessary dependencies and deploy CAPEv2 with the first Windows analysis VM.
2. **Command 2:** Ask for the number of additional Windows analysis VMs and provision parallel CAPE analysis.
3. **Command 3:** Deploy a separate Ubuntu INetSim VM and integrate all Windows guests using a tested isolated analysis network.

Cross-cutting requirements: Ubuntu compatibility checks; resources and CPU virtualization; permissions; reproducible configuration; safe re-runs; error detection; progress logs; secrets management; network isolation; validation tests; rollback and recovery.

## Current implementation status — 2026-10-08

- Canonical manual **Steps 1–6 recorded** in `docs/STEP_LOG.md`: host/interface baseline, installation of `cpu-checker`, KVM evidence, pre-existing Git availability, and successful CAPEv2 **source checkout**. A source checkout is not CAPEv2 installation.
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

- Manual installation evidence shows **51 newly installed + 2 upgraded packages**, active libvirt `default` network on `virbr0`, and upstream `cape2.sh` settings changed. The configured `eno1` interface was not in observed host inventory. Secret provided in output is **redacted** in project artifacts.
- **Safety blocker:** libvirt's default network is ordinarily **NAT**, not safe malware isolation. XML/firewall and guest-negative-connectivity evidence have not been collected; do not use it as a live analysis network. A dedicated verified isolated network must be built separately and tested before any malware analysis.
- **System warnings:** APT mixed `noble`/`focal` sources, duplicated VirtualBox entries, and invalid `/etc/modprobe.d/blacklist-kvm.conf` contents reported by libkmod. No repairs, upgrades, firewall edits or network reconfiguration authorized or executed by us.
- **Automation:** [`scripts/audit_libvirt_cape_network.py`](../scripts/audit_libvirt_cape_network.py), read-only and password-redacting; **11 synthetic tests passed**. Real SSL-55 execution, fresh-host package bootstrap, actual bridge isolation, and installer integration are **untested**. Full details: [LIBVIRT_NETWORK_STEP6.md](LIBVIRT_NETWORK_STEP6.md).

## Cross-machine release gate

Follow [PORTABILITY.md](PORTABILITY.md) for the dependency-by-dependency bootstrap contract and the fresh-machine test matrix. Completion requires supported-OS/hardware declarations, independent clean-host testing with dependencies absent, idempotent reruns, recovery from failures, protection of existing services, and verified network isolation. **Do not claim compatibility with every arbitrary machine.**

The initial `scripts/check_host_virtualization.sh` is deliberately **read-only**. Missing packages will be provisioned by future installer/bootstrap modules **after** sufficient manual evidence and design review; absence of an optional diagnostic tool does not automatically authorize installation during preflight.
