# Step 7 — User-run CAPEv2 kvm-qemu.sh all (partial success, unresolved errors)

**Reference host:** CSE-SSL-55. **Reported execution:** 2026-10-09. **Status: PARTIALLY COMPLETED / NOT FULLY VERIFIED.**

## Canonical manual procedure (reported, not assistant-executed)

```bash
cd ~/CAPEv2/installer
sudo chmod a+x kvm-qemu.sh
sudo ./kvm-qemu.sh --help
sudo ./kvm-qemu.sh all charan 2>&1 | tee kvm-qemu-all.log
```

`charan` is the user-selected SSL-55 Ubuntu account, not a portable literal. The user's uploaded `Pasted text(4).txt` begins with the QEMU build at `[1683/3252]`, **not** with the invocation or first half of the build. It contains **9,154 text lines** and ends with virt-manager installation output followed by a shell prompt. These are only the lines available for the current analysis; the missing prefix and original shell/pipeline exit status were not supplied. The displayed prompt establishes termination/return to the shell, **not zero exit status or runtime functionality**. No commands were independently run on SSL-55 by the assistant.

## Upstream command-line semantics — source-verified

Reviewed `kevoreilly/CAPEv2/installer/kvm-qemu.sh` (Git blob SHA `23b7eaa30bdd13bd9347098fe0d46204550b86f9`; equality with SSL-55 edited checkout **unverified**):

- Line ~69 sets `username=$SUDO_USER`. The proposed `username="$2"` logic near the command dispatch (~1288–1295) is **commented out**; the help says username is optional. Therefore, in this inspected revision `sudo ./kvm-qemu.sh all charan` normally takes the effective target username from `SUDO_USER=charan`, NOT from `$2`. A different sudo context (e.g., root shell, sudo -u, service, CI) can select the wrong account or no account. A final wrapper must explicitly validate the user and the actual script version; do not rely on a positional argument to set user identity.
- `--help` is not a dedicated read-only argument handler. The script's top-level `systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target` runs **before** command dispatch, even for help/unknown commands. The special help case is `-h`. **Do not present `--help` as a harmless preflight** or execute upstream script while inspecting its behavior.
- The `all` branch builds QEMU (9.2.2), SeaBIOS (1.16.3), libvirt (11.1.0), may install virt-manager, changes GRUB/IOMMU and sysctl/kernel behavior, manipulates AppArmor, installs Python packages, creates groups/rules, and restarts services. It also purges distro libvirt and creates APT hold/pin entries. This is **not idempotent** on the evidence supplied and should never be blindly repeated as an automated bootstrap.
- Standard Bash pipeline `sudo ... 2>&1 | tee ...` returns `tee`'s status without `set -o pipefail`. Capture the installer's actual exit status with `PIPESTATUS[0]` immediately or enable pipefail in a future reviewed executor. **Even exit 0 would not prove all nested failures were handled**, since many upstream subprocess outcomes are not terminal failures.
- Since this already ran on SSL-55, **do not rerun `all` as a troubleshooting shortcut**.

## User-supplied 9,154-line excerpt: verified outputs and blockers

Positive **stage indicators only**:
- `dpkg-deb` built `/tmp/qemu-9.2.2_builded.deb` (about 93.8 MB), followed by `Setting up qemu (9.2.2)` and `[+] Patched, compiled and installed` (around log lines 2055–2074). This supports package installation, not the exact executable/libvirt runtime backend.
- SeaBIOS build generated `out/bios.bin` and copied it to `/usr/share/qemu/bios.bin` and `bios-256k.bin` (around lines 2266–2293); compiler warnings occurred, and guest firmware behavior was **not** tested.
- `libvirt-python-11.1.0` wheel built and installed (around 6675–6684); libvirt service sockets were enabled.
- `kvm-ok` reported usable KVM, and `virt-host-validate qemu` reported many **PASS** items (around 6705–6722). Secure guest support remained **WARN**.
- Later build logs show `libvirt` runtime dependency version `11.1.0`, and installation progress for virt-manager; **no post-run virsh/QEMU binary/VM check or exact exit status** was included.

Unresolved real errors/warnings (**do not mark as fully successful**):
1. Source installer **purged nine Ubuntu libvirt packages** (around lines 2454–2485), including previously installed `libvirt-clients` and `libvirt-daemon-system`, removed default-network dnsmasq configuration, and applied APT holds. It replaced packaged components with custom-source versions and modified shared libraries. This may disrupt other VMs and the Step 6 `default` network. **The original default network's continued existence/health is unverified.**
2. Repeated libkmod errors (e.g. lines 2931, 2977–2984, 6723, 7678): malformed `/etc/modprobe.d/blacklist-kvm.conf`, line 1 starting with `-e`. The installer proceeded. Requires approved inspection, not blind rewriting.
3. SeaBIOS `sed: can't read .config: No such file or directory` (line 2129) happened before a Kconfig-generated `.config` appeared, with compiler overflow/overread and linker warnings. Firmware built and copied, but replacement integrity and whether all edits were applied at the intended stage remain unverified.
4. `fatal: The group `kvm` already exists.` (line 6708) was encountered during group creation. This is a common harmless *pre-existing group* in isolation, but the installer must branch based on `getent group kvm` and verify user membership/permissions before continuing.
5. System-wide `PIP_BREAK_SYSTEM_PACKAGES=1` and root pip installs were used. A later operation failed with `ERROR: Cannot uninstall cryptography 41.0.7, RECORD file not found` (line 7923), indicating an incompatible pip-vs-distro package modification. Use isolated virtual environments or an explicitly supported package policy instead of forcing system Python.
6. APT/DPKG reported **force-overwriting QEMU-owned firmware descriptor files** when installing `ovmf` (lines 7858–7862). A portable installer must define package ownership and version precedence before installing potentially conflicting QEMU+OVMF sources.
7. APT ran with mixed Ubuntu `noble`/`focal` repositories (already noted in Step 6). The excerpt shows unavailable libvirt package names, unavailable `libcroco3`, Python 2 dependency `python-enum34`, and `libnetcf1`/`libxenstore3.0` fetched from `focal` (lines 7931–7965). Cross-release dependency resolution is **not** a production-safe default.
8. Upstream `all` changed global sysctl settings, including `net.ipv4.tcp_syncookies=0`, bridge netfilter values, TCP congestion control, GRUB/IOMMU and power-management sleep targets. The log reported `[+] Please reboot` (line 6833) but did not prove a reboot occurred. **No reboot should be initiated by the automation without explicit informed authorization**; inspect settings first.
9. Existing Docker/host routing, libvirt default NAT, unrelated services, installed Python and package-manager state must be protected from these changes. Nothing here validates guest isolation or malware safety.

**Conclusion:** Report Step 7 as **PARTIAL BUILD WITH ERRORS / UNVERIFIED RUN TIME**, not complete successful deployment.

## Automation development

- [`scripts/audit_kvm_build_step7.py`](../scripts/audit_kvm_build_step7.py): read-only, credential-safe classification of log warnings/errors, missing log beginning, installer username selection and incomplete functional validation. It intentionally refuses to certify success or safe rerun of upstream `all`.
- [`scripts/test_audit_kvm_build_step7.py`](../scripts/test_audit_kvm_build_step7.py): **10 local synthetic tests passed**; the committed files match tested Git blobs (audit `1c21ef07380fa7d3a2cc0ed6f43d4b66ba911880`, tests `92f85b97eb836231bb4c38e37421717625bea69a`). The tool was also run read-only **against the user's uploaded excerpt**, yielding `UNVERIFIED_WITH_ERRORS`, **nine distinct findings**, and detecting that the excerpt begins mid-build. Exact results should be treated as pattern matching, not holistic system verification.
- `audit_username` only validates the named non-root account and recognizes the inspected upstream `SUDO_USER` assignment; it **does not** automatically fix or execute upstream scripts. It requires an existing login and source review.

### Required for eventual portable installer

1. Detect installed OS/platform, APT source purity/conflicts, required CPU/RAM/disk/KVM, existing workloads, target Ubuntu user (not root), sudo identity and shell environment. Require compatible CAPEv2/KVM/QEMU/SeaBIOS version matrix.
2. Stage and verify tools before installing missing packages. For a fresh host, bootstrap git, compiler/build dependencies, Python 3, pip tooling only within a supported isolation model, `acpica-tools` if actually needed, QEMU/libvirt dependencies, libraries and firmware. Validate each component after provision.
3. Never execute upstream `all` unreviewed. Separate QEMU, SeaBIOS, libvirt, host settings and virt-manager into **idempotent, gated modules**; detect compatible existing components and protect against destructive purge/holds, world-scope sysctl changes, unmanaged package collisions or service disruptions. Preflight and backup configs before authorized edits.
4. Set the intended username explicitly from the validated current login or a user override, check `SUDO_USER` semantics, group membership and use root only for tightly scoped commands. Verify each requested mutation and record its result.
5. Capture stage-specific exit codes, `pipefail`, timeouts, hashes, versions, checks and redacted logs. A shell prompt or successful `tee` is never a release criterion.
6. Provide rollback/recovery journal for partial runs. Avoid blanket `apt upgrade`, `apt autoremove`, forced dpkg overwrites, global pip changes or automatic reboot.
7. Gate any guest VM operation behind independent verification of libvirt state and a **dedicated isolated analysis network**; Step 6's default NAT is not adequate for live malware tests.
8. Test on fresh compatible Ubuntu, partially configured host, existing QEMU/libvirt, mixed repository warnings, missing `kvm` group, root login, absent sudo, multiple users, interrupted compilation and conflicting apt-managed files.

## Required next verification on SSL-55 (read-only, performed by user only)

A post-build report must confirm actual versions/binary paths/package ownership (`command -v`, `readlink -f`, `dpkg -S`), `virsh -c qemu:///system version`, daemon sockets/services, default network XML/status, KVM access, group membership, relevant sysctl/modprobe status, and whether a reboot is pending. The report must not include secrets. **Do not automatically restart, reinstall, purge or reboot** on the strength of this log.

**Authorization boundary:** Assistant made no changes to SSL-55. Changes in this document and scripts exist only on the project's GitHub `development` branch.
