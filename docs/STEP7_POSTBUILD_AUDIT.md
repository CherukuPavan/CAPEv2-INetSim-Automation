# Step 7 — Post-build verification report (2026-10-09)

**Input:** User-supplied `SSL55_Step7_PostBuild_20261009_025646.txt`, 76 physical text lines / 77 indexed file lines. **Status: BASIC QEMU/LIBVIRT/KVM FUNCTIONAL CHECKS PASS; HOST AND NETWORK REVIEW REQUIRED.**

This is user-run read-only evidence, not commands executed by the assistant. The raw report was **not** copied to GitHub; this is a curated summary without credentials or institutional addresses.

## What was verified positively

- Ubuntu session user `charan`, uid 1006; the user's own `id` shows only primary group and `sudo` in that **current session**.
- `/usr/bin/qemu-system-x86_64 --version` reports **QEMU 9.2.2**.
- `/usr/bin/virsh --version` reports **11.1.0**. `sudo virsh -c qemu:///system version` reports libvirt library/API **11.1.0** and running hypervisor **QEMU 9.2.2**. This confirms the **working libvirt-to-QEMU system connection**, beyond the previous build log alone. It is **not** a guest VM boot test.
- `kvm-ok` returned `/dev/kvm exists` and `KVM acceleration can be used`. Device has owner root/group kvm and `crw-rw----+`; ACL marker + present but detailed ACL and non-root device access were **not** tested.
- `libvirtd.service` is **active**. `virtqemud`/`virtnetworkd` are inactive, which is **not independently a failure** in an active monolithic `libvirtd` configuration; no service modification recommended on that basis.
- `virsh list --all` shows **no VMs defined** (expected at this manual stage).

## Configuration defects and review items

| Item | Exact observed status | Significance |
| --- | --- | --- |
| Default libvirt network | `default active / autostart no / persistent no` | **Transient** network. Differs from Step 6 where network was persistent/autostart enabled. Current active state does **not** prove it will survive a service restart or reboot. More importantly, a libvirt default network is normally **NAT**: no malware guest should use it unless isolated containment is separately validated. Inspect XML, bridge, network definition and intended guest topology before any change. Do not blindly `net-autostart` a transient/default NAT network. |
| User groups | `getent group kvm` and `getent group libvirt` list `charan` but current `id` does not | Account database membership appears added, but **the current login session has not adopted it**. Later a fresh login may be required before ordinary, non-root libvirt access; sudo-based checks do not establish normal-user access. |
| Module config | `/etc/modprobe.d/blacklist-kvm.conf` begins `-e blacklist kvm_intel` followed by `blacklist kvm` | First line is **invalid modprobe syntax** (consistent with earlier libkmod warnings); second is a real blacklist rule. KVM is usable **now**, but autoload behavior across reboot is uncertain. Requires a deliberately reviewed, backed-up correction, not automatic rewriting. |
| TCP SYN cookies | `net.ipv4.tcp_syncookies = 0` | TCP SYN-cookie protection currently disabled. Treat as a host security issue. The upstream installer changed global sysctl settings; a future deployment should **not** disable this. Investigate active source/persistence and restore a defensible default only with user approval. |
| Power management | Sleep, suspend and hibernate targets are `masked` | Persistent host-wide policy; inspected upstream script calls `systemctl mask` at top level, **even when invoked with `--help`**. This can interfere with normal academic workstation behavior. Review original baseline/host policy before any unmask. |
| Package state | `qemu` held; custom `qemu 9.2.2` listed; Ubuntu `ovmf 2024.02-2ubuntu0.10` present. Ubuntu `libvirt-clients`, `libvirt-daemon-system` and `seabios` absent from `dpkg-query`. | Expected in part after upstream purge/source compilation; **lack of distro package is not proof the executable or firmware is missing**. Existing package ownership/hold/firmware descriptor conflict still needs review. |
| Missing original `tee` log | Not found at `/home/charan/CAPEv2/installer/kvm-qemu-all.log` | Only this **expected path** is unverified/missing. Do not claim no log exists anywhere. The user separately supplied a partial 9,154-line build excerpt. |
| Reboot | `/var/run/reboot-required` exists | **Reboot is pending**, but not approved or executed by the assistant. Verify kernel module config and network persistence before considering it. |

**Blockers before relying on virtual machines after reboot:** review malformed/blacklisted KVM module, persistent or dedicated libvirt network, guest route isolation, and package/firmware health. Restore host TCP SYN-cookie security rather than carrying a weakened global setting into production. These changes require an authorized manual plan; do **not** rerun `kvm-qemu.sh all`, reboot, or reconfigure services automatically.

## Automation implementation and evidence

- Added [`scripts/audit_step7_postbuild.py`](../scripts/audit_step7_postbuild.py), which reads an uploaded text report **offline** and emits only structured booleans and fixed diagnostic codes. It never executes shell commands, starts VMs, changes networking, installs packages, or approves live-malware execution. Optional JSON outputs are new private files with mode 0600.
- Added [`scripts/test_audit_step7_postbuild.py`](../scripts/test_audit_step7_postbuild.py) with **14 local synthetic unit tests**, all passing on the separate test environment.
- The checker was additionally run on the **actual supplied** post-build report and classified it **`REVIEW_REQUIRED`**. Positive check flags included executable versions, libvirt/QEMU connection, KVM acceleration and active `libvirtd`. It raised **11 review/blocker diagnostic categories** for transient network/autostart, session group memberships, malformed module config and blacklist policy, disabled SYN cookies, masked power targets, held qemu package, missing log at expected path, pending reboot. This is static report analysis, not an independent on-host inspection.
- Verified source file hashes (Git blob) in the repository: auditor `209b7297e03222f5969e6e644e8a72bb68880799`; tests `6c07c0cd125152ed4d8bdce6a086101a8a8c73f3`. The committed files match those tested locally.
- No claim of guest network isolation, fresh-Ubuntu compatibility, Windows VM bootability or overall CAPEv2/INetSim deployment is warranted.

## Suggested next user-led step

Gather a **read-only targeted report** of the network XML/bridge and remaining settings before manual repairs:
- `sudo virsh -c qemu:///system net-info default`
- `sudo virsh -c qemu:///system net-dumpxml default`
- `ip -br link`, `ip -4 -br addr show virbr0` (if present), `ip -4 route`
- `id`, `id charan`, `getent group kvm libvirt`
- `sudo nl -ba /etc/modprobe.d/blacklist-kvm.conf` (review whether the file is safe to change)
- `sysctl net.ipv4.tcp_syncookies`, plus `grep -R -n -E '^net.ipv4.tcp_syncookies' /etc/sysctl.conf /etc/sysctl.d/ /usr/lib/sysctl.d/` for persistence source
- `systemctl status libvirtd --no-pager` or `systemctl is-enabled` as needed.

No host-side changes have been made by the assistant. **Do not enable the NAT default network for live malware guests**; the final design requires a dedicated, verified isolated analysis network.
