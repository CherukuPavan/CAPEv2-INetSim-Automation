# Step 7E — KVM module policy and dry-run validation (SSL-55)

**Date of observation:** 2026-10-09. **Input:** User-uploaded `SSL55_Step7E_KVM_Policy_20261009_032931_nSxfpAHQ.txt` (66 physical lines / 67 indexed lines). **Result:** Step 7E diagnostics COMPLETE; currently loaded KVM functioning; **module-loading policy and post-reboot behavior require review**. All checks were run **by the user**, not the assistant. No host changes were made.

## Evidence-backed findings

- Host kernel: `7.0.0-34-generic`. `/etc/modprobe.d/blacklist-kvm.conf` now contains one comment preserving the earlier malformed text and one valid `blacklist kvm` rule, `root:root` mode `0644`. `modprobe --showconfig` reports parsing **PASSED**: Step 7B correction remains effective.
- Effective KVM rules: `blacklist kvm`, `options kvm ignore_msrs=Y`, `options kvm report_ignored_msrs=N`. The latter two are present in `/etc/modprobe.d/kvm.conf`. These KVM options can affect unsupported guest MSR behavior and troubleshooting; they should be explicitly validated against intended guest OS/software and not silently enabled on other machines.
- `kvm` and `kvm_intel` are loaded; `irqbypass` is also present. `/dev/kvm` exists, `libvirtd` is active. Module files `kvm.ko.zst` and `kvm-intel.ko.zst` exist for the running kernel.
- `modprobe --dry-run --verbose kvm`, `modprobe --dry-run --verbose kvm_intel` and `modprobe --dry-run --verbose --use-blacklist kvm_intel` all returned **SUCCESS**. None loaded modules. **A dry run, particularly while KVM is already loaded, does not prove cold-boot autoload or absence of future module/policy problems.**
- No explicit KVM entries were shown in the scanned `/etc/modules` or systemd modules-load configurations. That is **not automatically a defect**: libvirt/QEMU or udev may load modules when needed, and the provided scans did not establish every possible boot-time path.
- Post-Step 7D active `net.ipv4.tcp_syncookies=1` confirmed again, independent corroboration of the earlier correction. Persistent sysctl and post-reboot behavior were not retested in this Step 7E report.
- The report states no configuration edits, module loads/unloads, service restarts or reboot.

## Significance of `blacklist kvm`

The remaining blacklist is a **valid** modprobe rule. Blacklists generally affect alias-based module autoload; they do not universally deny explicit `modprobe` invocation or dependency resolution. **Do not interpret the successful dry run as proof that the rule does nothing.** Conversely, **do not interpret the rule as evidence that KVM is currently broken**: runtime and system-libvirt evidence confirm it is working.

**Decision:** Keep the valid rule unchanged pending review of local administrator intent. There is no basis here for blindly deleting it, resetting module configuration, unloading/reloading modules or initiating a reboot. A controlled reboot, if later approved, requires a recovery/console plan and post-boot `lsmod`, `/dev/kvm`, `kvm-ok` and libvirt runtime verification. No live malware guest may use the existing `default` NAT network regardless.

## Portability/automation acceptance criteria

- A fresh supported host may use Intel `kvm_intel` or AMD `kvm_amd`, different distro/kernel module paths, compiled-in modules, and different effective configuration across `/etc`, `/run`, and `/usr/lib`; never hardcode SSL-55's `blacklist-kvm.conf` or current kernel version.
- Audit all applicable **effective** directives, distinguishing `blacklist`, `install`, `remove`, `options`, manual module configuration and already-loaded modules. Do not rely on `modprobe --dry-run` as a sole reboot gate.
- Separate the presence of a blacklist, **host administrative approval to alter it**, and observed runtime functionality. Detect anomalies and fail clearly rather than overriding policy silently.
- Verify MSR `ignore_msrs`/`report_ignored_msrs` values and effects against the supported CAPEv2/QEMU/Windows configuration; do not propagate them across arbitrary hosts without assessment.
- Require a real post-reboot check and guest isolation tests before claiming any deployment production-ready.

## Follow-on step

Review power-management state **read-only** (sleep/suspend/hibernate targets were masked by the upstream installer), and decide if that fits the specific workstation's policy before changing anything. The approved future analysis network is **dedicated and non-forwarded**, separate from the current transient libvirt NAT `default` network.

Related records: [STEP_LOG.md](STEP_LOG.md), [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md), [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md), [PORTABILITY.md](PORTABILITY.md).
