# Step 7A — Verified backup of SSL-55 KVM module configuration

**Observation date:** 2026-10-09. **Manual evidence:** User-uploaded `SSL55_Step7_KVM_Backup_20261009_030850.txt` (36 physical lines / 37 indexed lines). **Status: Step 7A backup verified; subsequent Step 7B first-line correction completed and verified.**

## Verifiable evidence

- Original: `/etc/modprobe.d/blacklist-kvm.conf`, `root:root`, mode `0644`, 37 bytes.
- Restricted backup: `/root/SSL55_KVM_Backup_yTIScjEU/blacklist-kvm.conf`; original command reported backup verification **PASSED**.
- Source and backup SHA-256: `d172d41f94534d38db5a0f3cb489313e45c89a47e23007693e7e29775d6052c1` (both match).
- Exact contents prior to any approved correction:
  ```text
  -e blacklist kvm_intel
  blacklist kvm
  ```
- `modprobe --showconfig` reported a **libkmod parse error** for malformed first line. It also listed active `blacklist kvm`, `options kvm ignore_msrs=Y` and `options kvm report_ignored_msrs=N`. These options may affect malware-analysis guest behavior but were **not changed** by the backup operation.
- `lsmod` showed `kvm_intel` and `kvm` loaded, and `/dev/kvm` exists with owner root/group kvm. Current loading does not prove reboot-time loading.

## Historical Step 7B correction specification — executed and verified later

The subsequently **executed** Step 7B procedure replaced the **first malformed line only** with a comment preserving its original text; the second, syntactically valid `blacklist kvm` line remains in force until its intended policy is reviewed. This removed the warning without changing that valid blacklist. This does not prove KVM reboot safety.

The procedure to provide to the user must:
1. Require sudo authorization and fail on errors.
2. Check the expected SHA-256 **and** exact byte-for-byte comparison with the protected backup; stop if either differs (never blindly edit changed files).
3. Reject a symbolic-link or unexpected file type; verify intended file metadata and expected two-line source.
4. Use a single anchored replacement targeting first line only.
5. Verify the resulting exact two-line file and preserved root:root 0644 metadata.
6. Run read-only `modprobe --showconfig` after the edit; collect warnings/errors and status without applying modules.
7. Log what changed to a private single TXT report. Do not print unrelated secrets or copy the root-only backup out of its protected directory.
8. Do not unload/reload modules, reset firewall, start/stop libvirt, auto-remove the remaining blacklist, change boot configuration, or reboot.
9. Separately determine whether the remaining `blacklist kvm` directive is permitted and compatible with future automatic module loading. If not, propose an explicitly approved backup-first change after reviewing host policy and other module files.

**Prior local simulation:** A Bash fixture containing the original two lines reproduced the expected SHA-256, and the one-line substitution yielded the expected output. **The user has now separately executed and verified the correction on SSL-55**, per the report below.

## Step 7B results from user-executed correction (2026-10-09)

Source: `SSL55_Step7B_KVM_Correction_2icT1bAB.txt` (uploaded by user; not committed as a raw log). The manual script reported its source-backup preflight **PASSED**, applied exactly the anchored first-line change and verified exact final contents:

```text
# Malformed directive preserved for review: -e blacklist kvm_intel
blacklist kvm
```

The source remained `root:root` mode `0644`. Read-only `modprobe --showconfig` completed with **no stderr**, and the expected `blacklist kvm` directive was present. The `kvm_intel` and `kvm` modules remained loaded; **no module reload or reboot was performed**.

**Acceptance:** Step 7B precise syntax repair **PASS**. The still-valid `blacklist kvm` policy requires separate review before reboot. Existing KVM modules and a clean parser alone do not prove post-reboot autoload behavior. Host `tcp_syncookies=0`, transient NAT default network and masked power targets are independent unresolved issues.

**New automation draft:** [`scripts/audit_kvm_modprobe.py`](../scripts/audit_kvm_modprobe.py) checks one nominated file and optionally the effective `modprobe --showconfig` parsing **read-only**. [`scripts/test_audit_kvm_modprobe.py`](../scripts/test_audit_kvm_modprobe.py) has **14 synthetic tests passing**. On a fixture representing this final file, the detector correctly reports syntax-clean text plus a valid KVM blacklist requiring manual review. Git blob SHA of auditor `1ee3105a30c1e417e0fb2fe3712a2742020017dd`, tests `c4cf1e351d1666f628320a49d41cd62287ff849e`; both matched locally tested files. Neither module modifies host config or declares malware/reboot safety.

## Portable automation lessons

- A new host may not have this config file, may have different filenames, may use another hypervisor driver, or may intentionally blacklist modules. Future automation must **inspect all effective modprobe config**, module state, platform, intended virtualization role, admin policies and permissions rather than install a fixed SSL-55-specific file.
- Read-only detection should separate malformed syntax, *valid* blacklisting, KVM module already loaded and availability after restart. A fail-closed policy must not silently override local organizational security controls.
- A machine-specific SHA-256 is a **concurrency/state guard for this manual instance**, not a portable constant.
- A successful current `kvm-ok` does not guarantee KVM support after reboot. Require a separate, authorized post-reboot verification and recovery plan.

## Related records

- [STEP_LOG.md](STEP_LOG.md) — chronological steps.
- [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md) — prior runtime/network findings.
- [STEP7_POSTBUILD_AUDIT.md](STEP7_POSTBUILD_AUDIT.md) — working libvirt/QEMU baseline and host safety concerns.
- [PORTABILITY.md](PORTABILITY.md) — fresh-machine acceptance gates.
