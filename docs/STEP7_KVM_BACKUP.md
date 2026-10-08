# Step 7A — Verified backup of SSL-55 KVM module configuration

**Observation date:** 2026-10-09. **Manual evidence:** User-uploaded `SSL55_Step7_KVM_Backup_20261009_030850.txt` (36 physical lines / 37 indexed lines). **Status: backup verified; malformed configuration NOT YET MODIFIED.**

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

## Scope of proposed Step 7B — awaiting user execution

Replace the **first malformed line only** with a comment that preserves its original text; leave the second, syntactically valid `blacklist kvm` line unchanged until its intended policy has been reviewed. This removes the warning from the first line while avoiding an unapproved behavioral change to valid blacklisting. It is not proof of KVM reboot safety.

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

**Local simulation:** A Bash fixture containing the observed two lines produced the expected SHA-256. The proposed one-line `sed -i` substitution was tested on that fixture, and the full resulting file matched the expected output, retaining owner/mode in the fixture. **Not executed on SSL-55 yet.**

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
