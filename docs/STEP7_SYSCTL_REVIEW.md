# Step 7C — SSL-55 SYN-cookie sysctl identity review

**Date:** 2026-10-09. **Input:** User-uploaded `SSL55_Step7C_SysctlReview_DeiDOi9A.txt` (32 physical lines, 33 indexed lines). **Result:** read-only inspection COMPLETE; configuration **NOT YET CHANGED**. Do not commit the raw report with host identities.

## Verified evidence

- Current running `net.ipv4.tcp_syncookies = 0` (SYN-cookie protection disabled).
- `/etc/sysctl.conf` is a regular file, `root:root`, mode `0644`, size 2804 bytes at observation; the relevant setting is at **line 77**: `net.ipv4.tcp_syncookies = 0`.
- `/etc/sysctl.d/99-sysctl.conf` is a symbolic link **`-> ../sysctl.conf`**.
- Both names resolve to **`/etc/sysctl.conf`**; `stat -L` reported device `66306`, inode `56754617` for both paths. **This is one underlying file, not two independent sysctl definitions.**
- The recursive grep printed two identical matches only because it traversed both names. Do **not** change both names independently, break/recreate the symlink, or append extra duplicate settings.
- No other setting was found in the directories queried by that user's command (`/etc/sysctl.conf`, `/etc/sysctl.d`, `/usr/lib/sysctl.d`, `/run/sysctl.d`). This report alone does not prove every possible config source or future policy override has been inspected.

## Security and correction intent

The value `0` disables TCP SYN-cookie functionality. For an Ubuntu host using TCP/IP networking, the normal protective setting is `net.ipv4.tcp_syncookies = 1`, unless host administrators have an explicitly reviewed contrary policy.

**Step 7D is a proposed, approval-gated manual change, NOT executed.** A safe procedure should:
1. Require explicit operator authorization, inspect exact current file/alias identity, reject unexpected symlinks or changed metadata, and insist on exactly one active `net.ipv4.tcp_syncookies = 0` definition at the expected line; never blindly append settings or edit both paths.
2. Check for additional conflicting persistent definitions and unknown local policy. Preserve other sysctl keys and comments unchanged.
3. Create a root-only, checksum/byte-verified backup of the **single canonical file**, and keep the restoration path available; never expose backups with full host settings in GitHub.
4. Apply only the exact key-value change on `/etc/sysctl.conf` from `0` to `1`; preserve ownership, mode, unrelated file contents and the existing symlink.
5. Apply **only** `net.ipv4.tcp_syncookies=1` at runtime with `sysctl -w` after verifying the durable file, not a broad `sysctl --system` that could load unrelated and risky settings.
6. Re-read the current value, persisted file, resolved symlink and effective override information; collect a private single report. If any verification fails, stop; do not unilaterally reset other host settings or reboot.
7. Do not change libvirt NAT, Docker networking, KVM blacklist, power-management targets, package holds or unrelated sysctls as a side effect.

## Automation work

- Added [`scripts/audit_sysctl_alias.py`](../scripts/audit_sysctl_alias.py), a **read-only**, symlink-aware preflight that compares resolved canonical targets, device/inode, root ownership, active exact settings and optionally the runtime sysctl. Reports are new private JSON files; no changes performed.
- Added [`scripts/test_audit_sysctl_alias.py`](../scripts/test_audit_sysctl_alias.py): **15 synthetic tests passed locally**, including SSL-55-equivalent linked layout, independent files, duplicates, missing/broken paths, comments, runtime read-only behavior and data non-modification.
- Both committed files match the locally tested Git blobs: module `2c7a6b1684426f37016f094de2d80c4c347a6f74`; tests `c01d868293894e700b086bc6886374b752df1bf7`.
- **Not verified** on SSL-55 directly; the real user file supplies the layout evidence. No production auto-remediation component or complete cross-Ubuntu acceptance exists yet.

## Portability cautions

Other supported Ubuntu releases or hardened hosts may have missing aliases, independent override files, different config precedence or explicit policy. A future installer must **discover** source policy rather than assume SSL-55's inode, username, line number or file layout. A read-only preflight cannot authorize an unattended global sysctl rewrite. Do not declare the hypervisor ready for Windows malware analysis: KVM module blacklist intent, persistent NAT network and guest isolation remain unresolved.

Related: [STEP_LOG.md](STEP_LOG.md), [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md), [PORTABILITY.md](PORTABILITY.md).
