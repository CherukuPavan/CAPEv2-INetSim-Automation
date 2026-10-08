# Step 7F — Persistent systemd sleep and hibernation mask review

**Observed 2026-10-09 on CSE-SSL-55.** Source: user-uploaded `SSL55_Step7F_PowerPolicy_20261009_033421_F3D5iOPz.txt` (93 physical lines, 94 indexed lines). The user executed a **read-only** diagnostic; assistant did not alter SSL-55.

## Verified evidence

| Target | Enabled, LoadState and UnitFileState | Persistent definition | Runtime override |
| --- | --- | --- | --- |
| `sleep.target` | `masked` | `/etc/systemd/system/sleep.target -> /dev/null` | None observed |
| `suspend.target` | `masked` | `/etc/systemd/system/suspend.target -> /dev/null` | None observed |
| `hibernate.target` | `masked` | `/etc/systemd/system/hibernate.target -> /dev/null` | None observed |
| `hybrid-sleep.target` | `masked` | `/etc/systemd/system/hybrid-sleep.target -> /dev/null` | None observed |

The masks were shown as root-owned symlinks under `/etc/systemd/system/`, each resolving to `/dev/null`, not merely transient masks in `/run/systemd/system`. The mask symlinks were timestamped on the installation date. The local `~/CAPEv2/installer/kvm-qemu.sh` line 76 was observed to contain:

```bash
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```

This strongly associates the masks with the installer, but **does not establish whether local host administrators intended to keep that policy**. The report also shows a reboot-required marker, and confirms no masking/unmasking, service restart or reboot was performed in this Step 7F check.

## Interpretation and next decision

Systemd masked units cannot be activated normally while masked. These four targets control sleep, suspend, hibernate and hybrid sleep. Long CAPEv2 analyses may benefit from preventing accidental suspend, whereas the masks could interfere with an ordinary Ubuntu desktop or institutional power policy. This is a **host-operating-policy decision**, not an automatic package-repair error.

**Step 7F diagnostics: PASS. Policy decision: PENDING.** Do not unmask/mask any target until the owner chooses whether SSL-55 is to remain awake as a dedicated analysis host or restore ordinary workstation power modes (and confirms permission to alter the host's policy). If restoration is chosen, inspect potential inhibitors/logind settings, preserve exact symlink state in a protected backup/journal, and propose narrow, separately approved commands with post-change checks. Do not blindly apply a four-target `systemctl unmask` on a shared machine.

This does **not** authorize a reboot or certify post-reboot KVM loading, libvirt networking, or malware isolation. The existing `default` libvirt network is NAT and transient; guest containment remains unverified. The valid `blacklist kvm` directive also remains under policy review.

## Automation evidence and release requirements

- Added [`scripts/audit_step7f_power_policy.py`](../scripts/audit_step7f_power_policy.py), a **read-only offline report parser**. It records boolean/status results for each exact target and persistent symlink, excludes raw host-identifying lines, refuses to authorize unmask/reboot/guest execution and never runs `systemctl`.
- Added [`scripts/test_audit_step7f_power_policy.py`](../scripts/test_audit_step7f_power_policy.py). **14 isolated synthetic tests passed**, including missing/inconsistent targets, runtime-vs-persistent mask evidence, missing installer command, missing end marker, redaction and no safety claims.
- The offline checker was executed against the **actual user-uploaded Step 7F report** and returned `PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED` with four `PERSISTENTLY_MASKED` target states and no parsing anomalies.
- The verifier and tests were developed/tested in a separate environment, **not** deployed on SSL-55. The final three-command automation must not impose upstream's top-level `systemctl mask` on every fresh Ubuntu host, and must treat an operator-approved no-sleep policy separately from virtualization dependency readiness.

Related: [STEP_LOG.md](STEP_LOG.md), [ROADMAP.md](ROADMAP.md), [PORTABILITY.md](PORTABILITY.md), [STEP7E_KVM_POLICY.md](STEP7E_KVM_POLICY.md).
