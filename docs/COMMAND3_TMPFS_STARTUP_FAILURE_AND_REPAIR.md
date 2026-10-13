# CAPE tmpfs startup failure and repair (2026-10-13)

## Verified host evidence (reported by operator)

On SSL-55 the operator restarted cape, cape-processor, cape-rooter,
cape-web and suricata. Four units reported active, but **cape.service**
repeatedly showed activating/auto-restart, exit status 1. Journal:

    CuckooStartupError: Fix permission on tmpfs path: chown cape:cape /mnt/tmpfs/

The operator previously enabled CAPE [tmpfs] and configured
freespace = 4096. A correct mounted tmpfs path must be writable/owned
by the cape service account. No remote host operation was executed by
the assistant, and the operator has not yet uploaded the repair report.

## Guarded immediate recovery (reference SSL-55, operator-only)

A full pasteable shell block was provided in chat; it saves a
CAPE_Tmpfs_Repair_YYYYMMDD_HHMMSS.txt report to the user's home and:

1. Confirms system user/group cape exist and exact /mnt/tmpfs is not a symlink.
2. Checks with findmnt --mountpoint /mnt/tmpfs that this exact directory
   is actually a mounted tmpfs. IF NOT, STOP without any chown.
3. Changes **only** the mounted directory owner (not recursively)
   to cape:cape, checks cape has write permission, and prints free space.
4. Restarts **only** cape.service; reports all five unit states
   and recent errors.
5. Reports further failures for operator to upload and review.

Never chown an unmounted /mnt/tmpfs directory to paper over an
absent tmpfs: memory dumps may then land on the root filesystem.
Do not claim repair successful until the report proves it.

CAPE upstream discusses the expected CAPE tmpfs mount and ownership:
- https://github.com/kevoreilly/CAPEv2/issues/2077
- https://capev2.readthedocs.io/en/latest/usage/start.html

## Added fail-closed development support for fresh hosts

scripts/command3_cape_tmpfs.py:

- Read-only --mode plan validates the exact [tmpfs] stanza, the
  configured path /mnt/tmpfs, exact mounted tmpfs filesystem,
  cape UID and GID ownership, directory owner permissions and
  available MiB >= the configured freespace threshold.
- --mode repair-owner is ONLY for a separately approved **other**
  host after root and exact typed interactive consent. It rechecks
  the state and uses fchown on an opened, verified mount directory FD.
  It never recursively changes contents or changes permissions,
  mount, fstab, services, guests, snapshots or network rules.
- Repair refuses unmounted/missing tmpfs, insufficient free memory,
  disallowed mount mode, and protected reference SSL-55.

scripts/command3_cape_services.py now includes the read-only
tmpfs gate. Regardless of systemd statuses, mount/owner/capacity
problems remain an explicit startup blocker. All untrusted analysis
and network-containment release gates remain in place.

## REQUIRED persistent boot behavior (not yet implemented end-to-end)

Ownership changes on a tmpfs mount may not survive remount/reboot.
A fresh-host Command 1 installer and future Command 3 orchestrator
must implement these steps before being called unattended-complete:

1. Create cape user/group before mounting tmpfs.
2. Check host RAM/swap, VM count and maximum concurrent Windows
   memory dump requirements. Never assume all hosts have space for
   the source example's 50 GiB tmpfs.
3. Reconcile existing fstab and mount units. Refuse foreign mounts
   or duplicate/conflicting mount declarations.
4. Create a persistent boot-time tmpfs mount with explicit owner IDs,
   permissions, and host-sized capacity. Example ONLY, not to paste:

       tmpfs /mnt/tmpfs tmpfs rw,nodev,nosuid,noexec,mode=0750,uid=<ACTUAL_CAPE_UID>,gid=<ACTUAL_CAPE_GID>,size=<APPROVED_SIZE> 0 0

5. Ensure the filesystem mounts before cape.service starts,
   e.g. an appropriate systemd RequiresMountsFor=/mnt/tmpfs dependency
   matched to the installed service/mount design. Preflight on every
   startup that ownership and capacity remain correct.
6. Validate a benign reboot and verify cape.service stays active,
   with no repeated CuckooStartupError.
7. Preserve firewall / INetSim containment: an active cape.service
   is NOT permission to execute malware or proof of safe routing.

This document records a fix and verified offline code components,
NOT a completed physical new-machine installation or TPM-safe VM restore.

## Correct systemctl syntax

    sudo systemctl status cape.service --no-pager -l
    sudo journalctl -u cape.service -n 60 --no-pager

The earlier --no.pager variant and uppercase -L option are invalid.
