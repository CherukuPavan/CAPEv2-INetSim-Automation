# SSL-55 storage recovery: inspect first, protect the exact Windows master

**Evidence:** Source report `CAPE_SSL55_DeepReference_20261013_105259.json`
supplied by the operator. Master `win11` is shut off, 64-GiB virtual
QCOW2 with **THREE backing layers**. `Afterfull` records running
state with **external memory**. Current /var/backups and
/var/lib/libvirt/images each show 48.41 GiB free (likely same
filesystem; compare device IDs instead of adding capacities).

Current conservative cold-source exporter requires **64 + 30 =
94 GiB free total**. Additional free space needed from the reported
location: **45.59 GiB**. It is NOT 94 GiB extra, and 400 GB initial
disk size does not mean 400 GB is safely reclaimable.

## Guardrails

Do NOT delete/move/truncate/modify any:
- `/var/lib/libvirt/images` QCOW2, arbitrary numeric-suffixed
  `win11.*` overlays, snapshots, guest disks, external saved-memory
  files, original master `win11`, `win11_trial_1`, `win11_1`
  or their linked backing files.
- Libvirt VM XML, `/var/lib/libvirt/swtpm` TPM blobs, guest firmware
  NVRAM VARS or external `Afterfull` saved-memory metadata.
- `/opt/CAPEv2`, CAPE storage/analysis reports, VM Agent/monitor files,
  PostgreSQL, MongoDB, local private backups, CA certificates, INetSim,
  GitHub credentials, root rclone configuration or encrypted Drive keys.
- Personal files from Downloads/Trash, or unknown Docker/snap data,
  without inspecting with the operator. A large folder is not
  evidence that it is expendable.
- Never run generic `docker system prune --volumes`,
  `virsh snapshot-delete`, `qemu-img rebase`,
  `rm -rf /var/lib`, or delete any original VM image to make room.

If any file is part of the QCOW2 backing chain, its deletion may
permanently invalidate the only source master. The 16-GiB runtime
`/mnt/tmpfs` is tmpfs (RAM-backed), NOT evidence of 16 GiB
reclaimable physical storage.

## No-deletion disk audit

Once authenticated and on the GitHub `development` checkout:

~~~bash
umask 077
REPORT="$HOME/CAPE_SSL55_SafeSpace_$(date +%Y%m%d_%H%M%S).json"
sudo -v
sudo python3 -B scripts/command1_ssl55_safe_space_audit.py \
  --storage-dir /var/backups > "$REPORT"
chmod 600 "$REPORT"
echo "$REPORT"
~~~

This measures only *aggregate* space in selected locations (via
`du -x`), filesystem IDs/capacity and real source QCOW2 metadata.
It explicitly reports **zero deleted bytes**. It does not expose
private home filenames. The directory sizes OVERLAP (for example,
`/var` includes `/var/lib/libvirt`); **DO NOT add them together**.

Because the repository is PRIVATE, unauthenticated GitHub raw
`curl` is not a supported way to fetch this script. See
`docs/PRIVATE_DEPLOYMENT_SOURCE_AND_GDRIVE_HANDOFF.md` for
authenticated GitHub source checkout.

If no GitHub checkout exists on SSL-55, the operator may instead run
the self-contained read-only fallback in the ChatGPT instructions and
upload the resulting TXT. Do NOT run arbitrary downloaded shell
cleanup scripts without review.

## What may be considered only AFTER seeing actual sizes

Potentially dispensable **review-only**: Ubuntu APT downloaded package
archives, user `pip` and Poetry download/build caches, old thumbnail
caches, user Trash with individually approved contents, and journal
rotation/retention adjustments if logs are no longer required.
These may only save a few GiB. None should be cleaned automatically,
and old CAPE forensic logs may be important evidence.

If independently approved cleanup provides fewer than 45.59 GiB, use
a separate mounted storage location with **94 GiB or more free** as
the export destination parent. It must be a real, trusted root-owned
non-group/world-writable directory and the exporter must run against
that filesystem. Copying the export folder within the same filesystem
does NOT create free space. The private Google Drive crypt remote
encrypts/uploads the completed bundle, but does not eliminate
the current local QCOW2 conversion headroom.

No deletion has been performed by the assistant, code, tests or
GitHub workflow. Physical storage inspection and every actual
cleanup require operator review and local execution.
