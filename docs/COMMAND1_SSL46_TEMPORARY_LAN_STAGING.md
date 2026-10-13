# SSL-55 → SSL46 → private encrypted Google Drive: exact golden-master storage

**Operator change:** Do NOT clean or delete anything on SSL-55 or
`/home/ssladmin`. Use **CSE-SSL-46** at **10.23.105.46** with **347 GB
available**, on the same trusted LAN, as TEMPORARY STAGING storage
for original `win11`'s 64-GiB virtual / 3-layer backing-chain Windows
disk plus domain XML, OVMF VARS and ORIGINAL MASTER swtpm private blobs.

**Engineering implementation:**
`scripts/command1_ssl46_sshfs_master_stage.py` is exposed as
`bash scripts/command1_pre_vm.sh ssl46-lan-stage`.

This uses the EXISTING guarded `command1_export_existing_master.py`
cold exporter, not a new ad hoc file copy of only one QCOW2 overlay.
QEMU reads the intact three-layer live *file chain* on SSL-55 and
writes one **flattened, independent** QCOW2 to a mounted remote SSHFS
directory backed by the SSL46 disk. No 64+ GiB intermediate disk is
required on SSL-55.

The export needs **94 GiB free** on the **mount's backing storage**,
not on SSL-55, since the current exporter requires virtual-size+30GiB.
SSL46's actual operator report identifies **347G available** on
`/dev/nvme0n1p2` (ext4 `/`). Still verify remote `statvfs`
after mounting the exact private staging folder. Space
from a different partition is irrelevant. Future new-host import still
needs disk+40GiB reserve independently.

The remote SMB/NFS port need not be opened: SSHFS carries filesystem
operations over authenticated, encrypted SSH/SFTP. The SSH key and host
fingerprint must be trusted by the operator. The Ubuntu 24.04
`sshfs` package supports `idmap=user` to map the remote SSH user's
UID/GID to the local mounting UID/GID. For running the existing
root-only Windows/TPM exporter, SSHFS must run **as root on SSL-55**,
with `idmap=user,default_permissions` and WITHOUT `allow_other`.
It MUST expose the directory on SSL-55 as locally root-owned 0700;
otherwise the exporter will rightly refuse.

Do not SSH directly as root on SSL46; use a dedicated approved normal
account with a fresh private 0700 directory. Root on SSL55 can mount
that remote private path using a root-owned OpenSSH identity file and
a manually checked, PINNED server host key. Password authentication
or root SSH login is not necessary after authorized key setup.

## One-time operator setup (actual SSL46 address and username now known)

The operator has verified **hostname CSE-SSL-46**, SSH user **charan**,
Ethernet IP **10.23.105.46/22**, SSH service **active**, and created the
NEW dedicated empty private folder
`/home/charan/cape-ssl46-private` with owner UID 1005, mode 0700.
No more staging folder creation is required; do NOT overwrite it.
As a first connection safety step, on SSL46 record its SSH server's
ED25519 host-key fingerprint via
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`.
Compare this out-of-band fingerprint to the **SSL55** observed SSH key
before permitting root-owned SSHFS connection. The IP, username and
private path are verified in the operator's 2026-10-13 report.

On SSL-55, install `sshfs` if missing, after package manager review:
`sudo apt-get install sshfs` (can require an operator approval).
Use a dedicated root-owned SSH private key at
`/root/.ssh/cape_ssl46_export`; install ONLY its public half as an
SSH `authorized_keys` entry for the approved SSL46 account.
Manually confirm SSH host's published fingerprint using SSL46's own
terminal BEFORE adding it to root's known_hosts. Never blindly
trust `ssh-keyscan` output without comparing fingerprint.

On SSL-55:
- Create the root-owned empty local mountpoint
  `/mnt/cape-ssl46-export` mode 0700.
- SSHFS mount exactly the SSL46 account's private directory with
  `idmap=user,default_permissions,StrictHostKeyChecking=yes` and
  dedicated IdentityFile. Do not mount over a populated directory.
  Do not use `allow_other`; never create a globally shared export.
- Confirm exact `findmnt --mountpoint /mnt/cape-ssl46-export`,
  `sudo stat -c '%u %a' /mnt/cape-ssl46-export` (expected `0 700`),
  `df -h /mnt/cape-ssl46-export`, and no unexpected source.
  The golden-master stage validates the actual mounted FUSE SSHFS
  `SOURCE`, not just the hostname passed as an option.

## Stages (only after encrypted SSHFS mount is verified)

Choose a safe NEVER-BEFORE-USED bundle ID such as
`cape-master-SSL55-20261013-lan01`. All steps run on SSL-55 as root.
The SOURCE parameter must be EXACTLY the SOURCE string reported
by `findmnt` (example below), not a guessed remote.

First plan, read only:

~~~bash
sudo python3 -B scripts/command1_ssl46_sshfs_master_stage.py \
  --mode plan \
  --sshfs-source 'SSL46_USERNAME@SSL46_IP:/home/SSL46_USERNAME/cape-ssl46-private' \
  --bundle '/mnt/cape-ssl46-export/cape-master-SSL55-20261013-lan01'
~~~

Only after the storage/host/source checks pass, use `--mode export`
and approve each exact, interactive cold export prompt. The existing
exporter is still responsible for:
- SHA and structural checks of ALL original QCOW2 backing layers,
  shut-off master `win11`, domain UUID, XML/OVMF and TPM private files;
- writing flattened 64-GiB virtual QCOW2 to the REMOTE SSHFS directory;
- post-conversion `qemu-img check`, file checksums incl.
  `capture-intent.json`, guest source-state rechecks and a full
  immutable root-private manifest.

Use `--mode verify` on the SAME bundle to hash-check *every byte*
over the encrypted LAN and check mount identity.

**Google Drive upload FROM SSL-55 using the remote staging folder:**
`--mode upload --crypt-remote cape_crypt` re-verifies the exact
SSHFS bundle and uses SSL55's root-owned
`/root/.config/rclone/rclone.conf` private crypt remote.
SSL46 does NOT need Google OAuth or rclone. The data is read via
SSHFS and encrypted by `rclone crypt` before uploading to the
user's personal private Google Drive. The uploader checks remote
bytes via `rclone check --download --one-way` and source SHA
verification again. This is multiple reads of large data and may
take significant LAN/Internet time. Never use a public Drive folder.

**SSL46 is temporary:** the SSHFS remote folder contains sensitive
PLAIN Windows disk and TPM material AT REST until it is removed.
Keep SSH account private and access-controlled. After confirmed
private encrypted cloud upload **and a separate test retrieval and
SHA check on an approved different machine**, the operator may
authorize deletion of exactly this temporary SSL46 export folder.
This automation intentionally provides NO recursive deletion,
`rm -rf`, cloud deletion, source snapshot deletion or auto-cleanup.
Never delete anything just because a transfer started or a CLI
returned an HTTP 200.

## What is NOT established yet

The SSL46 IP/account/folder permissions and destination disk capacity
have been reported, but its SSH host-key fingerprint, the actual
FUSE mount identity and mounted free-space view are not yet observed.
No new remote mount,
cold export, cloud upload or cleanup has been performed by ChatGPT.
SSHFS write/fsync/qemu-img compatibility must be verified with
a **small disposable test file** before the 64-GiB export.

The cold flattened disk does NOT preserve libvirt `Afterfull`
RUNNING RAM snapshot metadata. It preserves installed Windows and
the cold original-master TPM/UEFI state. A new-host boot and fresh
TPM-consistent running master checkpoint remain required for CAPE
restoration and multi-VM acceptance.

Official SSHFS option reference (Ubuntu 24.04):
<https://manpages.ubuntu.com/manpages/noble/man1/sshfs.1.html>
