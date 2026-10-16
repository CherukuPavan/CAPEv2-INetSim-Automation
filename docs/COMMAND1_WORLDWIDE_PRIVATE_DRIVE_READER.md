# Worldwide golden-master retrieval without personal Google login

**Status (2026-10-13): developer-stage and offline-tested. Physical service
account authorization, cloud download and Windows restore are still pending.**

This design works on a supported Ubuntu computer **anywhere with outbound
Internet**, including a machine on a completely different LAN from CSE-SSL-55.
It never depends on CSE-SSL-55/46 being online or accessible to the target.

## Why a public folder is unnecessary

The actual operator-approved master was exported from SSL55 to private SSL46
SSHFS, uploaded using SSL55's `cape_crypt`, and **crypt remote byte-compared**
against the source. Log `CAPE_GoogleDriveUpload_20261013_124755.txt`
completed with `SSL46_STAGED_MASTER_PRIVATE_DRIVE_VERIFIED`, exit 0 on
2026-10-13 at 13:59:35 UTC. An independent other-host download is *not* yet
proven. Do **NOT** delete the SSL46 copy.

Do **NOT** turn on “Anyone with the link.” A public URL is not used.
We need to authenticate a machine to read a private Drive folder; there is no
magical private anonymous download. A dedicated Google Cloud **service
account** provides non-personal authentication. It cannot access the user's
other private folders unless they are separately granted to that service
account. Google account credentials, service-account keys and crypt passwords
must never be committed to GitHub, supplied to ChatGPT or stored in plaintext
in a public download script.

## One-time preparation by the Drive owner

1. Create a dedicated Google Cloud **service account**, enable Drive API for
   its project and provision a JSON service-account private key using Google's
   trusted Cloud Console. Prefer one **dedicated account per deployment**
   that you can revoke independently.
2. Open the encrypted **parent** folder
   `My Drive/cape-private-encrypted` in Google Drive (NOT the entire My Drive,
   NOT the deeper `master-backups` child). Copy its **folder ID** from the
   browser address, not the folder contents or any file link.
3. Share *only that encrypted parent folder* with the service-account
   `client_email` as **Viewer**, keeping General access set to **Restricted**.
   The viewer must be able to read its `master-backups` child.
4. Deliver that JSON key separately to your trusted new Ubuntu host using a
   secure, private out-of-band channel (e.g., personally controlled removable
   drive or end-to-end encrypted file delivery). The public folder ID alone
   does **not** authenticate. Protect the key as a password.
5. Preserve the original `cape_crypt` password and **password2/salt if one
   was configured**. Both are necessary to decrypt this particular backup.
   The new host must use the exact original values, not fresh random ones.
   Keep them in a password manager; never paste secrets into chat.

## Steps on the approved new target host (NOT SSL55)

Preconditions: verified private GitHub `development` checkout (pinned commit),
existing `rclone` command, root `/root/.config/rclone` folder with mode 0700,
internet connectivity, and the private Google service-account JSON at
`/root/.config/rclone/cape-service-account.json` (owner root, mode 0600).
Install software only through separately approved host bootstrap; this helper
does not modify QEMU/CAPE/network.

```bash
sudo install -d -m 0700 -o root -g root /root/.config/rclone
# Copy the service-account key privately to that directory first;
# never make it world-readable or paste its contents.
sudo chmod 0600 /root/.config/rclone/cape-service-account.json

# Read-only preflight; replace both placeholders with ACTUAL new-host values:
sudo python3 -B scripts/command1_worldwide_drive_reader.py \
  --mode plan \
  --approved-host NEW_TARGET_HOSTNAME \
  --service-account-file /root/.config/rclone/cape-service-account.json \
  --shared-parent-folder-id ACTUAL_PARENT_FOLDER_ID
```

After reviewing the plan, run the **same** command with
`--mode setup`. The helper asks for typed consent and **twice asks for the
same original crypt password** using a no-echo prompt. The original optional
crypt salt password is separately requested. It creates only
`/root/.config/rclone/cape_world_readonly.conf` root 0600, using rclone's
`drive.readonly` scope, a service-account key **path**, and a crypt wrapper
for the encrypted `master-backups` child. It does not overwrite another
rclone config, call personal Google OAuth, leak passwords in CLI argv, install
packages or modify any guest. It cannot verify the Google folder ACL.

Before any large download, check the crypt remote **without writing data**:

```bash
sudo -H rclone --config /root/.config/rclone/cape_world_readonly.conf \
  lsf 'cape_crypt:cape-master-SSL55-20261013-lan01' --max-depth 1
```

If there is an error or expected encrypted files are not visible, **STOP**.
Do not fall back to raw `cape_drive` or a public folder. An incorrect
`root_folder_id`, missing share, crypt password/salt mismatch or unsupported
Google Cloud service-account policy can cause this; none is resolved by
publishing the folder. Avoid posting confidential logs or config contents.

Existing canonical root-only downloader needs NO personal OAuth and can
use the newly created dedicated config via its `--rclone-config` option:

```bash
sudo python3 -B scripts/command1_private_drive_bundle.py \
  --mode plan-download \
  --approved-host NEW_TARGET_HOSTNAME \
  --bundle-id cape-master-SSL55-20261013-lan01 \
  --destination /ROOT_PRIVATE_EXISTING_PARENT/cape-master-SSL55-20261013-lan01 \
  --crypt-remote cape_crypt \
  --rclone-config /root/.config/rclone/cape_world_readonly.conf
```

Only after reviewing available disk space, private destination permissions,
cloud inventory and machine identity should the operator use
`--mode download`, which requires another typed approval and SHA-256 validates
the **complete** master manifest. Alternatively the existing
`command1_private_master_stage.py` accepts the same `--rclone-config` and
combines download and protected VM cold import after additional approvals.
Neither command creates a running snapshot or attests Windows boot.

**Security after test:** delete/revoke the per-target service-account key
in Google Cloud, remove its Drive folder share and clean up target credentials
only with explicit operator approval. The untrusted source/master and its
backing chain must never be deleted or auto-reverted.

## Full three-command release gates remain

* **Command 1** complete portable CAPEv2/DB/host bootstrap, imported Windows
  real boot, Agent validation and TPM-coherent running snapshot are not done.
  INetSim is **deferred by operator request**, not silently claimed installed.
* **Command 2** guarded N-VM sequencer exists but new-host Windows boots,
  identity/static-IP (guest static vs DHCP reservation) and TPM-coherent
  restorable live snapshots are not yet physically proven. A standard libvirt
  running snapshot does **not** atomically restore external swtpm state.
* **Command 3** five configuration editors and five-service restart are
  implemented; routing.conf's observed `internet=virbr0` is unsafe to
  auto-apply and remains explicitly blocked. Real destination service
  acceptance and snapshot restore are not complete.

The reader is a concrete secure **worldwide access component**, not permission
to skip those release blockers. For source-of-truth progress see
`docs/THREE_COMMAND_PREDEPLOYMENT_AUDIT_20261013.md`.

## References

* https://rclone.org/drive/ (service_account_file, drive.readonly,
  root_folder_id and sharing with service-account)
* https://rclone.org/crypt/ (crypt password and salt compatibility)
* https://rclone.org/commands/rclone_obscure/ (password via stdin, no CLI argv)

## 2026-10-17 SHA-256 trust anchor for original SSL46 master

The user's original 2026-10-13 export and encrypted upload logs independently
record manifest SHA-256 `709b67bd2ddbe85ffc957ab34bb97f5c4bc49f7b32b7eff2d08de4588a860d2a`.
A connected Drive metadata check found six ciphertext objects. The 32,057,353,456
byte ciphertext object exactly matches the rclone crypt length for the originally
exported 32,049,528,832-byte Windows QCOW2: 32-byte header plus 16 bytes per
64 KiB chunk. This establishes size consistency, **not decrypted integrity**.

The joined private handoff now automatically pins that independent SHA-256
when restoring the known `cape-master-SSL55-20261013-lan01` bundle.
A substituted *decrypted* manifest is rejected before VM import. The
download retains partial private bytes for audit on failure. Standalone
downloaders may use `--expected-manifest-sha256`. This does not supply
private service-account access, the source crypt passphrase, guest boot,
running-snapshot acceptance, isolated network routing or full rollback.
