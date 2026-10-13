# Command 1 — exact master via private personal Google Drive (development)

**Status: coded and offline-tested; NO personal Drive credentials supplied;
no SSL-55 upload/download or new-host import performed.**

The operator has a **personal 5 TB Google Drive** and proposed making
a golden VM archive publicly accessible to new machines. That is **not
required**: use a restricted private Drive folder plus rclone's
**client-side crypt remote**. The source includes the complete Windows
disk, custom installed apps/registry, XML, OVMF VARS and MASTER swtpm
private blobs; never upload it unencrypted or commit it to GitHub.

### Design improvement: no additional huge local encrypted archive

The exact cold source bundle is created by
`scripts/command1_export_existing_master.py` as a directory of verified
files. `scripts/command1_private_drive_bundle.py` transfers those
files through a crypt remote that encrypts **individual file contents
and filenames ON THE FLY** when uploading to personal Google Drive.

A separate 64+ GiB encrypted tar/zip copy on SSL-55 is unnecessary.
The verified cold QCOW2 **export** still requires an output filesystem
with at least the virtual Windows size plus 30 GiB free. The user's
SSL-55 has 48.41 GiB free versus 94 GiB required, so do NOT attempt
the large export there. New [SSL46 remote SSHFS staging](
COMMAND1_SSL46_TEMPORARY_LAN_STAGING.md) sends the flattened output
DIRECTLY onto the user's SSL46 host with approximately 340 GiB free
over encrypted SSH/SFTP. The original three-layer Windows QCOW2 source,
CAPE, snapshots and TPM stay unchanged on SSL-55.

Google Drive is then uploaded FROM SSL-55 through the existing
SSHFS-mounted SSL46 bundle via local root-owned `cape_crypt` remote;
the second machine need not store Drive OAuth secrets. Deleting the
temporary SSL46 plaintext-at-rest bundle is a future separately approved
step ONLY after complete remote byte comparison and independent
download/reverification.

On target hosts, rclone downloads/decrypts into a NEW root-private
directory, then runs the canonical
`command1_export_existing_master.manifest_check` over all exact Windows,
UEFI and TPM member files. That includes expected SHA-256 and byte lengths;
an interrupted transfer is a PARTIAL_OR_UNKNOWN directory preserved for
manual inspection, not automatically cleaned or silently retried.

### Credential provisioning (operator once, later; NOT needed right now)

**IMPORTANT ROOT CONFIG MATCH:** The uploader/downloader is a
root-interactive program and by default reads
`/root/.config/rclone/rclone.conf` (owned UID 0, mode 0600).
Running only `rclone config` as an ordinary user instead creates
`$HOME/.config/rclone/rclone.conf`, which the root script does NOT
read by default. Avoid the mismatch: use `sudo -H rclone config`
on the source and new host with a secure interactive console.
Alternately use `--rclone-config /ABSOLUTE/ROOT_OWNED_0600_FILE`
when prepared through a trusted root-only process. Never copy an
unverified world-readable Google token file.

Configure `rclone` on the operator's system when ready:

1. A personal Google Drive remote named `cape_drive` using official
   Google OAuth. Create a dedicated **private** Drive subdirectory for
   the encrypted master. Do NOT set it to "Anyone with the link."
   An SSH-only terminal may display a URL to approve using a separate
   logged-in local browser, which is an expected OAuth setup step.
2. A second rclone remote named `cape_crypt` with `type = crypt`
   pointing to `cape_drive:cape-private-encrypted/master-backups`.
   Use **standard filename encryption**, encrypted directory names,
   and normal encrypted file contents. Back up the strong crypt password
   and salt password (if selected) in a password manager.
3. Confirm `sudo -H rclone listremotes` prints BOTH
   `cape_drive:` and `cape_crypt:`. Confirm the root config is
   **0600**; do not print its contents or copy it to ChatGPT/GitHub.
   Passwords in rclone config are *obscured*, not securely encrypted.
   On the target machine, separately authorize Google Drive and
   configure the SAME crypt password(s) to access the existing data.
4. Ensure **the encrypted Drive directory remains PRIVATE** even
   though its stored bytes are encrypted. The program cannot prove
   Google Drive folder ACLs, storage quotas or user account entitlements.
5. `rclone version` and
   `sudo -H rclone listremotes` are safe metadata checks; do not share
   `rclone config show` output since it contains credentials.

The helper INSPECTS the rclone config type without printing tokens or
passwords and refuses a raw Drive remote, unencrypted crypt modes,
unencrypted filenames, shortcuts to a foreign Team Drive, symlinked
config, insecure config permissions or incomplete source manifests.
The script cannot independently certify the external Google Drive
folder's ACL; operator must keep it private.

### Later-stage CLI template — not to run yet

After the cold source `cape-master-*` folder has been safely exported
and there is a private crypt remote configured:

```bash
sudo python3 scripts/command1_private_drive_bundle.py \
  --mode plan-upload \
  --approved-host CSE-SSL-55 \
  --bundle /PRIVATE/EXISTING/cape-master-SOURCE_ID \
  --crypt-remote mycrypt
```

Change `--mode plan-upload` to `--mode upload` only after confirming
the actual bundle paths/Drive configuration. Approval is interactive,
and upload calls `rclone copy --immutable` **through crypt** followed
by a full-byte `rclone check --download --one-way` against the local
bundle, then source re-verification. That full check reads all remote
bytes again (bandwidth/time cost) but no extra local duplicate disk.

On a NEW and separately approved host with enough free storage:

```bash
sudo python3 scripts/command1_private_drive_bundle.py \
  --mode plan-download \
  --approved-host NEW_HOSTNAME \
  --destination /PRIVATE/ROOT_OWNED_PARENT/cape-master-SOURCE_ID \
  --bundle-id cape-master-SOURCE_ID \
  --crypt-remote mycrypt
```

Change to `--mode download` only after reviewing the plan; it creates
the exact NEW destination as root `0700`, downloads via crypt and
validates every source-bundle byte with SHA-256. It does **not**
automatically import VM disk/UEFI/TPM or boot/revert anything.
Those are separate guarded Command 1 phases.

### Deployment completeness and caveats

- User's SSL-55 master Windows bundle has NOT been exported/uploaded
  under this design yet. No user credentials or crypt password stored
  in GitHub.
- The exact-master export itself may require up to full QCOW2 virtual
  disk size plus a safety reserve of temporary local storage. An
  approved external SSD or ample temporary location can address
  that separately.
- This is a bounded, root-private, immutable transfer; interrupted
  transfers are deliberately not auto-deleted. An explicit resumable
  partial-transfer recovery path and cloud-object ACL verification
  remain future enhancements.
- Portability of original Windows activation/TPM, actual boot, running
  snapshots and CAPE integration are NOT implied by a byte-valid bundle.
- Fresh-host automated CAPE installation and this transfer's integration
  into the final public Command 1 entrypoint still need work.

Official protocol/behavior references:
- <https://rclone.org/crypt/>
- <https://rclone.org/commands/rclone_copy/>
- <https://rclone.org/commands/rclone_check/>
