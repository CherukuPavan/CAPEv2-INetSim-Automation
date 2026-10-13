# Same-day deployment: private GitHub source + private Google Drive golden master

**Status:** Instructions for a later approved test. They DO NOT mean that
the fresh-host three-command installation has passed physical acceptance.
**Never use SSL-55 as the target host.** Preserve `win11`,
`win11_trial_1`, `win11_1` and all named snapshots.

## Important GitHub fact

This automation repository, `CherukuPavan/CAPEv2-INetSim-Automation`,
is **PRIVATE**, and its default branch is `main`.
Uncredentialed `curl https://raw.githubusercontent.com/.../development/...`
is NOT a reliable way to obtain this code: GitHub normally responds
with 404 for private repository raw files without authorization.
Do NOT make this repository public and do NOT put a personal access token
into a URL, shell command, terminal paste, issue, chat or report.

On each authorized computer, authenticate to GitHub independently
using **GitHub CLI** (OAuth) or the user's existing Git-over-SSH key.
An authenticated `git clone` from this private repo is a
one-time bootstrap prerequisite; it must select **development**,
not the older main branch.

One example after GitHub SSH authentication is configured:

~~~bash
git clone --branch development --single-branch \
  git@github.com:CherukuPavan/CAPEv2-INetSim-Automation.git \
  "$HOME/CAPEv2-INetSim-Automation"
cd "$HOME/CAPEv2-INetSim-Automation"
git status --short --branch
~~~

Alternatively use `gh auth login` and `gh repo clone
CherukuPavan/CAPEv2-INetSim-Automation -- --branch development
--single-branch`, after installing and logging in to `gh`.
GitHub CLI credentials are held by the user, never committed to GitHub
or passed to the CAPE automation. Do not `sudo git clone` into an
ordinary user's home; root-owned checkouts caused earlier SSL55
permission problems. Subsequent protected installation stages use
`sudo python3 -B ...` only for phases that actually require root.

Run the repository's **read-only, pinned private-checkout verifier**
before any package changes. Replace REVIEWED_SHA40 with the *actual
full* commit SHA of the release candidate, NOT a screenshot sample:

~~~bash
python3 -B scripts/private_repo_checkout_preflight.py \
  --checkout "$PWD" \
  --expected-sha REVIEWED_SHA40
~~~

If the repository changes during development, an old pinned SHA must
fail; update it only after the new candidate has passed relevant CI.
The program deliberately does not print remote URLs containing tokens,
does not authenticate GitHub, and never auto-updates the checkout.

## Master is a private encrypted DATA bundle, not repository code

### Source host prerequisites (only when export is explicitly approved)

- The original `win11` master must be FULLY SHUT OFF.
- Its actual QCOW2 backing chain and OVMF VARS/swtpm state must be
  independently verified. Source image export must use a NEW
  root-private `cape-master-*` folder with sufficient free disk space
  for its **virtual image size** plus reserve.
- `scripts/command1_export_existing_master.py` performs an exact,
  private cold QCOW2 flatten and original UEFI/XML/TPM artifact copy.
  New exports bind SHA256 of every member file, including
  `capture-intent.json`. It never boots/reverts source guests.
- A separate private Google Drive folder is required. Nothing is
  uploaded by a Git commit. TPM blobs must NEVER be shared publicly.

### Root rclone config — **do not confuse root with user profiles**

Transfer program defaults to
`/root/.config/rclone/rclone.conf`, **root-owned 0600**. Creating
remotes only by running bare `rclone config` as the normal user
instead writes a different file (`~/.config/rclone/rclone.conf`)
that the protected uploader cannot use.

On the authorized source host when ready:

~~~bash
rclone version
sudo -H rclone config
sudo -H rclone listremotes
~~~

During the secure interactive `sudo -H rclone config` wizard:
create `cape_drive` as your personal Google Drive remote, complete
Google OAuth in a trusted browser, and create `cape_crypt` with
`type=crypt` pointing to
`cape_drive:cape-private-encrypted/master-backups`. Choose normal
client-side file encryption, **standard filename encryption** and
encrypted directory names, with a strong crypt passphrase (and optional
salt). The password and OAuth tokens must stay OUTSIDE GitHub and ChatGPT.
Back up the crypt password safely; without it, restore is impossible.
Keep the Drive folder PRIVATE even though its contents are encrypted.

Expected terminal metadata ONLY:

~~~text
cape_drive:
cape_crypt:
~~~

Do NOT share `rclone config show`, `rclone.conf`, browser OAuth codes,
passwords, or any downloaded Windows/TPM files. Only share redacted
metadata and the success/failure of `sudo -H rclone listremotes`.

### Transport stages (not yet performed)

`command1_private_drive_bundle.py` provides source `plan-upload`
and approved `upload` through `cape_crypt:`. It validates the
full private bundle and uses immutable remote copy and byte
comparison. On a NEW target host a separately configured and
authorized copy of the SAME encrypted Google Drive remote (same crypt
password) is used. The target `plan-download` and `download`
modes save to a new root-private folder with exact SHA256 proof.
`command1_private_master_stage.py` joins new-host download with
guarded imported Windows disk, XML, NVRAM and original MASTER TPM state.

NO user's personal Google Drive files, passwords, tokens or original
Windows master bundle have actually been uploaded by the assistant.

## Three-command execution status

- **Command 1:** controlled prerequisite/bootstrap and encrypted exact
  master import components exist; **full custom QEMU/CAPE/INetSim/DB
  fresh-host installer, master Windows boot and final TPM-consistent
  RUNNING checkpoint are still missing or not physically tested.**
- **Command 2:** integrated guarded 1–16 count-driven exact clone
  provision, independent Windows network/Agent checks, running snapshot
  candidates and graceful shutdown. **Physical firstboot and coherent
  swtpm restore have NOT passed acceptance.**
- **Command 3:** one entrypoint for five config edits, exact N-machine
  kvm.conf and separately approved five-service restart/verify. The
  screenshot's `route=internet` and `internet=virbr0` is NOT applied
  unattended; this potentially invalid dirty-line mapping needs
  deliberate routing design and a verified disposable test host.
- No malware/sample execution is necessary for basic new-host
  acceptance. Start with **benign** Windows boot and service tests.

**Offline green CI proves the scripts parse and tested guard behavior;
it cannot prove a second host has enough RAM/storage, correct upstream
QEMU/Poetry dependencies or recoverable Windows+TPM snapshots.**

Reference implementation and tests:
- `scripts/private_repo_checkout_preflight.py`
- `scripts/command123_readonly_machine_report.py`
- `scripts/command1_reference_host_blueprint.py`
- `scripts/command1_private_drive_bundle.py`
- `scripts/command1_private_master_stage.py`
- `scripts/command2_exact_master_full_sequence.py`
- `scripts/command3_from_operator_reference.py`
