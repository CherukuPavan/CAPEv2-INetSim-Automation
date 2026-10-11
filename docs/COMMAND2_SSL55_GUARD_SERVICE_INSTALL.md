# Command 2 SSL-55: install-only CAPE firewall replay service (operator-approved)

## Approved scope, 2026-10-11

User explicitly approved INSTALLING and ENABLING a dedicated
`cape-analysis-guard.service` on shared SSL-55 subject to narrow
checks, and without changing existing firewall services, protected
VMs or inactive `cape-analysis-isolated` network.

**This does not approve any guest NIC attachment, VM boot, host reboot,
global nftables flush, CAPE/INetSim sample execution or disk cloning.**

## Verified source scripts on development

- `scripts/command2_ssl55_guard_service_installer.py`: strict
  `--mode plan` (root, read-only) and `--mode install` (create-only).
- `scripts/command2_ssl55_guard_scoped_replay.py`: exact historical
  CAPE nft table reconciler; if correct table already exists,
  no nft modifications. If absent, restore ONLY the pinned table
  after a root-only signed-off manifest and full host recheck.
- `scripts/command2_ssl55_guard_systemd_unit_plan.py`: exact
  `cape-analysis-guard.service` text with reviewed backend ordering.
- Pinned supporting modules `command2_ssl55_existing_guard_readonly.py`,
  `command2_ssl55_boot_persistence_readonly.py`,
  `dryrun_cape_lab_guard_nft.py`; all source bytes verified by
  installer against fixed Git blob SHA values before copying.

Installer refuses unless the original three libvirt domains match
their protected UUIDs, all shut off with autostart disabled;
only original `win11` has its restored saved default NIC;
trial and `win11_1` have zero NICs; analysis network is inactive
and autostart disabled; existing CAPE nft rules match the original
no-forward/host-agent policy; root-controlled `/etc/nftables.conf`
contains a global flush but has no CAPE guard reference;
base `nftables.service` remains loaded, disabled and inactive;
`cape-analysis-guard.service` does not already exist; exactly one
supported libvirt daemon service is active; and target directories
do not contain an earlier or partial installation.

### Two-phase guarded operator launch

The shell launcher fetches every file from an immutable Git commit,
verifies Git blob hashes and runs the root-owned `plan` against
live host state. The operator is shown the exact unit and checksum;
`install` reruns all checks, requires the exact plan SHA256 and
a TTY-entered literal `INSTALL-ENABLE-ONLY-CAPE-GUARD-SSL55`,
then acquires an exclusive root lock. **No blind overwrite.**

Only if checks pass, installation creates:

- `/usr/local/libexec/cape-command2/` (root 0700) and five
  exact pinned Python modules (root 0600).
- `/etc/cape-command2/ssl55-guard-replay-approved.json` (root 0600),
  exact host/VM/policy/operator/plan authorization.
- `/etc/systemd/system/cape-analysis-guard.service` (root 0644).

Then `systemd-analyze verify` checks unit syntax. Only on success
does the installer call `systemctl daemon-reload` and
`systemctl enable cape-analysis-guard.service`. It NEVER uses
`--now`, `systemctl start`, `systemctl enable nftables.service`,
`nft flush ruleset`, `virsh net-start`, `virsh start`,
or guest NIC attach. After enablement it confirms the dedicated
unit is loaded/enabled but INACTIVE, general nftables remains
disabled/inactive, protected VM/net definitions unchanged, and
existing CAPE guard still present. Failure leaves partial files
for deliberate review rather than deleting or retrying blindly.

## What is not established by an installer success

Enabling the service is NOT proof that it replays at boot. A
separate approved reboot/restarter experiment is required to
validate ordering and unrelated Docker/libvirt/campus rules.
Since all protected VMs and the analysis network remain autostart
OFF, no guest traffic is allowed to depend on this untested boot
guard. Guest IPv4+IPv6 actual negative egress, guest Windows
`WIN11-1`/192.168.240.101, CAPE agent 8000, running snapshot
capture/revert and cold TPM/UEFI recovery are still pending.

An installer BLOCKED result is not permission to bypass a check.
Upload one private TXT report; investigate the specific mismatch
before proposing further host changes.