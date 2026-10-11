# SSL-55 Command 2 — CAPE guard persistence: root-cause and safe repair design

Observed real host evidence: user-uploaded
`CAPE_Command2_BootPersistence_20261011_153057_wtbVV8dC.txt`.

## Confirmed observed state

- `nftables.service`: LoadState loaded, UnitFileState disabled,
  ActiveState inactive, boot_enabled_observed false.
- `cape-analysis-guard.service`: LoadState not-found.
- `/etc/nftables.conf`: root-controlled 243 bytes, contains a top-level
  `flush ruleset`, contains NO `cape_analysis_guard` reference and no
  include directive. Do NOT enable/restart nftables.service or
  use nft -f /etc/nftables.conf on this shared machine: global flush
  could interfere with Docker, libvirt and campus networking.
- The existing `inet cape_analysis_guard` nft rules currently match
  the original known three-chain policy shape and ordering.
- All three protected guests `win11`, `win11_1`, `win11_trial_1`
  are SHUT OFF and libvirt autostart disabled.
- CAPE private lab is defined/persistent but ACTIVE=no and
  AUTOSTART=no. Its private `cape-lab0` interface has no NAT/DHCP.
- NO actual guest IPv4/IPv6 external-egress probes, firewall reboot
  persistence test, or L2 between guests test has been performed.
  Therefore connecting `win11_1` is still NOT authorized.

## Implementation committed to development

- `scripts/command2_ssl55_persistence_design.py` is a PURE,
  fail-closed report decoder. It refuses if ANY observed protected
  VM/network/service/base-conf status differs from this report.
- `scripts/command2_ssl55_guard_scoped_replay.py` is an isolated
  *candidate* CAPE-table reconcile helper (NOT INSTALLED).
  Its default `--mode plan` makes NO changes. It validates exact
  SSL55 reference hostname, preserved original master backup
  sentinel, original/master/trial UUID and NIC/power/autostart
  identity, inactive private libvirt network, a disabled original
  nftables.service and a root-controlled base configuration.
  It pins the original historical three-chain nft policy SHA256
  `58b84446ad74ac7ea8b14aa57d94c19945baa3db7330e54c7fb2312a9577ea14`.
- Optional `--mode reconcile` (NOT RUN) is root-only, guarded by
  exclusive flock and root-owned 0600 operator authorization at
  `/etc/cape-command2/ssl55-guard-replay-approved.json`.
  If `cape_analysis_guard` exists and is correct, it is idempotent;
  if entirely absent, it can add ONLY the historically pinned
  CAPE table with `nft --check --file` then `nft --file`.
  It NEVER enables nftables.service, flushes the host ruleset,
  installs systemd, starts a VM/bridge, or connects a guest NIC.
  After creating a table it rechecks strict libvirt and nft state.
  The helper does not provide systemd boot ordering or persistence
  by itself. It MUST NOT be invoked in write mode without separate
  review of the exact host state and explicit authorization.
- Tests are synthetic and run through Python 3.10/3.12 CI.

## What still must be built before safe persistence is achieved

1. A dedicated, root-controlled CAPE-only systemd oneshot service
   that calls the pinned helper after the supported libvirt service
   is ready. Its required service dependencies differ between
   Ubuntu/libvirt versions, so read back actual service identities.
   This dedicated service must NOT enable or edit nftables.service.
2. A guarded, crash-safe installer for that exact unit, helper and
   imported Python dependencies; package files must be pinned to
   SHA256 hashes. Installer must neither start the bridge nor guest.
3. Root-controlled approval manifest created only after reviewing
   the target host and expected policy, with explicit operator
   authorization. Missing/changed manifest must fail closed.
4. A demonstrated boot sequence where the guard is active before
   any CAPE analysis bridge/guest is activated. Keep libvirt
   guest/net autostart disabled until this is actually verified.
5. Actual service-restart and full-host-reboot acceptance checking
   preserved unrelated Docker/libvirt/campus rules and the CAPE
   guard. Existing `nftables.conf` with global flush is an
   additional failure mode requiring review, not modification.
6. Controlled benign-only first NIC attachment under host-side
   quarantine guards and actual negative IPv4/IPv6 probes. Real
   guest tests necessarily follow NIC attachment; do not demand
   a pre-NIC packet test as a circular prerequisite.
7. Within isolated Windows: WIN11-1 and 192.168.240.101/24,
   no default gateway, agent port 8000 readback, clean RUNNING
   memory+disk snapshot and verified benign snapshot revert.

## Host policy

No additional VMs or large QCOW2 copies on SSL-55; preserve original
win11 and trial. Do not install/restart/enable services on the shared
host without the user's separately reviewed exact-host approval.
INetSim service simulation may wait, but external egress controls
cannot. Passing offline CI is NOT a production certificate.