# Command 2 — staged benign network qualification (not CAPE analysis)

## Fixing a circular acceptance prerequisite

The earlier separate-host NIC-attach script demanded actual guest
IPv4/IPv6 egress-negative test, host-to-guest CAPE agent reachability
and L2 guest isolation **before attaching any guest NIC**. Those
tests cannot be conducted inside a NIC-less guest. Treat that older
`attach` mode as a legacy higher-trust gate, NOT the pilot path.

`scripts/command2_quarantined_benign_nic.py` supports two distinct
stages on a separate, explicitly authorized fresh host:

1. `plan` requires exact libvirt VM identity, one independent disk,
   UEFI+TPM, a shut-off guest with ZERO NICs, active dedicated
   cape-analysis-isolated bridge with NO forward/NAT/DHCP, an existing
   dedicated nft firewall with observed scoped drop rules, no
   collisions with libvirt/host MACs and kernel routes/addresses.
   No writes are made.
2. `attach-benign` requires root and a direct interactive operator
   confirmation; a root-only 0600 host-only acceptance receipt
   matching exact VM UUID/MAC/IP/subnet and affirming the host
   conditions; second under-lock recheck; then one config-only
   e1000e NIC on the shut-off guest. The script does NOT start
   VM, apply guest IP, install firewall, create a snapshot or
   report CAPE analysis ready.

**Host-only approval is not a self-proving digital signature.**
Verification of the bridge, nft rules and identity are necessary but
not sufficient; do not issue a receipt until the live host guard
lifecycle is reviewed. Run ONLY benign external IPv4+IPv6 negative
egress tests and intended host-to-guest agent tests first. Prove
reboot persistence and cross-VM L2 isolation before malware/CAPE.

3. AFTER benign negative-egress evidence, Windows guest identity/IP
   is verified and the agent is reachable on the isolated subnet,
   perform a full independent cold QCOW2+UEFI+swtpm checkpoint
   acceptance (or equivalent approved recovery stage).
4. Capture a memory+disk running snapshot, demonstrate benign revert
   and check Windows identity, IP, TPM and agent again.
5. Only then publish CAPE-ready machine and snapshot inventory.

## Specific SSL-55 limitation

This script ABSOLUTELY refuses SSL-55 (host name and protected-backup
sentinel). It does not repair the already existing win11_1 on the
reference host. For SSL-55, the first step is to inspect the
CURRENT nftables/systemd boot posture read-only, then engineer an
independently approved reference-only benign lab activation/attachment
procedure. No new guests or large cold copies on shared SSL-55.

Legacy cape_analysis_guard (present on SSL-55) and new-host
cape_analysis_cmd2_guard are DIFFERENT tables. Never install a
second competing table over the existing firewall automatically.

Current work is developer stage. Windows guest config media,
isolated bridge activation/guard fail-closed lifecycle, CAPE agent
and actual 1..16 VM acceptance remain unverified on physical host.