# Command 2 — SSL-55 win11_1 pilot and sequential IP policy

## Requested development order (2026-10-11)

1. Finish the existing isolated win11_1 analysis clone's network,
   unique static IP, CAPE agent and verified usable RUNNING snapshot
   **on SSL-55**, subject to measured host isolation, resources and
   shared-host approval. Do not create extra clones or large disk backups
   on SSL-55. The protected original win11 NIC was already restored.
2. Make **portable Command 2** create N independent analysis guests,
   configure Windows identity/IP, attach NICs only behind accepted
   isolated network enforcement and set verified CAPE running snapshots
   with cold QCOW2+UEFI+swtpm recovery.
3. After the SSL-55 reference/pilot is accepted and automation
   implementation is integrated, user prefers Command 3 development.
   Later run full three-command portability acceptance on a separate
   approved sufficiently provisioned host. Do not call any component
   production verified before that later new-host acceptance.
4. INetSim-specific service simulation can be integrated later;
   basic real host firewall IPv4/IPv6 isolation, safe CAPE agent access
   and no uncontrolled Internet egress are NOT optional even for a pilot.

## Important: 'previous Windows VM IP + 1'

Use **previous verified Windows ANALYSIS clone on the isolated network**.
Never infer an analysis address by incrementing the protected
win11 master address if its NIC uses default NAT 192.168.122.0/24.
Fresh isolated 192.168.240.0/24 uses bridge 192.168.240.1 and
reserved first analysis-guest static IP 192.168.240.101, then
win11_2 .102, win11_3 .103, etc. Existing Windows guests must
have real guest-OS readback; the tool does NOT trust host-only guesses.
If the exact preceding +1 address is already occupied, stop without
silently skipping or overwriting another VM's IP.

Implementation: scripts/command2_sequential_guest_ip.py and
scripts/test_command2_sequential_guest_ip.py, integrated as an
independent IP/name consistency check in
scripts/command2_portable_zero_nic_entrypoint.py.
IP allocation is a PLAN. Actual Windows IP application remains gated
by the guest PowerShell script and unimplemented secure auto-delivery.

## Evidence needed now — single read-only SSL-55 audit

Script: scripts/command2_ssl55_win11_1_readiness.py
Tests: scripts/test_command2_ssl55_win11_1_readiness.py
Read-only report includes live+inactive clone NICs, exact UUID,
disk/UEFI/TPM XML, CAPE bridge/no-forward state, presence of guarded
nft chains, existing snapshot names and image filesystem free GiB.
It expressly does NOT claim nft guard effectiveness, IPv4/IPv6
negative egress, CAPE agent reachability or snapshot validity.
No VM, disk, host network or firewall changes are performed.

### Dependencies BEFORE modifying SSL-55

- Review exact report and enough host storage for a memory-bearing
  running snapshot without a separate large independent clone copy.
- Confirm permission for narrowly scoped bridge/nft modifications
  on this shared host; preserve campus, default VM NAT and Docker.
- Build/test independent CAPE bridge IPv4+IPv6 fail-closed isolation,
  no NAT, no DHCP, and reboot/restart persistence; runtime probe guest
  negative external egress and positive host-to-guest CAPE path.
- Existing running win11_1 must be cleanly stopped under explicit
  approval before --config NIC attachment. Do not attach on a running
  guest or remove unrelated devices. Never use libvirt default NAT.
- Apply hostname WIN11-1 and IPv4 192.168.240.101/24 inside Windows,
  gateway absent, verify assigned MAC, UUID, reboot and CAPE agent 8000.
- Capture actual running memory+disk snapshot only after agent and
  network negative tests. Confirm it is restorable via benign
  snapshot-revert and guest-agent recheck, with special attention
  to swtpm/UEFI state safety. No malware samples needed for acceptance.

Automated stages MUST refuse instead of claiming success when
preflight and guest runtime evidence are missing. The existing
generic separate-host snapshot/NIC guards deliberately block SSL-55;
do not bypass them. Any reference-host-specific pilot apply should
be narrowly scoped, independently reviewed, and explicitly approved.

## Current truth

The original win11 master has its one saved e1000e NIC restored.
win11_1 is still running with zero NICs based on last host audit.
No actual Windows static IP, CAPE agent network reachability,
isolated NIC, running CAPE-ready snapshot or snapshot revert has yet
been established for win11_1. The new IP planner and read-only
readiness audit are development milestones, not completed deployment.