# 2026-10-11 SSL-55 Command 2 — confirmed firewall boot replay, next bridge-only stage

## Actual after-reboot evidence

User uploaded `CAPE_Command2_RebootVerification_20261011_200314.txt`: 

- Pre-boot ID `77d97988-1364-4356-9eb4-2a11e7af3cb9`; post-boot ID
  `7b41e444-0def-41b8-b9c2-1f68ecf13a37` — actual host reboot.
- `cape-analysis-guard.service` is **loaded, enabled, ACTIVE**,
  `Result=success`, `ExecMainStatus=0`, `ConditionResult=yes`.
- Current boot journal: CAPE `inet cape_analysis_guard` table was
  **restored** by unit and finished at 20:04:57 UTC.
- General `nftables.service` remains INACTIVE/DISABLED.
- Protected Windows master, win11_1 and trial remain shut off.
- Isolated CAPE network was still INACTIVE/AUTOSTART=no.
- This demonstrates CAPE guard replay after ONE reboot. It does
  NOT prove packet-path IPv4/IPv6 negative egress, L2 isolation
  or survival of Docker/libvirt/firewall restarts.

**Do NOT reboot SSL-55 again merely to repeat this initial test.**

## Next guarded activation (one existing isolated libvirt bridge, no NIC)

Script: `scripts/command2_ssl55_bridge_only_activation.py`
Mock tests: `scripts/test_command2_ssl55_bridge_only_activation.py`.

- `--mode plan` inspects ONLY: root+protected SSL55 marker,
  successful current-boot CAPE replay systemd status, base
  nftables service disabled, three protected VM UUIDs and
  shutdown/autostart/NIC counts, no other running libvirt VM,
  all existing guard nft chain structure, exact inactive
  `cape-analysis-isolated` network XML with port isolated=yes,
  bridge cape-lab0, IPv4 192.168.240.1/24, NO forward/NAT,
  DHCP, DNS or libvirt IPv6, and no host CIDR/route collision.
- `--mode activate` REPEATS plan, requires root and direct TTY
  phrase START-ISOLATED-BRIDGE-ONLY-SSL55, takes exclusive
  root-only flock, rechecks the same plan under lock and
  runs ONLY `virsh net-start cape-analysis-isolated`.
- It verifies manual-only active bridge and intended IPv4,
  no global/site-scoped bridge IPv6, unchanged nft table
  inventory, original legacy CAPE nft guard structure,
  no running VM and no NIC on win11_1 or trial.
- If an unexpected condition appears after net-start,
  it reports PARTIAL and requires a human decision; it
  does NOT blindly delete network/firewall or attach a guest.

**Starting the bridge is NOT an approval to connect a VM.**
Even a successful bridge-only start is not proof of IPv4/IPv6
guest egress prevention. Connecting existing win11_1 via one
MAC e1000e NIC requires its own operator authorization and
a separate benign-only positive/negative network test stage.

Current next steps: bridge-only first, then test host-side
egress isolation, guarded zero-NIC -> one-NIC configuration
for existing win11_1, Windows WIN11-1 and 192.168.240.101/24,
agent HTTP 8000, usable running snapshot, benign revert.
No other VM creation or large QCOW2 copies on SSL55.
