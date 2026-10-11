# SSL55 existing win11_1 benign-only NIC — post-bridge step

## Grounded live bridge state

User uploaded CAPE_Command2_Bridge_20261011_201302.txt:
result `SSL55_ISOLATED_BRIDGE_ONLY_ACTIVE_WITH_NO_GUEST_NICS`.
The bridge cape-lab0 is ACTIVE with 192.168.240.1; nft table inventory
unchanged; original win11, win11_1 and win11_trial_1 are SHUT OFF.
win11_1 and trial each have zero NICs; no VM starts or disk operations.
Negative IPv4/IPv6 egress, CAPE agent and running snapshot remain
unproven. Do NOT rerun libvirt net-start.

## Existing clone single-NIC step (BENIGN TESTING ONLY)

`scripts/command2_ssl55_win11_1_benign_nic.py` supports `plan`
(read-only) and `attach-benign` (config-only). Before any saved NIC
change, it requires:

- Exact SSL55 host and protected master sentinel; root operator.
- Master win11 saved default NIC still restored (count 1), shut off;
  win11_trial_1 zero NIC, shut off; win11_1 zero NIC and shut off;
  all three autostart disabled; no other active libvirt VM.
- Existing CAPE guard service loaded/enabled/active after real reboot,
  original nftables disabled/inactive, exact expected CAPE nft guard
  input/output/forward structure.
- Live CAPE libvirt network cape-analysis-isolated with NO forward
  (no NAT), no DHCP, no libvirt IPv6, DNS disabled, isolated=yes
  port, exactly one cape-lab0 bridge with 192.168.240.1/24,
  no nonbridge overlap with 192.168.240.0/24, no global/site IPv6
  on the bridge, and NO existing bridge ports.
- Unique verified current libvirt/host MAC candidate
  `02:0a:30:6a:3f:50`; exact existing clone UUID
  `732b2256-ee99-41fa-881d-fbf5c476d960`; ONE independent
  `win11_1.command2.qcow2` disk, unique OVMF and emulated TPM2.
- No previously defined win11_1 libvirt snapshots.

Only after those checks and typed `ATTACH-ONE-BENIGN-NIC-WIN11_1-SSL55`
does the script issue a single `virsh attach-interface --domain win11_1
--type network --source cape-analysis-isolated --model e1000e
--mac 02:0a:30:6a:3f:50 --config`.
It verifies exactly one saved attached NIC and same disk/NVRAM;
VM stays SHUT OFF. It never starts a VM, network, snapshot,
IP change, nft, or edits the protected master/trial.

If postchecks fail, state may be PARTIAL and needs manual review;
DO NOT rerun the NIC tool or blindly detach. This script is the
reference-host-specific pilot; separate-host
command2_guarded_isolated_nic.py remains unchanged and protected.

## Subsequent pending tasks

After a verified saved NIC attach, do NOT immediately run CAPE malware.
Next: guarded benign host/guest boot step, real Windows NIC driver
MAC and static-IP configuration WIN11-1 / 192.168.240.101/24
with NO default gateway, actual IPv4+IPv6 negative external egress,
host-to-guest CAPE agent HTTP/8000 positive and guest reset behavior.
Capture and benign-revert running memory/disk snapshot only after
those gates and full UEFI/TPM consistency review.

Do not create extra VMs or large QCOW2 copies on shared SSL55.