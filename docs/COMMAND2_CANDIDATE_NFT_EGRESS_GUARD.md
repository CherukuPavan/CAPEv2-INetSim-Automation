# Command 2 — candidate bridge-scoped nft guard (NO APPLY)

**This is a development-only offline rules proposal, not host
isolation, not a network-setup command, not a NIC-attachment approval.**

Code: scripts/command2_cape_egress_guard_plan.py
Tests: scripts/test_command2_cape_egress_guard_plan.py

The Python module generates text for a dedicated inet nftables table
cape_analysis_cmd2_guard scoped to the dedicated CAPE bridge cape-lab0:
- FORWARD: drop packets routed from this bridge to other networks.
- INPUT: drop guest IPv6 traffic delivered to host, and drop guest
  IPv4 packets addressed to non-CAPE-bridge host IPv4 addresses.
- No change to other interfaces by design; base chain policy accept
  still defers all unrelated traffic decisions to existing host rules.
- No flush ruleset, no network start/define, no systemctl operations.
- The output is a proposal. It is NOT installed, validated by
  nft -c, reboot-persisted, or tested with any live guest.

Crucially, this inet proposal alone does NOT prove:
- Layer-2 isolation between analysis VMs sharing the same bridge;
- Behavior of existing nft/iptables/Docker/libvirt forwarding chains
  and kernel bridge netfilter settings;
- Protection against spoofed guest source addresses or unexpected
  TAP/bridge uplinks and IPv6 link-local paths;
- CAPE host-to-guest and INetSim guest-to-host positive communication;
- Negative IPv4 AND IPv6 guest external egress, and persistence
  after restarting libvirt/firewall services and reboot;
- Sufficient API control or authenticated evidence to approve a NIC.

The integrated portable entrypoint includes this design in the
READ-ONLY proposal report as candidate_l3_nft_guard_only and retains
network_isolation_verified=false and nic_attachment_authorized=false.

Future integration on a SEPARATE approved target must:
1. Collect the complete host libvirt, kernel route, firewall and
   bridge inventory and refuse shared/uncontrolled links.
2. Validate a collision-free no-forward libvirt network XML.
3. Establish L2 + L3 ingress/egress guards without changing
   unrelated Docker, campus or host networking.
4. Validate nft syntax on the actual host before changes, perform
   explicit reviewed guarded atomic application and reboot persistence.
5. Run real benign guest IPv4/IPv6 external-negative probes and
   CAPE/INetSim positive tests, including after host reboot.
6. Only after independent signed/attested host proof consider
   adding ONE approved NIC per VM with exact reserved MAC.

Do not apply generated nft text as an isolated security solution.
Do not use it on SSL-55. Its original win11 saved NIC has already
been successfully restored, and win11_1 intentionally remains no-NIC.