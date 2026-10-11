# Command 2 — SSL-55 original master and analysis clone NIC recovery

**This document authorizes NO NIC, bridge, firewall or VM changes.**

User asks whether missing network parts of win11 and win11_1 can be
restored on SSL-55. They are fundamentally different situations:

- Protected master win11 UUID 289d89be-68ec-4c62-90e1-ea930849266f
  remains shut off. Historic source XML was saved with a libvirt default
  network interface. The most recent 2026-10-10 host NIC table was blank.
  We must establish whether its CURRENT inactive NIC definition differs
  from preserved original XML BEFORE any repair is contemplated.
- Separate clone win11_1 UUID 732b2256-ee99-41fa-881d-fbf5c476d960
  has ZERO NICs intentionally. Its static address 192.168.240.101
  cannot be safely applied until isolated NIC connectivity and host
  IPv4/IPv6 containment and reboot persistence are independently proved.
  Do not attach default NAT or blindly activate the inactive analysis net.
- Trial win11_trial_1 UUID e75f6fef-347d-462f-9738-4de3df6bfa74
  also remains protected; no additional VMs on SSL-55.
- CAPE network cape-analysis-isolated / cape-lab0 was inactive and
  nonautostart; existence of nft inet cape_analysis_guard is NOT a
  proof of effective egress filtering or persistence.

New nonmutating diagnostic:
- scripts/command2_ssl55_network_readonly_audit.py
- scripts/command2_ssl55_network_readonly_acceptance.sh
- scripts/test_command2_ssl55_network_readonly_audit.py

Compares active/inactive NICs on exact UUID domains, lab network state,
and ROOT-PRIVATE preservation backup domain.xml at
/var/backups/cape-win11-preservation/win11-state-92POdfNc/metadata/domain.xml.
No VM starts, libvirt definition changes, network attachment, nft changes,
TPM content reads, disk copy, snapshot or master modifications occur.

Interpretation:
1. If saved master NIC XML matches preserved original, no demonstrated
   master NIC configuration loss; do not alter it.
2. If NIC XML differs from preserved original, engineer a narrowly scoped
   libvirt XML repair ONLY after exact domain XML and current power state
   are verified and the operator separately authorizes it.
3. The zero-NIC win11_1 condition is intentional until isolation
   acceptance; any static IP and CAPE reachability depend on a safe NIC.
4. Do not create more guests, huge clone copies or backups on SSL-55.

Portable new-host candidate: scripts/command2_isolated_network_xml_plan.py
produces no-NAT, no-DHCP, no-forward libvirt XML WITHOUT applying it.
It does not prove any host firewall or IPv4/IPv6 isolation yet.

Command 2 is incomplete until real host-side isolation guard persistence,
guest-side hostname/IP delivery/verification, independent QCOW2+OVMF+swtpm
restore and parallel CAPE/INetSim acceptance pass on OTHER machine.