# SSL-55 original win11 saved NIC repair — guarded two-phase procedure
## Completed — host-verified guarded restoration, 2026-10-11

Operator report CAPE_MasterNIC_Restore_20261011_133805_Ifv1ismz.txt
returned ORIGINAL_SHUTOFF_WIN11_SAVED_NIC_RESTORED.
Reported master: one saved interface, default network, shut off,
snapshot finalshutoffversion. Both running clones untouched;
host firewall unchanged, no network started and no extra guests.
Do not repeat apply. This procedure below is retained as an
auditable record, NOT as a new operational instruction.
win11_1 remains intentionally no-NIC until actual egress protection
is verified on an approved separate deployment host.


**2026-10-11 actual read-only audit: original win11 has 0 saved
interfaces, while the protected original backup has exactly ONE
e1000e interface connected to libvirt default.** Original master is
SHUT OFF and UUID 289d89be-68ec-4c62-90e1-ea930849266f.
Separate running win11_1 and trial each have ZERO NIC, intentionally.
The isolated CAPE network is inactive, autostart off, and its
IPv4/IPv6 egress containment has NOT been verified.

Exact evidence: user TXT
CAPE_SSL55_NetworkReadOnly_20261011_132144_s2Qf9Jhu.txt.

Code: scripts/command2_ssl55_master_nic_guard.py
Tests: scripts/test_command2_ssl55_master_nic_guard.py

## Phase 1: PLAN ONLY (next operator step)

Run only the SHA256-verified development version via sudo in plan
mode and upload the one resulting TXT. Do NOT invoke --mode apply yet.
The plan reads private preserved metadata/domain.xml (NO disk/TPM
contents), master libvirt inactive XML, UUID, master power state,
snapshot-current and snapshot-list, existing libvirt domain NIC MACs,
and net-info default. It fails closed on unusual original adapter
models/MACs/PCI positions or a changed master. It produces a
checksum-bound candidate for exactly the saved e1000e interface.
Plan does not call any modifying virsh command or create files.

## Phase 2: APPLY (DEFERRED until Phase 1 reviewed)

This mode is NOT automatic and must NOT be executed based only on
the first audit report. It requires an exact approved plan-sha256,
TTY input of RESTORE-ONLY-SHUTOFF-WIN11-SAVED-NIC, root ownership,
an exclusive root-owned flock lock, repeat live checks and matching
source/current backup/checksum. It uses ONLY
virsh attach-device win11 <temporary root-private XML> --config.
It NEVER requests --live or boots the VM, defines a different VM,
starts any libvirt network, adds a NIC to win11_1, or touches
nftables, Docker, INetSim, CAPE, NVRAM, TPM or QCOW2.

Following attach, it rereads and checks master UUID, current
snapshot name and full snapshot-name inventory, backup unchanged,
e1000e MAC and network, master shutoff state and protected
disk/UEFI/TPM/controller/resource subtree fingerprint. On error,
NO blind rollback or retry: stop and review exact libvirt state.

**Important:** restoring a libvirt default NIC creates a NAT-capable
link if the original clean master is booted with the default network.
Do NOT boot the master for malware analysis; do not attach the clone
to default or any unverified CAPE network. Original master NIC
restoration is separate from completing isolated Command 2 guests.

## Not completed by this master repair

win11_1 still intentionally has zero NIC until an independent
host-side reboot-persistent IPv4+IPv6 containment policy has passed.
Windows static IP and hostname transport, CAPE/INetSim reachability,
per-VM QCOW2+UEFI+swtpm cold-restore tests, parallel analysis and
full two-command fresh-machine acceptance are remaining Command 2
requirements. Command 3 MUST wait until those are verified on a
separate approved adequately provisioned machine.