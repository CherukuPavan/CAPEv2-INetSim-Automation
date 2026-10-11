# Command 2 — network, full cold restore and running CAPE snapshot

**Development as of 2026-10-11; no deployment approval.**

## Strict phase order for each of win11_1 through win11_N

1. Existing Command 1 verified cold Windows template and a fresh
   approved OTHER host are prerequisites. SSL-55 is reference-only;
   never add guest NICs or snapshots there until independent security
   review explicitly authorizes an existing-guest action.
2. scripts/command2_portable_zero_nic_entrypoint.py generates identities,
   network/host preflight, guarded zero-NIC shut-off QCOW2/UEFI/swtpm
   clone definitions and private Windows JSON configurations.
3. Command 1 golden Windows must ALREADY have trusted first-boot
   configuration delivery/privileged bootstrap. This critical guest
   transport is NOT installed by Command 2 yet. The guest-local
   command2_guest_personalize.ps1 supports a no-NIC hostname phase
   and an isolated NIC static-IP phase with explicit host approval.
4. Host must independently establish and prove persistent, nonoverlapping
   CAPE/INetSim isolated-network routing; no unintended IPv4/IPv6
   egress or VM lateral traffic. Candidate generated nft text and
   libvirt network XML alone are NOT enforcement or proof.
5. scripts/command2_guarded_isolated_nic.py can attach exactly one
   shut-off CONFIG-ONLY e1000e guest NIC after host network and a
   root-private detailed acceptance record. It never starts guests,
   changes firewall or starts networks; refuses SSL-55/sentinel.
6. Windows guest applies its unique static IPv4 with no default
   gateway, verifies unique WIN11-N hostname/MAC and running CAPE
   agent. scripts/command2_cape_agent_probe.py issues only a bounded
   GET http://GUEST_IP:8000/ and requires the real CAPE Agent JSON
   identifying administrator privileges. No guest commands/samples.
7. scripts/command2_portable_cold_bundle.py provides guarded cold
   full independent disk+UEFI+swtpm checkpoint capture, SHA256
   verification and a destructive restore requiring typed approval.
   The VM must be shut off; restores retain ALL previous files and
   write an exclusive intent for manual recovery from partial crashes.
   After restoring, guest boot/TPM/Windows/CAPE and network identity
   acceptance remains mandatory and UNVERIFIED.
8. scripts/command2_running_cape_snapshot_gate.py provides a guarded
   RUNNING snapshot capture on a separate host only after live-agent
   and network acceptance and checks INTERNAL disk+memory metadata.
   It refuses a disk-only snapshot and any fallback. CAPE guidance
   says the Windows agent must be running when the snapshot is taken.
   Modern libvirt/swtpm/OVMF combinations may reject this on a real
   host; do not claim compatible until tested on the actual host.
9. scripts/command2_benign_snapshot_revert_gate.py provides an
   explicit DESTRUCTIVE benign revert smoke test after a separately
   verified full cold checkpoint. It checks running guest/agent after
   revert and does NOT itself attest BitLocker, TPM, UEFI or CAPE
   parallel production readiness.
10. scripts/command2_cape_kvm_config_plan.py generates KVM conf
    sections with labels, per-VM IP, win11 tags and exact names
    cape_ready_win11_N for N=1..16. This file is only a proposal and
    must NOT be installed into live CAPE until all matching snapshots
    and guest mappings are really verified.

## Safety / scientific validity

- Candidate nft input/FORWARD rules cannot prove bridge L2 behavior,
  IPv6 leak prevention or reboot persistence. Run actual negative
  egress and positive CAPE/INetSim network tests on a DIFFERENT host.
- Root-owned operator acceptance JSON is a witnessed checklist, not
  cryptographic proof by itself. Independently reproduce each claim.
- A running-memory snapshot does not replace a cold full QCOW2/UEFI/
  swtpm checkpoint, or vice versa. Reverting running snapshots with
  virtual TPM/UEFI must pass real after-revert Windows identity tests.
- Running snapshot and restores are potentially disruptive; never
  carry them out on SSL-55 under the current shared-host restrictions.
- Each write-capable module requires explicit operator approval,
  exact clone UUID, and protected-host refusal. Test success does
  not automatically authorize production use.

## Current blocker to an honestly COMPLETE Command 2

**No approved separate full-capacity KVM host has been made available
for live tests, and no automatically invoked trusted Windows first-boot
configuration mechanism is known to be installed in the golden
Windows master.** Until those are provided/verified, multi-VM
hostname/IP, live snapshot/revert, CAPE parallel analysis and network
containment cannot be honestly marked fully complete. Command 3 is
locked until the full docs/COMMAND2_PRODUCTION_ACCEPTANCE_GATES.md
matrix passes.

Reference documentation:
- https://capev2.readthedocs.io/en/latest/installation/guest/saving.html
- https://github.com/kevoreilly/CAPEv2/blob/master/conf/default/kvm.conf.default
- https://www.libvirt.org/manpages/virsh.html
- https://qemu-project.gitlab.io/qemu/specs/tpm.html