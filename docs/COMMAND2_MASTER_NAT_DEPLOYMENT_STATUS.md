# Command 2 master-equivalent NAT deployment — operator handoff

**Development-only, 2026-10-12. Not yet an end-to-end certified install.**
All changes are on branch **development**, not main.

## Physical SSL55 reference (PASS — leave untouched)

On protected \`CSE-SSL-55\`, the operator's real upload
\`CAPE_SSL55_OneNAT_SnapshotFix_20261012_195300.txt\` confirmed:
- Only \`win11_1\` is running. Protected master \`win11\` and
  \`win11_trial_1\` are shut off and unchanged.
- Exactly one persistent \`e1000e\` NIC on libvirt \`default\` NAT,
  \`virbr0\`, MAC \`02:ca:55:11:01:02\`. Windows DHCP lease and
  active+inactive network host reservation \`192.168.122.131\`,
  gateway/DNS \`192.168.122.1\`; physical HTTPS 200 and Agent 0.23 proof.
- Three independent **running RAM + Windows OS QCOW2 + UEFI QCOW2**
  internal snapshot labels validated within libvirt and BOTH exact files:
  \`cape_candidate_win11_1\`, \`cape_postnat_win11_1\`,
  \`cape_one_nat_win11_1\`. No snapshot has been reverted or deleted.
- **NO matching swtpm persistent/volatile capture-at-snapshot-epoch,
  TPM-safe restore, or two benign restore cycles.**
  \`cape_one_nat_win11_1\` is a candidate, not \`cape_ready_win11_1\`.
  **Never click Revert/Apply in virt-manager on the protected VM.**

## New portable master-style NAT path (CODED; physical test PENDING)

Existing original, isolated Command2 stages produce unique Windows guest
identity journal entries containing old \`192.168.240.x\` candidate IPs and
create 1..16 independent **SHUT-OFF, ZERO-NIC** guests. Do not blindly
apply the old guest static isolated-network config to the new NAT NIC.

After root-on-*OTHER-HOST* identity reservation + stopped zero-NIC
staging, use the guarded dispatcher:

\`\`\`bash
# Read-only actual master/default NAT and all-N journal checks
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase master-nat-plan --mode plan \
  --approved-host "ACTUAL_NON_SSL55_HOST" \
  --journal "/root/cape/command2-identity-reservation.json"

# Read-only all-N net attach/DHCP plan (requires ALL target VMs SHUT OFF)
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase master-nat-attach --mode plan \
  --approved-host "ACTUAL_NON_SSL55_HOST" \
  --journal "/root/cape/command2-identity-reservation.json"

# ONLY after operator checks, apply saved e1000e NIC and matching DHCP host
# reservations with typed interactive 1..16 guest consent. This is a
# one-way mutation; a partial batch STOPS and MUST be reviewed.
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase master-nat-attach --mode apply \
  --approved-host "ACTUAL_NON_SSL55_HOST" \
  --journal "/root/cape/command2-identity-reservation.json"

# Root-owned existing 0700 directory: install -d -m 0700 /root/cape/nat-iso
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase master-nat-media --mode plan \
  --approved-host "ACTUAL_NON_SSL55_HOST" \
  --journal "/root/cape/command2-identity-reservation.json" \
  --nat-media-dir "/root/cape/nat-iso"

# Optional approved immutable per-VM CAPE_NAT2 ISO build
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase master-nat-media --mode apply \
  --approved-host "ACTUAL_NON_SSL55_HOST" \
  --journal "/root/cape/command2-identity-reservation.json" \
  --nat-media-dir "/root/cape/nat-iso"
\`\`\`

The command paths above are *examples* for a newly prepared test host.
Do not reuse a journal path that does not exist or guess a hostname;
use the actual existing root-private host journal and verified clone
identities. Never execute the portable workflow on SSL55. There is
NO automatic installation of guest-side scripts or attachment of the new
media yet. Creating an ISO does NOT configure or start Windows.

Each ISO contains \`nat-config.json\`, \`nat-config.sha256\` and
\`command2_guest_master_nat.ps1\`. Inside the approved Windows clone,
the separately reviewed script has \`Plan\`, \`Apply\`, \`Verify\` modes,
requires matching SMBIOS UUID, one exact NIC/MAC and config SHA256,
and only applies DHCP+gateway/DNS after explicit benign-only approval.
Windows hostname rename requires separate approval and manual reboot.
Verify can require HTTPS with \`-RequireHTTPS\`. Because the older
Windows startup task currently accepts ONLY isolated-network approval
media \`CAPE_CMD2\`, **CAPE_NAT2 is NOT yet auto-consumed at boot**.
Correct auto-attachment + SYSTEM execution + reboot and post-boot proof
remain an engineering acceptance task on the separate host.

## How to keep NAT and malware containment distinct

The libvirt master source's \`default\`/virbr0 NAT gives Windows actual
Internet, as required. **This topology is not an isolated malware lab.**
Do not claim NAT per-port isolation or release malicious files; actual
analysis-time egress restriction requires a separate reviewed host
firewall/network policy, packet-level tests including IPv6 and peer L2,
DNS/INetSim routing policy and reboot-persistent enforcement.

Every clone additionally needs: unique effective Windows hostname,
NAT DHCP address and host route, Windows DNS+real HTTPS proof, CAPE
Agent \`:8000\` reachability, exact CAPE IP/VM registration, independently
verified running OS+UEFI+RAM snapshot, and a **physically twice-tested
TPM-compatible disposable restore** before becoming \`CAPE_READY\`.

## TPM restoration is a real architectural gap

Upstream QEMU supports TPM emulator migration/snapshot semantics;
however, the specific libvirt running snapshot process here has NOT
proven that \`swtpm\` persistent/volatile blobs are atomically
checkpointed with disk, firmware and RAM. See:
- https://www.qemu.org/docs/master/specs/tpm
- https://manpages.debian.org/trixie/swtpm-tools/swtpm_ioctl.8.en.html
- https://lists.libvirt.org/archives/list/users@lists.libvirt.org/message/7BF52MFBOHLST55FUUWNLQ76JFR4ZF6V/

A file copied from \`/var/lib/libvirt/swtpm\` AFTER snapshot capture is
**not** an exact-epoch TPM snapshot. No unsafe retroactive attachment of
that file is allowed. Plan a disposable host/VM recovery with independent
cold recovery backup and two benign restore cycles, observing BitLocker,
Secure Boot, Windows boot, Agent, NAT IP and guest/application markers.
No protected SSL55 snapshot reversions.

## Command 2 checklist (as of this handoff)

**PHYSICALLY VERIFIED:** SSL55 single VM new permanent NAT, Windows HTTPS,
both bridge Agent checks before retirement, unique DHCP lease+reservation,
one final NIC, THREE visible internal running OS+UEFI+RAM checkpoints.

**CODED AND OFFLINE-TESTED ONLY:** portable ordered identities and zero-NIC
staging, all-N permanent default NAT attach + host DHCP apply,
per-guest Windows NAT profile and ISO generation.

**NOT YET PROVEN:** actual all-N portable apply on another machine;
unattended guest-side NAT script install and identity setup; post-boot N
hostnames and addresses; dual-VM parallel CAPE analysis; automatic
running checkpoints for the new all-N NAT profile; safe swtpm revert
at snapshot epoch; INetSim-specific analysis-time containment; all-host
one-command acceptance. Command3 services/config are user-retained,
but these Command2 dependencies cannot be claimed completed by
delegating them to Command3.

**Never assert Command2 production-ready without the missing evidence.**
