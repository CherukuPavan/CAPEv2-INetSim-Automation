# Command 1 + Command 2 — EXACT user-built master, not reconstructed Windows

## Canonical decision (user reaffirmed 2026-10-12)

**Do NOT ask the operator to list Windows applications, registry edits,
CAPE Agent setup, Python installation, Windows Update choices, firewall
changes, or other Windows customization again.** Their exact
manually configured `win11` is the authoritative Windows install and
the **actual Windows disk** is the source of Command 1. No historical
PDF recollection or synthetic baseline is a replacement.

The new-host flow requires TWO physically distinct kinds of input:

1. **Windows guest golden bundle**: the original master's complete
   cold disk image, UEFI VARS, machine XML and its independently captured
   MASTER TPM persistent state, kept root-private. This preserves the
   installed Windows filesystem, applications and registry *as captured*.
2. **Ubuntu host CAPEv2 environment**: installed host OS dependencies,
   QEMU/libvirt/swtpm, CAPEv2 source, Python/Poetry environments,
   databases/services and INetSim. **These live outside the Windows
   guest disk.** Transferring Windows storage does NOT install CAPEv2
   on the receiving Ubuntu host. Command1 host bootstrap/installer
   remains separate unfinished work; Command3 will configure conf and
   start services as agreed with user.

### Implemented / tested **offline** (development only)

- `scripts/command1_export_existing_master.py`: real libvirt
  `win11` source, exact SSL55 master UUID pin, must be **shut off**.
  Hash-verified, root-private, exclusive, no overwrite, flattened
  independent QCOW2 copy, full UEFI VARS and master-specific swtpm blobs,
  saved exact domain XML, SHA-256 manifest, read-only plan/verify modes.
  Exports Windows apps/settings *by cloning bytes*, not by reimplementing
  them. Never start or revert `win11`, `win11_1` or trial.
  **This private folder includes Windows user data, secrets and TPM
  material. Never upload to GitHub or into ChatGPT.**
- `scripts/command1_import_existing_master.py`: approved **other host**
  only; validates master manifest, firmware CODE path and collisions;
  stages Windows image byte-for-byte (no accidental QCOW2 re-encode),
  UEFI and **master's own** TPM blob at separate host state path,
  defines the guest in SHUT OFF state. Requires reviewed target swtpm
  service account. Does **NOT** automatically boot Windows or attest
  Windows activation, TPM/PCR portability, supported CPU/OVMF, CAPE Agent
  or a running restorable snapshot.
- Both phases are visible via `bash scripts/command1_pre_vm.sh
  master-export ...` and `master-import ...`; this wrapper is not
  the complete fresh Ubuntu CAPEv2 installer.
- `scripts/command2_from_exact_master_bundle.py`: one prompt
  **"How many ADDITIONAL Windows VMs? (1-16)"**. On OTHER hosts
  it coordinates existing source-verified zero-NIC independent
  QCOW2+UEFI clone staging, exact win11_1..N UUID/MAC/hostname
  reservations, one permanent master-equivalent `default`/virbr0
  e1000e NIC and per-VM stable DHCP IP reservations, and all-N
  immutable Windows NAT ISO config media. Root/private plan+approved
  apply, fails closed on partial work. The intermediate isolated
  guest config JSON created by the old zero-NIC stager is **NOT**
  deployed for the master-NAT profile. Does NOT boot Windows or
  invoke configuration ISO automatically.
- `command2_portable_master_nat_agent_batch.py` can independently
  verify host-side Agent over all N NAT addresses **after** the guests
  are properly personalized and booted.
- SSL55 actual `win11_1` permanently verified on `default` NAT,
  unique IP `192.168.122.131`, and **three** running RAM/Windows
  QCOW2/UEFI snapshots; the latest `cape_one_nat_win11_1` is present.
  **Do not revert any of these** until a matched swtpm 2.0 restore
  is genuinely proven; libvirt internal checkpoints do not imply
  atomic TPM state rollback.

### 2026-10-13: guarded FINAL SHUT OFF handoff for N permanent-NAT clones

Development-only on the **approved OTHER host**, never SSL-55:

```bash
# Requires previously captured and independently checked N running
# RAM/Windows QCOW2/QCOW2-UEFI checkpoints; PLAN is read-only.
sudo python3 scripts/command2_portable_workflow.py \\
  --phase master-nat-final-shutdown --mode plan \\
  --approved-host "$(hostname -s | tr '[:upper:]' '[:lower:]')" \\
  --journal /root/approved-private/command2-identity-reservation.json \\
  --witness-dir /root/approved-private/windows-witness

# ONLY after reviewing the exact plan and separate-host evidence, change
# --mode plan to --mode apply, with direct per-VM operator approval.
```

This wraps `command2_portable_master_nat_final_shutdown.py`.
The plan requires every cloned guest (1–16) to be RUNNING, with
the exact host-journal UUID/MAC/DHCP reservation, positive NAT Agent and
Windows acceptance evidence, and existing named *running* QCOW2 OS +
UEFI + RAM internal snapshots; it reads only. The apply mode rechecks
all N, then uses the guarded `portable-master-nat` graceful Windows
shutdown path, confirming SHUT OFF per VM and preserving every saved
snapshot. It stops after any uncertain/failed shutdown, never destroys,
reverts, starts or auto-retries. It is **not safe to rerun automatically
after a partial batch**. The final state expected by standard CAPE is
SHUT OFF, with a checkpoint originally captured RUNNING.

**Important limits:** this adds the missing NAT/SHUT OFF sequencing but
does NOT restore, synchronize or test swtpm persistent/volatile TPM state.
These checkpoints remain **CAPE_UNVERIFIED** until separate disposable-host
full restore/revert tests, malware egress containment, CAPE configuration,
and concurrent benign analyses pass. All current tests are synthetic.

### Blocking work BEFORE full Commands 1 & 2 can be certified

- Command1 safe noninteractive install of **complete** Ubuntu host
  CAPEv2/INetSim/database/CAPE service dependencies on a new host;
  existing distro virtualization/prereq/source components are partial.
  Avoid blindly running upstream `cape2.sh base`/`kvm-qemu.sh all`,
  which previously had real host-side errors and dangerous side effects.
- Command1 guest import followed by a **real verified boot**,
  compatible TPM/BitLocker/Windows licensing, CAPE Agent and NAT
  verification, supported QCOW2 UEFI conversion and newly captured
  **final running** master snapshot.
- Command2 attach each guest's individualized NAT ISO and **safely
  execute the intended Windows hostname/DHCP provisioning** with
  verified bootstrapped guest transport, reboot and signed evidence;
  QEMU guest agent/startup SYSTEM task presence in the user's actual
  master has NOT yet been established. The disk clone alone cannot
  change unique Windows hostname/IP.
- Command2 per-guest **RAM+OS+UEFI running snapshot** after guest
  changes, coupled with independent **TPM permanent/volatile state
  recovery that passes TWO benign revert cycles on disposable guests**
  before CAPE snapshot promotion.
- Per-job malware containment policy for permanently attached NAT
  Internet, plus CAPE machine configs and INetSim path checks.
  Unrestricted NAT Internet during malware execution is NOT an
  analysis safety guarantee.

### Resource and portability warnings

- Physical SSL55 latest shared volume free space was approximately
  51 GiB after three snapshots; conservative full master export
  demands master virtual disk capacity PLUS 30 GiB reserve.
  **Do not try export to an undersized SSL55 local destination.**
  Use a separate, approved, private volume with capacity.
- A private golden bundle must be delivered to each target host by
  an authenticated transfer (SSH/rsync or a local private disk) with
  its manifest. Automation source in GitHub is NOT the Windows image.
- Never copy the MASTER's TPM secrets unchanged to every `win11_N`.
  Unique Windows/UEFI/TPM identity is mandatory, and encrypted Windows
  source disks need authorized clean-template preparation.
- All new code is **offline-CI-tested only**, and the user has asked
  to postpone physical testing on other hosts until after Command3.
  Don't call the final one-command installers production-ready yet.

**Release rule:** Only claim Command1 and Command2 complete after all
remaining implementation and physical acceptance gates genuinely pass.
All development stays on `development` — never alter `main`.
