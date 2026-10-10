# Command 2 acceleration checkpoint — 2026-10-10

**Branch:** development only. **Status:** verified first independent
Windows clone plus successful no-NIC CAPE agent check; reusable multi-clone
staging code now tested in GitHub CI. Complete production Command 2 remains
unfinished. No malware execution is authorized.

## Host-verified SSL-55 accomplishments

- Protected original Windows 11 master `win11`: SHUT OFF; original
  snapshot, TPM, NVRAM, backing layers and backup preserved.
- Standalone decrypted 64-GiB Windows QCOW2 template verified:
  `/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2`.
- `win11_trial_1` boots on an independently copied QCOW2, new libvirt UUID,
  separate UEFI NVRAM and newly created emulated TPM, with zero NICs.
- Windows C: fully decrypted (0.0% BitLocker); Python 3.10.11;
  elevated CAPE Agent 0.23 responds at localhost port 8000 with status init.
- Dedicated `cape-analysis-isolated` libvirt network DEFINED, INACTIVE,
  non-autostart, no bridge created, no NAT, no DHCP, no libvirt DNS.
  Proposed `cape-lab0` and `192.168.240.0/24` have no local route collision
  detected, but remote/site conflicts are NOT checked.
- Installed and verified transient nftables `inet cape_analysis_guard` with
  SHA-256 `58b84446ad74ac7ea8b14aa57d94c19945baa3db7330e54c7fb2312a9577ea14`.
  Reboot persistence and actual IPv4/IPv6 guest egress isolation NOT established.
- Host persistence audit: nftables.service disabled; the existing
  `/etc/nftables.conf` has `flush ruleset`. Never blindly enable the
  generic nftables.service, which could remove Docker/libvirt rules.

## New development, tested but NOT executed on SSL-55

1. `scripts/stage_first_no_nic_windows_clone.py`: generalized its strict
   proven zero-NIC domain renderer to take a new name/disk/NVRAM while
   preserving all original master domain validation.
2. `scripts/command2_stage_independent_clones.py`: interactive
   `--mode plan|stage --count N` (1–16); plans `win11_1`, `win11_2`,
   etc, assigns planned `WIN11-1`, `WIN11-2` and
   `192.168.240.101`, `192.168.240.102` ... (not written to Windows
   yet), checks source and disk space, clones the independent plaintext
   template using `qemu-img convert`, copies NVRAM into distinct files,
   generates UUID/GenID/future MAC, defines only SHUT-OFF ZERO-NIC VMs
   with new per-domain swtpm state on first boot, checks the libvirt
   definition and disk independence. On partial failures, preserves
   all artifacts and reports them for manual review; it does NOT start
   guests, attach NICs, edit CAPE, or claim that hostnames/IPs have been applied.
3. `scripts/command2_clone_vms.py` legacy CLI `--apply` is now
   explicitly blocked. Do not use the old code to export the
   encrypted master or call unavailable virt-win-reg tooling.
4. `scripts/guard_cape_lab_boot.py`: independent nftables guard
   **reconciliation module only**, for a future dedicated CAPE-only
   systemd boot service. It verifies an existing CAPE guard or
   creates only the intended table if missing. It never flushes unrelated
   tables, starts any lab network or affects Windows guests.
   **The systemd boot service has NOT been installed/enabled.**
5. `scripts/patch_clone_hivex_system_copy.py`: proof-of-concept Hivex
   patching of a *separate extracted SYSTEM hive copy*, for hostname and
   static IPv4. Does NOT write to any QCOW2 or VM. Need first real cloned
   hive integration test, readback and benign guest boot before using it
   in bulk provisioning. A new guest MAC may change Windows interface GUID.

Unit tests for these modules passed together with the existing offline suite
in [CI run 38091435476](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38091435476).
A passing mocked CI run is **not** equivalent to successful deployment on SSL-55.

## Remaining critical Command 2 acceptance work

- Implement and safely enable a **separate** CAPE-only boot guard service,
  with rollback plan and ordering; refuse lab activation if guard is absent.
  No blanket nftables.service reload or global forwarding edits.
- Approve source subnet/site overlap and implement INetSim on host-side
  `cape-lab0` without enabling actual external malware egress.
- Test harmless isolated-network packet attempts in all directions and
  IPv4/IPv6; verify blocked host management, campus, Docker, NAT and Internet.
  Verify benign host-to-guest CAPE agent access on TCP/8000.
- Implement offline Windows SYSTEM-hive safe writeback to individually
  staged **stopped clones**, with whole-disk protection and rollback;
  validate unique Windows hostnames/IPs from inside Windows after boot.
  Do not assume a copied Registry adapter GUID survives new MAC hardware.
- Add fresh clone swtpm/AppArmor startup validation, snapshot+snapshot-revert
  without touching the master, dual guest parallel run and CAPE machine
  registration. A separate-stage handoff currently exists.
- Merge into one portable Command 2 entry point **only after**
  successful SSL-55 end-to-end acceptance. Add host-independent discovery
  instead of hardcoding SSL-55 backup directories and snapshot names.

## Operator hold

Keep `win11` shut off; `win11_trial_1` running with zero NICs;
`cape-analysis-isolated` inactive and non-autostarted. No malware.
Do NOT execute `command2_stage_independent_clones.py --mode stage`
without reviewing its SSL-55 plan/storage report first. It is intended to
be applied to one disposable clone for initial field verification.

## Command 2A single-test host acceptance ready (2026-10-10)

- Generalized multi-clone script now confirms the original protected
  `win11_trial_1` UUID matches its previously verified value, not only
  the VM name and zero-NIC status.
- Every independently copied disk is now required to pass the **same
  plaintext NTFS candidate check** that was used for the successful first
  Windows clone, *before* clone NVRAM publication or libvirt definition.
- Added fail-closed regression test: copied disk judged encrypted may NOT
  proceed to registration; temporary artifacts are retained for review.
- One-step `scripts/command2_stage_first_clone_acceptance.sh`
  performs preflight and, only after terminal acknowledgement
  `STAGE-WIN11-1`, stages **one** shut-off zero-NIC `win11_1`.
  Both steps append to a single private `CAPE_Command2A_FirstClone_*.txt`.
  It never starts guests or joins an analysis network. The source is
  `win11_decrypted_template.qcow2`, never the encrypted master snapshot.
- Exact development revision through this checkpoint:
  `d9a085325cbc26f91b6d4e001a2ecad00e8c7441`.
  Offline CI: https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38092048383
- No second clone is host-verified yet: expect either preflight PASS
  then a shut-off clone definition, or BLOCKED with one operator report.
  Clone guest hostname/IP, TPM/AppArmor startup, snapshots, CAPE reachability,
  independent L2/L3 isolation and parallel CAPE acceptance still pending.
- Private GitHub repository access from the SSL-55 shell is NOT known;
  operator deployment must fail safely if the host cannot authenticate.

## October 10 — legacy win11_1 filename collision caught safely

Operator executed the first clone acceptance wrapper. Authenticated GitHub
checkout succeeded at reviewed SHA
`46de6aaeb65f34429f1dc427d9e37f5b7574b7ea`. The plan correctly
stopped **BEFORE** staging, reporting
`Target disk/NVRAM already exists: win11_1.qcow2`,
`created=[]`, `BLOCKED_OR_PARTIAL_REVIEW_REQUIRED`.
That older file predates the Command 2A clone test. Its content is NOT
reverified by this report and may be an earlier protected recovery copy.
**DO NOT rename, overwrite, delete, truncate, convert or start this image.**

The safe fix is **separate Command 2-specific artifact filenames**:
`win11_1.command2.qcow2` and
`win11_1.command2_VARS.fd`, and the analogous names for `win11_N`.
Libvirt domain naming stays `win11_1`, `win11_2`, etc.; only the
private clone artifacts use separate filenames. Both target paths
are checked for absence and are created exclusively. The verified
zero-NIC XML renderer now permits matching legacy names or matching
`.command2` names, rejecting mixed pairs or different directories.
Offline CI includes distinct-destination and renderer tests.

The operator must obtain the new `development` revision before the
acceptance test; the old clone code is intentionally not patched
in place on SSL-55. Do not use a previously downloaded checkout
whose commit SHA is outdated. If the separate target names are also
occupied, STOP and review instead of overwriting or deleting.

## Actual SSL-55 independent second clone staged — Oct 10 22:50

Operator report `CAPE_Command2A_FirstClone_20261010_225052_N9tH7v9D.txt`
is **PASS**:
- Plan: `MULTI_CLONE_ZERO_NIC_PLAN_ONLY`, free capacity 125 GiB;
  conservative requirement 94 GiB for 1 clone.
- Stage: `INDEPENDENT_ZERO_NIC_CLONES_STAGED`, one `created`
  entry with `STAGED_SHUT_OFF_ZERO_NICS`.
- Domain: `win11_1`; UUID
  `732b2256-ee99-41fa-881d-fbf5c476d960`.
- Fresh independently cloned disk
  `/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2`
  and NVRAM
  `/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd`.
- No source-master mutation reported; guest **NOT STARTED**, zero NICs,
  no network attached, no snapshot, TPM state created only on first boot.
- `WIN11-1` and `192.168.240.101` remain **PLANNED**, NOT SET
  inside Windows. Planned MAC
  `02:75:dc:63:ca:e1` is NOT attached to any NIC.
- Malware execution NOT approved, egress isolation NOT verified.

Next: independently check live libvirt identity, disk chain, NVRAM
and AppArmor scoping; guarded TPM socket profile for this exact new VM;
then one benign first boot with zero NICs. Do not start trial/master,
activate the network, or use malware samples.

## First independent clone benign boot gate READY — Oct 10

Code in `scripts/command2_boot_first_cloned_windows.py` and wrapper
`scripts/command2_first_clone_benign_boot_acceptance.sh` passed
[synthetic CI 38093326064](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38093326064).

This test is pinned to the reported `win11_1` UUID
`732b2256-ee99-41fa-881d-fbf5c476d960`; verifies independent
`win11_1.command2.qcow2` and `win11_1.command2_VARS.fd`,
existing master and trial status/identities, current snapshot,
app-level clone AppArmor swtpm rule, sufficient memory, read-only
QCOW2 check, and zero NIC/host passthrough in inactive XML.

Operator `plan` is no-write. Only after approval `boot` may install
a narrow name-specific AppArmor swtpm socket include, start the named
clone `--paused`, check the live zero-NIC QEMU definition, and
`virsh resume` it. The script is limited to the named clone
and can suspend only it if post-start checks fail.

**Not yet host verified:** `win11_1` Windows boot, agent status,
guest static IPv4, AppArmor startup, independent TPM state, or new
clone Windows desktop. The first benign boot should be validated
by opening the **win11_1** console and inspecting the guest desktop
and localhost CAPE Agent status. No NIC/network, sample analysis,
firewall service reload or host network modification is authorized.
