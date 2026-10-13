# Three-command integration audit — October 13, 2026 (development)

**Reference host:** CSE-SSL-55; Windows golden master `win11` remains
protected. The operator's manually completed CAPE configuration and
five-service startup proof are the canonical source. No host commands,
snapshot restoration or Windows/TPM transfer were executed by the
GitHub development activity below. `main` unchanged.

**All-code offline CI:** 1,478 Python tests successful on each of
Python 3.10 and 3.12, in
[GitHub Actions #38372435151](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38372435151).
That is *synthetic verification only*, not fresh-host qualification.

## Newly integrated code

| Workflow | Committed component | Code status |
|---|---|---|
| Source/target single-report readiness | `scripts/command123_readonly_machine_report.py` | Read-only + tested |
| Source-specific SSL55 CAPE host provenance | `scripts/command1_reference_host_blueprint.py` | Read-only, no secrets, tested |
| Cold golden Win11 export | `scripts/command1_export_existing_master.py` | Exact QCOW2/UEFI/XML/swtpm with all-member SHA256 incl. intent metadata |
| Personal Google Drive upload/download | `scripts/command1_private_drive_bundle.py` | Guarded rclone CRYPT transport, all-member SHA and immutable transfer tests |
| Private encrypted download -> cold master import | `scripts/command1_private_master_stage.py` | Guarded joined developer-stage flow |
| Persistent per-host CAPE tmpfs | `scripts/command1_cape_tmpfs_mount.py` | Guarded other-host systemd mount + preflight; physical reboot test not done |
| Count-driven Command2 all-N cloning | `scripts/command2_exact_master_full_sequence.py` | ONE guarded interactive N-VM sequence using exact-master helpers; TPM restore unproven |
| Command3 exact config / KVM registration | `scripts/command3_from_operator_reference.py` | ONE config-only entrypoint, conditional on all-N snapshot records and tmpfs |
| Command3 routing/service acceptance | `scripts/command3_cape_routing.py`, `scripts/command3_cape_services.py` | READ ONLY by design, not active routing/service deployer |

IMPORTANT: Count 3 means additional `win11_1`, `win11_2`, `win11_3`,
not replacing `win11`. Clone Windows configuration uses verified
permanent NAT DHCP MAC reservations; it does **not** mean a guest-side
`DHCP Enabled: No` static setting. The source guide's `Afterfull`
running snapshot is not carried over intact by QCOW2 flattening.

## Real release gaps; none may be waived by code-only CI

1. **Command1 complete host installation:** The canonical SSL55
   manual Step7 custom `kvm-qemu.sh all` and Step10 `cape2.sh base`
   altered global dependencies/packages/kernel/power/service state.
   There is no fully safe idempotent portable CAPEv2+INetSim+DB+
   custom hypervisor build replacement yet. Existing prereq/distro
   libvirt and tmpfs modules do not make that full installation.
   Next required engineering input: redacted SOURCE PROVENANCE report
   from `command1_reference_host_blueprint.py`, to pin the real
   CAPE commit/service/package versions without guessing; then
   implement and test a compatible host install.
2. **Command1 actual master running snapshot:** Exported cold image
   copies installed Windows/apps/settings and original master TPM
   bytes. It does NOT recreate the original `Afterfull` libvirt
   RUNNING RAM snapshot metadata on a fresh target. Target host must
   independently boot original Windows/TPM/UEFI, demonstrate elevated
   Agent, capture a fresh running RAM/OS/UEFI checkpoint, and pass
   TPM-consistent restore acceptance before auto-registering.
3. **Command2 independent Windows boot:** A genuinely BitLocker-sealed
   Windows system volume cloned with a NEW TPM may not boot without
   an operator-approved unencrypted maintenance clone source or
   supported recovery. Never copy the master TPM identity to every
   clone. Actual per-guest firstboot/guest verification requires a
   target machine; no synthetic unit test supplies it.
4. **swtpm2 snapshot consistency:** QEMU/libvirt native snapshots
   cannot by themselves atomically restore separately stored TPM
   persistent/volatile state. Existing running-snapshot candidates
   are not proven safe CAPE rollback sources. Implement/test a
   TPM-state-aware recovery model on disposable new-host guests,
   with at least two successful benign restoration cycles.
5. **Command3 full execution:** The five configuration edits and
   count-bound KVM planning are joined; the reference routing profile
   and service restart are not yet automatic. Must be integrated
   with verified target network/service settings and benign real-host
   validation, rather than blindly asserting that a unit is active.
6. **Cloud and capacity:** No private personal Google Drive credentials
   have been configured or source golden-master bundle uploaded.
   Root-owned rclone config is required, with separate personal Drive
   OAuth and crypt password; storage/copy time and guest count are
   unknown until measured. No copied TPM/Windows artifacts are in GitHub.
7. **Physical reproducibility:** Fresh Ubuntu host RAM, disks,
   virtualization support, network, packages, and CAPE/Windows
   runtime can only be measured on the actual target. CI does not
   test these physical properties.

## Minimal next step WITHOUT moving to another machine

On SSL55, run the single **READ-ONLY** provenance script
`scripts/command1_reference_host_blueprint.py` and upload the
resulting JSON report. It only records allowlisted version/status and
master metadata; it does not read conf contents, TPM, Google OAuth,
or Windows bytes; no manual config is redone.

Then, on your own schedule, prepare the root-owned personal Drive
rclone CRYPT remote following
`docs/COMMAND1_PRIVATE_DRIVE_TRANSFER.md`. Do not make the
Google Drive folder public; do not send rclone.conf or passwords.

Before a second machine's installer is run, the seven real blockers
above must either be coded and verified or explicitly remain a test
objective on a disposable approved host. A claim that "everything is
done except testing" would currently be FALSE.
