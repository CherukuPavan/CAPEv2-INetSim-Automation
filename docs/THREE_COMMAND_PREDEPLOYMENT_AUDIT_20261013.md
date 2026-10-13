# Three-command integration audit — October 13, 2026 (development)

## 2026-10-13 later physical evidence and revised operator scope

This is a **newer checkpoint** than the original predeployment audit text
below. The actual original cold Windows master was SHA-256 verified on SSL46,
and the private `cape_crypt` upload completed with independent cloud byte
comparison, no source changes/deletion, and script exit 0
(`CAPE_GoogleDriveUpload_20261013_124755.txt`). The old cloud/upload blocker
listed later in this document is now CLOSED **for source cloud transfer**.
Target-host retrieval and SHA verification remain UNTESTED.

The operator now requires **worldwide independent-network deployment**:
a village machine must not log into the owner's personal Google account and
must not depend on SSL55/SSL46 being online. A new reviewed component
`scripts/command1_worldwide_drive_reader.py` provisions a private
`drive.readonly` service-account crypt remote on an approved other host
without overwriting existing credentials. It still requires individually
authorized service-account Viewer folder sharing, a securely delivered key,
and matching original crypt password/salt. See
`docs/COMMAND1_WORLDWIDE_PRIVATE_DRIVE_READER.md`. NEVER make the Drive
folder public; no actual independent target download has yet passed.

**INetSim automation is deferred at the operator's request**. This is a
scope change, not evidence INetSim exists, is installed or works.

**Full new-host CAPE + database/service bootstrap, Windows golden master
first boot, final verified and TPM-consistent running snapshot, truly complete
all-N clone sequence, snapshot restoration, non-exposing routing and complete
three-command execution remain engineering and physical acceptance gaps.**
The availability of gated phase helpers and green synthetic CI does not
close these. No helper may claim rollback safety without real, independent
two-cycle guest/TPM evidence from a disposable other host.


## 2026-10-13 SSL55 reference JSON received

The operator uploaded a redacted package/service reference report and
our audit is committed as
[`docs/SSL55_REFERENCE_EVIDENCE_20261013.md`](SSL55_REFERENCE_EVIDENCE_20261013.md).
It proves Ubuntu 24.04.3 LTS, CAPE/processor/rooter/web/Suricata
loaded+active, MongoDB active under `mongodb.service`, PostgreSQL
active, a mounted `/mnt/tmpfs`, master `win11` shut off with a named
`Afterfull` snapshot, and `rclone` installed. It does NOT attest
INetSim installation, working QEMU/libvirt via selected dpkg package
names, actual CAPE checkout SHA or Windows virtual image size.
VM/home storage free: 48.41 GiB on the reported host; conservative
golden source export needs Windows virtual disk size PLUS 30 GiB.
A root-only READ-ONLY deep host fingerprint is implemented to
resolve these unanswered requirements without touching SSL-55.

**Reference host:** CSE-SSL-55; Windows golden master `win11` remains
protected. The operator's manually completed CAPE configuration and
five-service startup proof are the canonical source. No host commands,
snapshot restoration or Windows/TPM transfer were executed by the
GitHub development activity below. `main` unchanged.

**All-code offline CI:** 1,524 Python tests passed on each of
Python 3.10 and 3.12
([Actions #38385255330](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38385255330)).
This includes the exact private GitHub development checkout guard and
the approved five-service Command3 restart tests.
This is *synthetic verification only*, not fresh-host qualification.

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
| Command3 routing/service acceptance | `scripts/command3_cape_routing.py`, `scripts/command3_cape_restart_verified.py` | Routing still READ ONLY; separate approved exact five-unit restart/verify implemented and tested |

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
5. **Command3 full execution:** The five configuration edits,
   count-bound KVM planning and separately approved five-service
   restart/verify are available through one Command3 entrypoint,
   with distinct modes and root-private stage receipts. The reference
   routing profile is still NOT automatically written; the screenshot
   connects CAPE internet mode to a libvirt VM-side NAT bridge rather
   than a verified external dirty-line NIC. Host network/service
   integration and benign real-host acceptance remain necessary.
   An active systemd unit does NOT prove successful Windows snapshot
   restoration.
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

## Private source distribution note

This GitHub repo is PRIVATE, not publicly readable by `curl` to raw
GitHub without authentication. New hosts must use a separately
AUTHENTICATED `development` checkout, full pinned commit SHA, clean
tree and the read-only `private_repo_checkout_preflight.py` before
planning any mutable installation. See
`docs/PRIVATE_DEPLOYMENT_SOURCE_AND_GDRIVE_HANDOFF.md`.
