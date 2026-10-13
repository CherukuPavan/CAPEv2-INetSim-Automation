# Command 1 — Joined encrypted private Drive download and exact cold master import

**2026-10-13 developer-stage engineering, NOT a fresh-host Command 1 release.**
This phase makes exact-source Windows master transfer and import an auditable
one-entrypoint workflow without touching SSL-55, your personalized source
Windows disk or any existing snapshot.

## New target-host entrypoint

`scripts/command1_private_master_stage.py`:

- **plan** requires an approved DIFFERENT host, root, a private
  personal Drive rclone crypt remote, an encrypted bundle ID such as
  `cape-master-20261013_abcdef`, a NEW root-private destination
  folder, two independent NEW local target files for OS QCOW2 and
  OVMF VARS, and the actual host swtpm service username.
- It checks the remote encrypted object inventory and new-host disk
  reserve, then preflights the target libvirt file paths.
- **stage** requires an additional typed batch confirmation and persists
  an exclusive root-private progress witness. It calls the original
  private crypt Drive downloader (which requires its own typed approval),
  verifies the original golden master's **entire** canonical SHA256
  manifest, then calls the existing exact cold master import's own
  preflight and separately approved import.
- It only reports success after the importer has verified the expected
  Windows/UEFI/TPM manifest, libvirt domain, target paths and remaining
  shut-off state. It does **not** boot Windows or create a snapshot.
- **verify** read-only re-checks exact manifest and installed master.
- On any interrupted download or failed import, a private
  `PARTIAL_OR_UNKNOWN` receipt is saved. The workflow does not delete
  the source bundle, guess missing TPM files, reboot, revert, blindly
  retry, or erase an existing VM.

Operator should not execute this on SSL-55. The user's manual source
configuration remains finished and protected; any transfer requires
a real exported bundle and preconfigured private encrypted Drive
remote, which are NOT yet present/verified in this environment.

## Future approved target-host template (not ready to run yet)

```bash
sudo python3 scripts/command1_private_master_stage.py \
  --mode plan \
  --approved-host NEW_HOSTNAME \
  --crypt-remote MY_PRIVATE_RCLONE_CRYPT_NAME \
  --bundle-id cape-master-ACTUAL_SOURCE_ID \
  --bundle-dir /ROOT_PRIVATE_BACKUPS/cape-master-ACTUAL_SOURCE_ID \
  --os-disk /APPROVED_OS_IMAGE_PARENT/win11.qcow2 \
  --uefi-vars /APPROVED_UEFI_PARENT/win11-VARS.fd \
  --tpm-user ACTUAL_SWTMP_SERVICE_USERNAME
```

(Use the actual swtpm service account detected on the new host, not
the SSL-55 guest TPM secrets as a clone identity. The user's original
Windows master state may use its OWN transferred TPM when imported;
each Command2 clone needs an independent TPM instance.)

After a reviewed plan, `--mode stage` will perform the private
download and guarded cold import on the approved new machine.
`--mode verify` re-checks the imported shut-off master.

## Remaining work, explicitly NOT accepted yet

- Unattended fresh Ubuntu bootstrap, CAPEv2+INetSim package and service
  installation, Python/Poetry/DB/KVM/OVMF/swtpm configuration.
- Actual private Drive OAuth/crypt setup and transfer of user's real
  exact master bundle (the user offered 5 TB but has not yet uploaded).
- Verification of sufficient SSL-55 export staging space; current
  cold-image exporter still flattens QCOW2 locally before transfer.
- New-host boot of original customized Windows/UEFI/TPM and independent
  clean running-state snapshot with demonstrated TPM-safe restoration.
- All-N Command2 guest first boot/personalization and reliable
  repeated full-state rollback for CAPE analysis.
- Command3 full routing and service restart orchestration and real
  all-N CAPE tests.

Read alongside:
- `docs/COMMAND1_PRIVATE_DRIVE_TRANSFER.md`
- `docs/COMMAND12_PRE_COMMAND3_ENGINEERING_AUDIT_20261013.md`
- `docs/COMMAND3_JOINED_AUTOMATION_HANDOFF.md`

Successful offline CI is a code acceptance milestone, not proof of
any real VM, Google Drive account, tmpfs reboot or service runtime.
