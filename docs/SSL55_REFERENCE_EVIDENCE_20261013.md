# SSL-55 source report reconciliation — 2026-10-13

Evidence: operator-supplied local JSON report
`CAPE_SSL55_InstallerReference_20261013_103129.json`.
The original JSON (with hostname and package versions) is NOT copied into
GitHub; the following is an engineering summary only.

**Canonical OS:** Ubuntu 24.04.3 LTS, x86_64, 32 CPU threads,
kernel 7.0.0-38-generic.
**Reference master:** `win11` currently shut off, snapshot names
`Afterfull`, `basicinstallwinsnapshot`, `finalshutoffversion`
reported. A named snapshot alone does NOT establish running RAM
content, availability on another host, or consistent swtpm state.

**CAPE:** all six named conf files exist; `cape.service`,
`cape-processor.service`, `cape-rooter.service`, `cape-web.service`,
and `suricata.service` loaded/enabled and active. `/mnt/tmpfs`
is an active `tmpfs` filesystem. PostgreSQL and MongoDB also active.

**Package versions observed:** Python3 3.12.3-0ubuntu2.1; Git
1:2.43.0-1ubuntu7.3; OVMF 2024.02-2ubuntu0.10; swtpm/swtpm-tools
0.7.3-0ubuntu5.24.04.1; PostgreSQL metapackage
18+293.pgdg24.04+1; MongoDB package `mongodb-org` 8.0.32;
Suricata 1:7.0.17-0ubuntu0.

**Unexpected package registration:** Ubuntu `dpkg-query` reported
`not_installed_or_unknown` for qemu-system-x86, qemu-utils,
libvirt-clients, libvirt-daemon-system, virt-manager and virtinst.
This is **NOT PROOF that working QEMU/libvirt binaries are absent**.
The source demonstrably retains registered virtual machines and
its XML/snapshots; automation MUST inspect actual paths, versions
and compatibility before installing distro packages atop an unknown
custom build. No 'apt install all missing' shortcut is approved.

**INetSim status unknown:** `inetsim` dpkg query returned
`not_installed_or_unknown` and `inetsim.service` had
LoadState=`not-found`. Neither identifies alternative binary,
container, source-install, or custom service definitions. The
automation cannot honestly certify INetSim or silently select
an unverified version based on this report.

**CAPE Git revision:** `unavailable` in the source JSON. This
may reflect absent `.git`, permissions or Git safe.directory;
it does not establish any known CAPE release revision.

**Cloud/data:** `rclone` binary reported installed, but root-owned
0600 rclone crypt credentials, OAuth authentication, Google Drive ACLs
and all-byte-verified master upload have NOT been shown or used.
`rclone_installed = true` is not proof of any configured remote.

**Storage:** `/var/lib/libvirt/images` and `$HOME` each reported
48.41 GiB free, potentially the same underlying filesystem. The
existing golden exporter's `MIN_AVAILABLE=30*1024**3` check requires
`master Qcow2 VIRTUAL capacity + 30 GiB` free. If its true virtual
disk is >18.41 GiB, the reported location **cannot** pass the
conservative source-export check, even though the compressed QCOW2
file may occupy less than its virtual size. The exact disk virtual
size and backing chain are not in the supplied JSON. Do not start
an export or assume Google Drive alone supplies local staging space.

## Developer-mode follow-through (NO SSL55 mutations performed)

- `scripts/command1_reference_report_gate.py` validates source JSON,
  returns explicit unknown/blocked requirements and DOES NOT infer
  missing hypervisor capability from `dpkg`.
- `scripts/command1_actual_master_export_capacity.py` checks the
  exact source libvirt/QCOW2/UEFI/TPM metadata and capacity without
  exporting/copying Windows or restoring snapshots.
- `scripts/command1_ssl55_deep_fingerprint.py` combines root-only
  metadata-based source inspection, actual QEMU/libvirt tool paths,
  CAPE Git SHA (if available), INetSim path presence and root rclone
  config permissions into ONE no-secret JSON report.
- Existing `scripts/command1_pre_vm.sh` now offers:
  `reference-evidence`, `source-export-capacity` and
  `source-deep-fingerprint`, all read-only.

Read-only deep host fingerprint is the next minimal input to resolve
exact installed package/source and export disk-space uncertainty; it
does NOT make Windows/TPM snapshot restoration physically tested.
Original SSL-55 master and GitHub main must stay unchanged.

**This is not yet a fully unattended CAPEv2+INetSim fresh-install,
exact Win11 running master, independent all-N clones, reliable
TPM-coherent snapshot reset, or verified Command3 live routing
release.** The user needs a physically disposable new host for
benign acceptance after the remaining implementation gates are met.
