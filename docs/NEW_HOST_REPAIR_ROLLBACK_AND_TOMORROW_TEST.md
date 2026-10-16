# Tomorrow's new-host test: recovery checkpoint, doctor, repair and rollback

**Scope: DIFFERENT authorized Ubuntu 24.04 x86_64 target, anywhere in the
world.** **Not** SSL55, not SSL46, not a production host with unrelated VMs.
The private golden-master bundle already exists in the operator's encrypted
personal Google Drive. INetSim is expressly **deferred** for this test.

> THIS IS A DEVELOPER-STAGE DRY RUN. No fully unattended three-command
> installation or real TPM-safe running snapshot rollback has been
> certified. The recovery tooling below is deliberately narrower than a
> universal undo: it never purges APT packages, deletes virtual disks,
> undefines libvirt VMs, reverts TPM, resets firewall rules or formats data.

## Before FIRST deployment attempt

**Operator's rollback requirement is deployment-scoped**, NOT a complete
Ubuntu reset: undo ONLY changes caused by the three deployment commands and
preserve the initial packages, files, VMs, network and services. The
[deployment-only rollback contract](DEPLOYMENT_SCOPED_REPAIR_ROLLBACK_CONTRACT.md)
documents required per-resource receipts and reverse-order undo. This is
NOT completely implemented: the current command only restores the six CAPE
config files. An optional offline full-host image is a secondary safety
precaution for a disposable test machine, not the intended rollback mechanism.

1. Capture a *before* read-only inventory and baseline on the NEW host before
   any mutable deployment command. Keep this private for troubleshooting.
2. Use a private, authenticated, **pinned `development` checkout** of
   `CherukuPavan/CAPEv2-INetSim-Automation`; don't download moving
   scripts with uncredentialed curl or sign into a personal Google account.
   Consult `docs/PRIVATE_DEPLOYMENT_SOURCE_AND_GDRIVE_HANDOFF.md` and
   `docs/COMMAND1_WORLDWIDE_PRIVATE_DRIVE_READER.md`.
3. Ensure sufficient physical memory, free storage for the cold bundle
   and N Windows clones, VT-x/AMD-V, supported UEFI/swtpm, and a **safe
   network**. Do not analyze untrusted malware on default libvirt NAT.

Once the private repo is checked out on that fresh target:

```bash
cd "$HOME/CAPEv2-INetSim-Automation"
# READ ONLY: new-host report (never include credentials or Windows contents).
python3 -B scripts/command123_repair_doctor.py \
  --approved-host "$(hostname -s)" \
  --additional-count 0 \
  --storage-dir /var/lib/libvirt/images \
  > "$HOME/CAPE_NewHost_InitialDoctor.json"

# Save the returned receipt path; one new private record per test.
sudo python3 -B scripts/command123_repair_rollback.py \
  --mode baseline --approved-host "$(hostname -s)"
```

The baseline copies any existing
`/opt/CAPEv2/conf/{api,auxiliary,cuckoo,kvm,mitmdump,routing}.conf`
as SHA256-bound bytes to a unique root-only receipt under
`/var/lib/cape-deployment-recovery/<UUID>/manifest.json`. On a blank
host with no CAPE config folder, it records the files as **absent**.
Never upload those recovery copies: they may include local DB credentials.

Run the specifically approved Command 1/2/3 development phases as
per their handoffs. Do not bypass any phase that refuses a missing
prerequisite, guest boot, network policy or TPM-aware recovery witness.
**No complete three-command entrypoint has been physically qualified.**

## After deployment's intended CAPE configuration is present

Seal ONLY after you have deliberately reviewed the resulting CAPE
configuration. Use the exact receipt printed at baseline:

```bash
sudo python3 -B scripts/command123_repair_rollback.py \
  --mode seal --approved-host "$(hostname -s)" \
  --receipt /var/lib/cape-deployment-recovery/ACTUAL_UUID/manifest.json
```

This separately stores the **post-deployment intended configuration** as
root-only SHA256-bound files. It does NOT attest that the application,
guest boots, Internet/INetSim isolation or snapshots actually work.
Do not reseal after unreviewed changes or treat the receipt as proof of
ownership of package/VM/network modifications.

## Repair: check and fix only missing sealed config files

Read-only plan:

```bash
sudo python3 -B scripts/command123_repair_rollback.py \
  --mode plan-repair --approved-host "$(hostname -s)" \
  --receipt /var/lib/cape-deployment-recovery/ACTUAL_UUID/manifest.json
```

`--mode repair` performs the matching explicitly approved repair.
It may recreate ONLY a completely MISSING sealed CAPE configuration file
from verified private bytes, with original owner and mode. It refuses
overwriting a file whose bytes or ownership differ, refuses changed
receipts, and requires CAPE/Suricata stopped and **no libvirt guest
running**. Services are NEVER auto-restarted. It does not repair
Windows guest boot, DHCP/static-IP mismatches, VM disks, service
dependencies, apt packages, firewall policy or TPM snapshots.

## Rollback: restore the baseline for tracked CAPE configs ONLY

Read-only plan:

```bash
sudo python3 -B scripts/command123_repair_rollback.py \
  --mode plan-rollback --approved-host "$(hostname -s)" \
  --receipt /var/lib/cape-deployment-recovery/ACTUAL_UUID/manifest.json
```

`--mode rollback` requires another exact typed approval, all five
CAPE/Suricata units stopped and no running guest. It only changes
**exactly the six tracked CAPE configuration files** when their current
bytes/metadata still match the sealed values. Pre-existing files are
restored to their original root-private copies. New, sealed files absent
before deployment are **moved to private `quarantine/`** under the
recovery folder, never unlinked. Unknown changes force a STOP. A partial
step failure leaves a durable `partial` receipt and blocks blind
automatic re-execution. The operator must inspect private state.

**Deployment-wide rollback is NOT YET provided by this subcommand.**
The intended feature is to undo just this deployment's changes across
packages, CAPE files/services, new VM disks/UEFI/TPM, and dedicated network
resources, restoring the affected *pre-deployment* values while preserving
all unrelated original state. That functionality requires an exact
transaction journal that all three deployment commands must populate.
Until it is implemented and tested, do not remove VMs, packages or network
objects from before/after inventory differences alone. A full-system image
is optional insurance for tomorrow's controlled test, not the rollback goal.
See [contract](DEPLOYMENT_SCOPED_REPAIR_ROLLBACK_CONTRACT.md).

## One consolidated non-mutating post-test report

```bash
python3 -B scripts/command123_repair_doctor.py \
  --approved-host "$(hostname -s)" \
  --additional-count 3 \
  --storage-dir /var/lib/libvirt/images \
  > "$HOME/CAPE_NewHost_PostTestDoctor.json"
```

Use the actual **additional clone count**, 0–16. Read the reported
`blockers` instead of assuming failed stages succeeded. Snapshot names
are only listed as metadata; they are not a TPM-revert acceptance witness.
The doctor does not touch hypervisor, samples, personal Google OAuth,
crypt passwords, rooter/firewall or Windows state.

## Escalation/stop criteria

* Refuse to install or repair on SSL55/SSL46.
* If a new machine cannot authenticate to private Drive, stop and check
  the restricted service-account Viewer folder grant and **matching**
  rclone crypt password/salt; never publish the backup.
* If an installer fails or produces `PARTIAL_OR_UNKNOWN`, preserve
  diagnostics and existing files and request review before retry.
* If an existing Windows VM or TPM state differs from expectation, stop.
  The recovery tool does not change VM state and does not invent evidence
  that a running RAM snapshot safely restores swtpm persistent state.
* Until the deployment-specific resource-ownership journal and
  guarded undo are implemented, STOP at an explicit review for packages,
  services, network and VM removal. Do not guess ownership from names.
  An optional existing test-host image can be used for emergency recovery,
  but no universal wipe or OS reinstall is the user's desired rollback.

## Validation evidence

The repository-wide GitHub Actions job
`repository-wide-preflight.yml` parses tracked Python, Bash, PowerShell,
YAML, docs and runs recovery/cloud tests in Python 3.10 and 3.12.
`three-command-integrated-offline.yml` additionally runs the full
existing synthetic Python regression suite. Neither workflow proves
physical Windows/TPM restore, network containment or a portable host
installation. A new-host trial is mandatory before claiming readiness.

## 2026-10-17 read-only doctor corrections

`scripts/command123_repair_doctor.py` now recognizes both Ubuntu 24.04 and
26.04 as candidate host families. This is **not** full release approval:
the official 26.04 virtualization package candidates passed separate
disposable experiments, but the real Windows/TPM recovery contract remains
independently unverified.

The doctor now reads `virsh version --daemon` and applies the existing
QEMU >= 9 / libvirt >= 10.10 experimental snapshot floor, reporting a
specific blocker if versions are unavailable or too old. It checks the
complete *defined* libvirt inventory (including third-party VMs) for
exact `shut off` state, rejects unstable repeated inventories, and never
starts, changes, reverts or undefines a VM. Other incomplete CAPE install,
network and TPM rollback gates remain unchanged.
