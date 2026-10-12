# Command 2 unified portable operator workflow — development handoff

**Status: development implementation; no second host, TPM snapshot, or
parallel-analysis production acceptance yet.** Do not confuse the presence
of an entrypoint with proof that two Windows machines are ready.

Main operator entrypoint:
`scripts/command2_portable_workflow.py`

Use `--phase PHASE --mode plan` to inspect the intended single guarded
operation (default, read-only). Use `--mode apply` ONLY after the relevant
independent evidence exists. Every host-mutating helper will require a
direct interactive TTY and its own typed approval; the front-end never
prompts for one approval covering all risky steps. Child helpers execute
through Python's direct argv list, **never shell=True**, and individually
revalidate libvirt, UUIDs, paths, networking and storage.

## Supported phases and order

| Phase | What is actually done | Independent acceptance still required |
| --- | --- | --- |
| `stage` | Count-driven 1..16 shut-off zero-NIC clones and per-guest reserved JSON | On a supported other Ubuntu/KVM host only; prerequisite Command 1 master+bootstrap. Initial clone firmware RAW. |
| `network-install` | New dedicated `inet cape_analysis_cmd2_guard` nft rules and persistent libvirt `cape-analysis-isolated` network; start network, **autostart OFF** | Actual reboot persistence, IPv4+IPv6 packet negatives, peer L2 and host/CAPE/INetSim positive traffic NOT proven; no guest NICs attached. |
| `guard-persistence` | Create-only root-pinned nft policy + independent CAPE-only systemd replay unit, **enable without starting** | Requires already active, checked network+nft policy, zero running/autostart guests, existing nftables.service disabled/inactive, and typed approval. Physical reboot persistence still NOT proved. |
| `identity-batch` | NEW: one count-driven, all-guest zero-NIC identity ISO preflight, followed in apply mode by ordered per-VM identity ISO build + attach using existing safeguards | All VMs must be SHUT OFF and zero-NIC; each actual step keeps independent typed approval; **does not** install Windows task, boot Windows, set IP, attach NIC, snapshot, or complete Command 2. If any step fails, retain artifacts and stop without blind retry. |
| `identity-build` | One SHA-verified, UUID-bound per-guest read-only optical configuration ISO | Windows SYSTEM startup bootstrap must be installed beforehand. |
| `identity-attach` | Inserts the ISO into exactly one previously empty CD-ROM on a shut-off zero-NIC clone | Operator separately boots guest to perform hostname personalization and verifies identity; no automatic guest start. |
| `approved-firstboot` | NEW: one specifically approved Windows firstboot with an **already-attached** isolated NIC and V2 receipt verifying the trusted source-master SYSTEM task; checks exact disk/UEFI/swtpm/ISO and live paused guest NIC before resume | Does not claim Windows rename, static IPv4, CAPE Agent readiness, or snapshots; default is no-write plan and apply requires per-guest approval. |
| `approved-firstboot-batch` | NEW: count-driven read-only all-N verified one-NIC preflight with per-VM private V2 receipts, aggregate RAM capacity check, then ordered individually authorized first boots | No physical real-host acceptance yet. Stops on any failure without cleaning/starting other guests. Source Windows bootstrap must be independently confirmed, network containment physically proven, and post-Windows proofs remain. |
| `graceful-shutdown` | NEW: exact VM-bound Windows shutdown through an existing live QEMU Guest Agent channel if approved, then bounded ACPI fallback; waits for actual libvirt `shut off` before success | No forced poweroff/reset; never trusts `Domain is being shutdown`; fails if Windows does not respond. `plan` is read-only. |
| `graceful-shutdown-batch` | NEW: all-N reservation-bound read-only preflight, then sequentially approved shutdown requests with actual stop-state confirmation | Stops on the first timed-out/failed guest; never force stops remaining guests or claims cold-state readiness prematurely. |
| `identity-boot-batch` | NEW: one count-driven **all-VM** preflight of already attached zero-NIC identity media, then orderly guarded per-VM paused boots with separate typed approval | Stops on first error and preserves any running/paused guest; does NOT verify Windows rename, shut down guests, attach NICs, assign IPs or create snapshots. Requires adequate RAM for each actual boot. |
| `identity-boot` | NEW: explicit separate-host **one-VM** zero-NIC first Windows boot, starting PAUSED, checking live clone disk/UEFI/TPM/CD-ROM and no NIC/passthrough, then resuming | Requires the source golden Windows SYSTEM startup task already installed and reviewed. May trigger Windows hostname rename/reboot but cannot independently attest it. The guest must be safely shut off and its changed identity verified before later NIC phases. Never starts SSL-55's clone. |
| `nic-attach` | Adds exactly one isolated network NIC in saved XML, after root-private network acceptance receipt | The real packet-isolation/reboot evidence is operator-witnessed; the receipt cannot be invented by the software. |
| `network-approve` | A second ISO containing host-approved NIC/network JSON+hash replaces the first media in saved guest XML | Separate Windows boot needed to apply unique static IPv4 and prove agent/network, no gateway. |
| `cold-capture`, `cold-verify` | Full disk + OVMF + swtpm backup while guest shut off, SHA-256 checks | Snapshot-only copy is insufficient; real cold restore needs a separate gate. |
| `cold-restore` | High-risk actual disposable-host cold restore, separate typed approval and restore-risk acknowledgement | Never on SSL55. Operator boots, verifies agent + TPM + UEFI and records real restore evidence. |
| `firmware-sidecar` | Copies existing RAW pflash NVRAM into a separate, checked QCOW2 sidecar | Guest SHUT OFF, existing full cold backup SHA pinned. Original RAW unchanged. |
| `firmware-activate` | Saved-only XML transition to QCOW2 sidecar with exclusive backup of original XML | Requires separate actual full disk/OVMF/swtpm restore witness. Boot/TPM/Secure Boot/BitLocker must be rechecked. |
| `snapshot-capture-batch` | NEW: approved OTHER-host all-N preflight against **per-VM pinned full stopped-state cold recovery**, exact Windows/host acceptance receipts, running Agent/VM identity, QCOW2 OVMF, native snapshot version, aggregate RAM/storage reserve; then sequential separately typed-approved live RAM+disk capture | An experimental capture, **not** TPM/UEFI rollback proof, not SSL-55, not final CAPE registration. Stops on first failed child; no rollback/auto retry. |
| `snapshot-capture` | Explicit, one-VM running internal disk+RAM snapshot attempt after full cold-backup and stack checks | Actual TPM/OVMF rollback is NOT established by successful snapshot creation. |
| `snapshot-revert-once` | One **destructive but explicitly approved disposable-host** `virsh snapshot-revert` back into RUNNING saved RAM/disk state; requires exact shut-off VM UUID, hashed full cold bundle, present QCOW2 OVMF, live libvirt/nft isolation and typed per-VM consent | **No** automatic guest shutdown or retry, **no** TPM/UEFI proof from the host alone; repeat with separate approval after off-guest Windows/TPM baseline comparison and clean shutdown. |
| `snapshot-batch` | Checks all recorded `cape_ready_win11_N` snapshots captured while RUNNING, with each VM SHUT OFF for CAPE and two real witnessed benign revert cycles | Read-only gate; does NOT perform the revert tests or prove witness cryptographically. |
| `agent-batch` | NEW: a **read-only** N-guest live CAPE HTTP/8000 admin reachability check against reserved guest IPv4, exact MAC, isolated NIC in both saved and running XML and host network policy | Any guest probe failure prevents all-N success. This is not a Windows hostname/IP or TPM snapshot witness and cannot certify analysis readiness. |
| `cape-register` | Propose or explicitly write backed-up `kvm.conf` with one UNIQUE snapshot per VM, only if the batch snapshot gate passes | Neither CAPE service restart nor two real parallel benign jobs is automated/accepted yet. |

## First command on a suitable, prepared separate host

Use a checked-out copy of `development`, from a reviewed pinned Git
commit. Do not fetch a moving `development` branch automatically from a
privileged installation script.

```bash
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase stage --mode plan \
  --approved-host "$(hostname -s | tr '[:upper:]' '[:lower:]')" \
  --count 2 --disk-dir /var/lib/libvirt/images/cape-clones-staging \
  --nvram-dir /var/lib/libvirt/qemu/nvram \
  --template /path/to/canonical-flat-master.qcow2 \
  --template-sha256 "REVIEWED_64_HEX_SHA256" \
  --journal-dir /var/lib/libvirt/images/cape-command2-private-journal
```

The above command **cannot succeed with the placeholder template/hash**;
it is an example of the expected interface. Wait until the Command 1
master, scripts, file paths, available RAM/disk and machine inventory are
present and independently reviewed. Default `--subnet auto` uses host
route, IPv4 address and libvirt network collision inventories; after
staging, all later phases derive the subnet from immutable per-VM config.

The isolated network installer creates a *new*, dedicated nft table
and persistent libvirt network on the second host **only with explicit
per-host approval**, without modifying existing Docker/campus firewall
objects or enabling guest NICs. The separate `guard-persistence` phase
creates a pinned CAPE-only replay helper, policy, and systemd unit and
enables (never starts) it. It does not change `/etc/nftables.conf`,
modify `nftables.service`, enable libvirt network or guest autostart,
or reboot the host. Until **the actual reboot and IPv4/IPv6/L2
packet-path tests pass**, NIC-attachment receipts must not be signed.

The existing real SSL55 base VM is **not** a supported target for this
portable entrypoint. Never run `--mode apply` there.

## Count-driven Windows identity optical phase (new, NOT complete Command 2)

After the separate-host `stage` phase has successfully reserved and created
all N shut-off zero-NIC Windows clones, the operator need not type two
different script commands for every VM merely to prepare their identity media.

```bash
# Read-only admission/preflight for ALL exact journal-reserved clones.
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase identity-batch --mode plan \
  --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json

# Requires an interactive TTY, all-N guest preflight and per-VM typed
# approvals. Builds and attaches ONLY identity ISOs to shut-off zero-NIC VMs.
# sudo python3 -B scripts/command2_portable_workflow.py \
#   --phase identity-batch --mode apply \
#   --approved-host OTHERHOST \
#   --journal /absolute/private/command2-identity-reservation.json
```

This is a sequential, fail-closed development bridge to the future **single
Command 2 clone-and-configure operation**. The parent snapshots the existing
journal digest and checks it before each child step. A failure stops before
the next VM or phase; previously written ISOs or VM config changes are
never automatically removed or overwritten. The parent does not bypass
per-VM typed approvals, install the Command 1 Windows SYSTEM bootstrap,
power on guests, assign static IPs, validate external/lateral isolation,
perform TPM-consistent running snapshots, or register CAPE. The
source Windows master must have been prepared beforehand.

**Do not run apply on SSL-55.** This code is offline CI tested only. No
separate-host physical deployment or end-to-end Windows integration is certified.

## Count-driven first zero-NIC boot bridge

The new `--phase identity-boot-batch` accepts the SAME private N-clone
reservation already used by `identity-batch`. It checks that **every**
Windows VM is an independent, shut-off zero-NIC guest with its exact
previously attached identity media BEFORE it attempts to start any.
`--mode plan` is read-only. On `--mode apply` each VM starts through
the individually protected paused-boot helper, requiring its own typed
approval, and the parent stops immediately on failure (without force
shutdown or retry). The guest's static IPv4 is **not** yet set.

```bash
# Other prepared/approved host ONLY: read-only preflight of N ready clones
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase identity-boot-batch --mode plan \
  --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json
```

Do not run `apply` on SSL-55. This is NOT unattended two-command
completion: Windows guest identity must be independently verified, each
guest later safely shut off and pass network isolation before NIC
attachment. No real physical N-clone Windows boots are yet accepted.

## Alternative direct first boot with already isolated NIC (one boot, no intervening shutdown)

The old identity-only path required a zero-NIC Windows first boot/hostname
rename, clean guest shutdown, NIC attachment, new ISO, then another Windows
boot to apply the static IP. This was an unnecessary **manual intermediate
boot** for the user's desired two-command installation. Development now
also supports a separately guarded, firstboot-with-NIC path:

1. The Command1 Windows source must actually contain the reviewed,
   SHA-256-pinned SYSTEM startup task and the matching guest personalization
   script before the template was captured; software existence alone does
   **not** prove the Windows task has been installed.
2. Physical isolated-network IPv4/IPv6 negative traffic, peer L2 rejection,
   host-to-guest positive path (which may use separate benign probes),
   reboot persistence, and preservation of unrelated host rules are mandatory
   before making the firstboot-V2 receipt. The existing production isolation
   gate is not bypassed. A V2 receipt is for the exact host/clone UUID,
   NIC MAC, reserved IPv4 and the actual source-master libvirt UUID; the
   human must record the SHA-256 pins of both reviewed Windows scripts,
   attest the master is shut off, and **explicitly record that the Windows
   identity has NOT yet been verified**.
3. Existing media and isolated-NIC setup stages can attach one approved
   interface and replace the identity-only optical ISO with the
   `CAPE_CMD2` host-approved optical config while the guest is SHUT OFF.
   `approved-firstboot` validates those **real saved objects**, current
   isolated libvirt/nft readback, master identity, host RAM and independent
   disk/OVMF/TPM. Only after per-VM typed authorization does it issue
   `virsh start --paused`, reject unsafe live devices, and resume.
4. Windows SYSTEM startup task validates the approved optical hash/UUID/MAC
   and host-approved proof. If the Windows hostname differs, it invokes
   *Identity* in approved one-NIC mode, refuses any existing IPv4/IPv6
   default route, then requests restart. On the next successful startup it
   can apply/verify the unique static IPv4 **without a gateway**. Host code
   **does not** claim the actual Windows rename/reboot/static-IP succeeded:
   proper guest and CAPE Agent measurements remain mandatory.

There is an ordered all-VM bridge for this path:

```bash
# READ-ONLY and for a fully prepared, approved OTHER host only.
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase approved-firstboot-batch --mode plan \
  --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json \
  --network-receipt-dir /absolute/private/receipt-directory
```

Every private V2 receipt MUST be named
`win11_N.firstboot-network-receipt.json` and pass the real VM-bound
bootstrap, master, and network gates; the all-N memory requirement is
checked BEFORE any guest boot. `--mode apply` still requires direct
operator TTY and a separate per-guest approval and **is not** a completed
unattended production Command 2. Do NOT synthesize receipt booleans.
No real other-host guest or SSL-55 VM has been booted by this change.

## Count-driven running snapshot capture bridge (EXPERIMENTAL only)

After every Windows clone has independently passed the network, static-IP,
agent and cold-backup gates **and** has been reconfigured offline with a
QCOW2 OVMF sidecar, the new `snapshot-capture-batch` may plan all N
snapshot captures from one parent invocation. It never treats RAW OVMF or
a standalone running snapshot as proof of TPM rollback.

Each root-private `--snapshot-evidence-dir` contains
`snapshot-recovery-index.json` (0600; canonical format
`COMMAND2_RUNNING_SNAPSHOT_BUNDLE_INDEX_V1`, exact host, guest_count,
and one `entries` object per VM with *only* `manifest_sha256`), plus
one root-private per-VM folder `win11_N/`. Each guest folder contains
`cold/command2-cold-bundle.json` and associated unchanged full-state
disk/UEFI/swtpm files, and an exact
`snapshot-acceptance.json` private acceptance receipt. No automatic
witness fabrication is permitted. Actual cold restoration, TPM handling
and network acceptance must already have been independently reviewed.

Example index *shape only* (SHA placeholder is NOT valid operator proof):
```json
{
  "format":"COMMAND2_RUNNING_SNAPSHOT_BUNDLE_INDEX_V1",
  "host":"approved-lab",
  "guest_count":2,
  "entries":{
    "win11_1":{"manifest_sha256":"<64-HEX-REVIEWED-HASH-1>"},
    "win11_2":{"manifest_sha256":"<64-HEX-REVIEWED-HASH-2>"}
  }
}
```

```bash
# Other-host ONLY; read-only plan with all-N backup rehashing:
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase snapshot-capture-batch --mode plan \
  --approved-host approved-lab \
  --journal /absolute/private/command2-identity-reservation.json \
  --snapshot-evidence-dir /absolute/private/snapshot-evidence
```

The matching `--mode apply` has an interactive, separately guarded
approval for EVERY VM and preserves any partial snapshot for review.
After successful capture, repeated **benign** full-state snapshot reverts,
TPM/OVMF/Secure Boot/BitLocker/Agent and IPv4/IPv6/L2 checks, final
shutoff and CAPE machine registration are STILL REQUIRED. This is not
the final two-command installer and has not run on physical lab VMs.

## Verified Windows guest graceful shutdown (2026-10-12 fix)

The SSL-55 operator observed that `virsh shutdown win11_1` printed
`Domain 'win11_1' is being shutdown` while Windows stayed on until
manually stopped. Libvirt documents that this response only acknowledges a
request; Windows can ignore the virtual ACPI power button. Simply polling
more often cannot make the guest comply.

`scripts/command2_graceful_shutdown.py` adds a **real state-verified**
host-side helper. For a matching reserved clone it requires the exact VM
UUID, disk, OVMF state, isolated NIC, and swtpm2. On SSL-55 it is scoped
to `--scope ssl55-clone --vm win11_1` and protects the source master
and trial. On a separate host the matching canonical journal must be
given with `--scope portable-other`. `--mode plan` is read-only,
including an already-stopped VM. With explicit operator authorization,
`--mode shutdown` first uses a supported live virtio QEMU guest-agent
channel **if one already exists**. If that request fails or Windows
does not stop promptly, it sends **one** ACPI graceful power-button
event and waits up to the bounded deadline for actual `shut off`.
Failure is **blocking**; it never uses `virsh destroy`, `reset`,
arbitrary Windows process execution, or a hard-off fallback.

The protected SSL-55 source/master was NOT modified during coding.
The separate Windows source template's `command2_guest_startup_autoconfig.ps1`
now configures Microsoft `PBUTTONACTION`=3 (AC-power button invokes
Windows **Shut Down**) *only during an explicitly approved Install* with
exact source UUID and reviewed script hashes, then verifies it.
`-Mode Verify` checks the policy without modifying it. The Windows
OS/guest-agent must still actually execute successfully; source code
and CI cannot guarantee the OS will respond to ACPI. Since earlier
clones exclude arbitrary host-connected channels, do not claim QGA is
present on SSL-55 merely because agent fallback is implemented.

```bash
# Read-only plan; protected SSL55 exact guest. It is already off now.
sudo python3 -B scripts/command2_graceful_shutdown.py \
  --mode plan --scope ssl55-clone \
  --approved-host cse-ssl-55 --vm win11_1

# On an approved OTHER host, read-only all-N preflight:
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase graceful-shutdown-batch --mode plan \
  --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json
```

No need to invoke the shutdown helper on the currently stopped SSL-55
`win11_1`. The next pending SSL-55 action is the separately guarded
OFFLINE OVMF QCOW2 XML transition, **not** another shutdown. A snapshot
or consistent swtpm rollback has NOT been performed.

## All-N benign CAPE Agent reachability gate

After the separately approved one-NIC firstboot phase and the Windows
bootstrap's internal rename/reboot/static-IP process, the host can verify
that **every** reserved Windows agent responds on its unique RFC1918 IPv4.
A single command checks the exact reservation, one isolated NIC/MAC in
saved and running XML, same reserved guest storage, active host nft/libvirt
containment, a shut-off Windows source master, and each CAPE Agent's
read-only administrator HTTP response. One failure makes the total FAIL.

```bash
# On a prepared separate other host ONLY. No guest or network changes.
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase agent-batch --mode plan \
  --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json
```

This audit **does not** prove the Windows static IPv4 was assigned rather
than leased, Windows hostname, IPv6 guest isolation, TPM/OVMF full-state
rollback, completed running snapshots or two concurrent CAPE analyses.
Those remain independent release gates; no other host was actually
tested by this addition.

## Guarded first zero-NIC identity boot

After the successful `identity-batch --mode apply` and separate approval
that the Windows template already contains the exact pinned SYSTEM startup
task, the saved-off clone's identity ISO may be used to initialize its
Windows hostname. The development helper checks the exact journal UUID,
independent disk/OVMF, SHA-matched mounted ISO, zero external NICs, protected
`win11` source shut-off, free RAM and no existing snapshots before touching
the VM. It uses `virsh start --paused`, reads the live domain device graph,
and only then resumes the clone. If the paused device check fails, it
**leaves the VM paused** for operator review; no forced shutdown/retry.

```bash
# Plan only, on a separate already prepared Ubuntu/KVM host:
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase identity-boot --mode plan \
  --approved-host OTHERHOST --vm win11_1 \
  --journal /absolute/private/command2-identity-reservation.json
```

The corresponding `--mode apply` would require a separate exact typed
approval, not a silent bulk start. **No such real guest boot has been
performed** by this code or the CI tests. Host observation alone cannot
prove the Windows startup task ran, that the identity is correct or that
Windows safely completed its restart; those remain mandatory acceptance
steps before any guest NIC attachment, host isolation approval, IP change,
CAPE memory snapshot or N-machine registration.

## Per-guest example once a signed reservation is present

These are **examples**, not ready-to-run instructions without the
complete second-host acceptance receipts and physical prerequisites.

```bash
sudo python3 -B scripts/command2_portable_workflow.py \
  --phase identity-build --mode plan \
  --approved-host OTHERHOST --vm win11_1 \
  --journal /absolute/private/command2-identity-reservation.json

sudo python3 -B scripts/command2_portable_workflow.py \
  --phase firmware-sidecar --mode plan \
  --approved-host OTHERHOST --vm win11_1 \
  --journal /absolute/private/command2-identity-reservation.json \
  --recovery-bundle /absolute/complete-cold-bundle \
  --manifest-sha256 REVIEWED_SHA256

sudo python3 -B scripts/command2_portable_workflow.py \
  --phase snapshot-batch --mode plan --approved-host OTHERHOST \
  --journal /absolute/private/command2-identity-reservation.json \
  --witness-dir /absolute/private/revert-witnesses
```

## Why applying every phase consecutively would fail (correctly)

A successful count stage intentionally creates **zero NICs** and no
running guests. Windows personalization requires a trusted SYSTEM
bootstrap in the source master and a separately permitted boot after
the first ISO. Attaching a NIC requires genuine host isolation
acceptance, including reboot persistence, not just the existence of
an nft rule. Snapshot capture requires an earlier complete stopped
backup, proven restoration, QCOW2 firmware and an explicit guest
agent + network acceptance receipt. CAPE KVM's normal machinery
expects the guest **shut off** when it starts analysis and then
reverts to the separately captured **running** memory/disk snapshot.

These gates are deliberately non-automatic until actual Windows,
TPM, UEFI and guest-to-guest negative tests pass. An operator
cannot safely replace them with JSON files full of `true` values
without performing the physical tests.

## Remaining engineering before Command 2 production release

1. Install+prove the trusted Windows SYSTEM task in the Command 1
   source master and verify the identity/bootstrap flow on both clones.
2. Physically verify the new guard replay unit after a real reboot;
   independently validate actual guest IPv4+IPv6 and peer-L2 negative
   probes, and CAPE/INetSim positive service paths.
3. Real cold restore followed by OVMF+TPM reboot tests; standard
   libvirt running snapshot behavior with swtpm state must be
   empirically proven or replaced by a properly engineered custom
   CAPE machinery full-state reset adapter.
4. Two concurrent harmless CAPE analyses, each with repeated
   *complete* state reverts and unique guest mapping.
5. End-to-end target-host interruption, reserve and reboot tests.
   Offline GitHub CI is not this physical acceptance.

**Current real SSL55 decision:** libvirt 11.1.0; QEMU 9.2.2;
`win11_1` RUNNING and standing cold backup, RAW OVMF NVRAM and swtpm2,
no snapshot, 64.74 GiB free and 40 GiB reserve. Preserve VM, backups,
master and trial. No malware and no blind attempts to snapshot/revert.
