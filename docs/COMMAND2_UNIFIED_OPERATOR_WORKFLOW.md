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
| `identity-build` | One SHA-verified, UUID-bound per-guest read-only optical configuration ISO | Windows SYSTEM startup bootstrap must be installed beforehand. |
| `identity-attach` | Inserts the ISO into exactly one previously empty CD-ROM on a shut-off zero-NIC clone | Operator separately boots guest to perform hostname personalization and verifies identity; no automatic guest start. |
| `nic-attach` | Adds exactly one isolated network NIC in saved XML, after root-private network acceptance receipt | The real packet-isolation/reboot evidence is operator-witnessed; the receipt cannot be invented by the software. |
| `network-approve` | A second ISO containing host-approved NIC/network JSON+hash replaces the first media in saved guest XML | Separate Windows boot needed to apply unique static IPv4 and prove agent/network, no gateway. |
| `cold-capture`, `cold-verify` | Full disk + OVMF + swtpm backup while guest shut off, SHA-256 checks | Snapshot-only copy is insufficient; real cold restore needs a separate gate. |
| `cold-restore` | High-risk actual disposable-host cold restore, separate typed approval and restore-risk acknowledgement | Never on SSL55. Operator boots, verifies agent + TPM + UEFI and records real restore evidence. |
| `firmware-sidecar` | Copies existing RAW pflash NVRAM into a separate, checked QCOW2 sidecar | Guest SHUT OFF, existing full cold backup SHA pinned. Original RAW unchanged. |
| `firmware-activate` | Saved-only XML transition to QCOW2 sidecar with exclusive backup of original XML | Requires separate actual full disk/OVMF/swtpm restore witness. Boot/TPM/Secure Boot/BitLocker must be rechecked. |
| `snapshot-capture` | Explicit, one-VM running internal disk+RAM snapshot attempt after full cold-backup and stack checks | Actual TPM/OVMF rollback is NOT established by successful snapshot creation. |
| `snapshot-revert-once` | One **destructive but explicitly approved disposable-host** `virsh snapshot-revert` back into RUNNING saved RAM/disk state; requires exact shut-off VM UUID, hashed full cold bundle, present QCOW2 OVMF, live libvirt/nft isolation and typed per-VM consent | **No** automatic guest shutdown or retry, **no** TPM/UEFI proof from the host alone; repeat with separate approval after off-guest Windows/TPM baseline comparison and clean shutdown. |
| `snapshot-batch` | Checks all recorded `cape_ready_win11_N` snapshots captured while RUNNING, with each VM SHUT OFF for CAPE and two real witnessed benign revert cycles | Read-only gate; does NOT perform the revert tests or prove witness cryptographically. |
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
