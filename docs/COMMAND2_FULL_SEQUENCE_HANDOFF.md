# Command 2 — ONE guarded count-driven exact-master sequence (development)

**Implemented:** `scripts/command2_exact_master_full_sequence.py`

This is an interactive batch orchestrator over existing, independently
guarded and reviewed steps, not permission to run malware or an attested
TPM-consistent snapshot restore. No operations were run on SSL-55 or an
actual second machine.

## User interaction

- Invoked once on an approved OTHER host, the tool asks **How many
  ADDITIONAL Windows VMs? (1-16)** unless --count is supplied.
- The master `win11` is **not counted**; e.g. count 3 creates requests
  for `win11_1`, `win11_2`, `win11_3` in addition to `win11`.
- `--mode plan` runs the existing complete verified private exact
  Windows bundle cold-clone resource/identity plan **read-only**.
- `--mode run` requires root, a direct terminal, the master-vm
  bundle, target output directories and operator approval. Then:
  1. Call verified exact-cold-master count-driven wizard for all N
     independent Windows QCOW2 disks, UEFI variables, UUID/MAC/TPM
     identities, permanent DHCP reservations and trusted per-VM ISO.
  2. Convert each clone's OFFLINE firmware VARS to standalone QCOW2
     to support later native RAM+OS+UEFI snapshot capture.
  3. For EACH `win11_N` sequentially: boot paused and verify identity
     before resuming; stage the pinned benign Windows identity/DHCP
     script with CAPE Agent and checksum-bound ISO settings; request
     execution; independently collect actual Windows hostname, DHCP,
     IP, DNS, gateway, HTTPS and agent evidence.
  4. Validate every cloned guest's live Agent/NAT network.
  5. Capture each guest's running RAM/OS/UEFI internal snapshot
     candidate, with EXACT per-guest name `cape_one_nat_win11_N`.
  6. Gracefully shut off all captured guests (each snapshot remains
     recorded as a RUNNING-state checkpoint).
- The original `win11` master and trial domain are never edited,
  started, reset, reverted or copied as shared TPM instances.
- Before EVERY mutation the helper has its own checks and typed
  approval. The controller never skips them.
- A root-private receipt tracks the exact stage, VM, completed
  activities and failures. A failed guest step returns
  PARTIAL_OR_UNKNOWN and **stops without retry, forced shutdown or
  deleting any prior guests/media/snapshots**.
- Executing a benign Windows network/hostname script is not proof
  that Windows applied/rebooted correctly. The next independent
  verification is mandatory. If the first boot fails on BitLocker or
  hardware compatibility, the controller stops; it does not
  automatically decrypt, reinstall Windows or duplicate TPM secrets.

## CLI template for FUTURE approved other host

The already downloaded SHA256-verified master bundle and imported
offline master must exist, and the named output directories and
root-private evidence directory must already be provisioned. These are
templates, not SSL-55 commands:

```bash
sudo python3 scripts/command2_exact_master_full_sequence.py \
  --mode plan \
  --approved-host YOUR_NEW_HOST \
  --bundle /ROOT_PRIVATE/cape-master-YOUR_ID \
  --disk-dir /APPROVED_VM_STORAGE \
  --nvram-dir /APPROVED_UEFI_STORAGE \
  --journal-dir /ROOT_PRIVATE/command2-journal \
  --iso-dir /ROOT_PRIVATE/command2-nat-media \
  --evidence-dir /ROOT_PRIVATE/command2-evidence
```

For actual provisioning change `--mode plan` to `--mode run`.
It asks the additional VM count; use `--count 3` to explicitly fix
the value and skip only the count prompt. You will still approve
each host and guest mutation.

## Unresolved items that MUST NOT be called finished

1. The exact Windows golden master, including its original Windows
   apps/registry and UEFI/TPM, has not yet physically booted on the
   new host. A BitLocker-protected Windows OS volume can refuse
   independent-clone startup without an approved cleartext/decrypted
   clone source. **Never copy the original TPM identity into all
   clones** to bypass that.
2. Libvirt's internal running RAM/OS/UEFI snapshot does **not**
   atomically snapshot swtpm2's external persistent/volatile files.
   These are experimental snapshot candidates; a supported TPM-state
   lifecycle adapter and at least two benign reboot/revert/attestation
   cycles are needed before treating them as stable CAPE rollback.
3. The exported cold master bundle contains the OS, UEFI and TPM
   bytes, but flattening QCOW2 loses the original libvirt
   `Afterfull` running snapshot metadata. On a NEW machine, the
   master must be booted/independently checked and an approved,
   separately named RUNNING snapshot created and verified before
   Command3's `kvm.conf` master-registration guard can accept it.
4. CAPE host package installer/INetSim installation, Command3 routing
   release and service orchestration still require completion and
   real-host evidence.
5. The per-VM Windows guest execution helpers are intentionally not
   an unattended malware-testing feature; a hardware, Windows
   behavior, Agent and NAT variation may cause an early controlled
   stop on the disposable test host. The generated private receipt
   is then needed for precise next steps, not a blind rerun.
6. Code-mock/offline green CI verifies ordering, guard enforcement
   and errors, NOT ability to boot a real Windows VM, restore TPM,
   or process concurrent CAPE tasks.

The approved new-host plan/receipt makes this an integrated developer
stage. The physically demonstrated fully unattended three-command
release does **not** exist yet.
