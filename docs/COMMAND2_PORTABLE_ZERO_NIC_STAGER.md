# Command 2 — guarded portable ZERO-NIC stager (development)

**DANGEROUS IF MISUSED ON A PRODUCTION HOST: it can allocate 64-GiB
virtual disks and persist new libvirt VM definitions.**
**NEVER run it on SSL-55. Do not stage on any host without written
authorization, adequate dedicated capacity, and a verified Command 1
Windows source template.** The module refuses SSL-55 by hostname, but
hostname checks alone are NOT strong hardware attestation.

Code:
- scripts/command2_portable_zero_nic_stager.py
- scripts/test_command2_portable_zero_nic_stager.py

## Scope of this milestone

Unlike earlier pure XML/planning models, **--mode stage can perform
real host modifications on a separate approved machine**. It stages
exactly the count from an existing, root-private, atomically recorded
identity reservation. Every guest:
- Gets an independent QCOW2 copy made from a *verified, standalone,
  cold, plaintext* Command 1 Windows template (never original BitLocker
  master snapshots), with qemu-img structural checks and NTFS probe.
- Gets an independent copy of the reviewed master OVMF VARS; never a
  copy of the master TPM state. A unique emulator TPM backend is
  defined and will create fresh state on later approved guest boot.
- Gets a distinct libvirt UUID, Windows generation ID, planned MAC and
  future Windows hostname/IPv4, and independent VM disk/NVRAM paths.
- Is defined persistently but remains **SHUT OFF WITH ZERO NICs**.
  It never boots, executes a sample, or changes host firewall/network
  rules. The MAC/IP/hostname are only **reserved** until a separately
  verified personalization and network stage.
- Retains any partial clone images/NVRAM/domain/intent files on error,
  never deletes/retries them blindly.

Prior to ANY file or VM action the engine requires:
1. Exact explicitly approved non-SSL-55 host, root privilege for stage,
   private root-owned mode-0700 journal directory and mode-0600 reserved
   manifest. It checks clone UUIDs, names, MAC, IP, UEFI and disk paths.
2. A **fresh read-only host discovery** using the target preflight
   module (KVM, resources, flat template metadata, CIDR overlaps,
   source master shut-off, tools and libvirt names). Refuses any blocked
   condition, mismatched reservation or resource count.
3. Exact master libvirt UUID/power state, domain XML and independently
   reviewed source template SHA-256, source QCOW2 info, plaintext
   volume probe, exact OVMF NVRAM state, root-private files, and safe
   artifact directories.
4. Conservative available capacity of at least
   **N * 64 GiB + 40 GiB** before group staging and at least
   **64 + 40 GiB** before each clone, leaving 40 GiB reserve.
5. No existing duplicate domain, UUID, MAC, disk or NVRAM path.
6. Explicit interactive phrase before stage, a root-private exclusive
   lock, then a **second live host preflight and collision check**.
7. An fsync'd O_EXCL per-VM intent BEFORE conversion. A crash or error
   leaves the intent; the next invocation refuses automatic retry.
   A separate completion note is published only after libvirt readback
   verifies shut-off, exact UUID/genid, independent paths, TPM emulator
   and no NIC. Missing/partial artifacts require manual forensic review.

## Not operationally approved

The complete two-command workflow is **NOT ready**. This is a
development-stage privileged engine with offline mocked safety tests,
not fresh-host evidence or a fully crash-recoverable, idempotent
multi-VM installer. It does not:
- Install Windows/CAPEv2/dependencies, or validate Windows licensing.
- Guarantee source Windows master is personalized or snapshot-restorable.
- Apply Windows hostnames and static IPs inside the guest.
- Attach a NIC, configure INetSim/CAPE interface mapping, guard IPv4/IPv6
  runtime egress or prove nftables/libvirt persistence after reboot.
- Restore a full QCOW2 + UEFI + swtpm cold checkpoint or verify
  parallel CAPE agent functionality.
- Automatically reconcile incomplete staging after a crash.
- Guarantee initial boot/TPM/UEFI/AppArmor compatibility on a real host.

**Never use --mode stage on SSL-55.** Do not run even on a separate host
until a dedicated operator acceptance plan has been reviewed.
A future integrated Command 2 frontend must coordinate Command 1
provenance, reservation creation, staging, guest bootstrap, guarded NIC,
benign network acceptance, snapshots, and crash-safe recovery.
