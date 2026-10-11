# Command 2 — formal production acceptance (Command 3 locked)

Status on 2026-10-11: NOT COMPLETE, NOT DEPLOYMENT APPROVED.
Never start Command 3 on the assumption that passing mocked tests
means these end-to-end conditions passed.

## A. Fresh supported target prerequisites
- Command 1 source master is installed, correctly licensed and prepared.
- Source Windows guest agent/host-only bootstrap and cleartext template
  are VERIFIED on the actual target and stored securely.
- Host versions, KVM/OVMF/swtpm, AppArmor/libvirt permissions and
  physical CPU/RAM/storage resource admission are accepted.
- SSL-55 preservation fingerprint/host guard has been verified; no
  additional VM may be created or re-networked on that reference host.

## B. Command 2 exact requested VM count
- One entry command asks for TOTAL clone count N and stages exactly
  win11_1..win11_N; it refuses collisions, stale journals, and shortage.
- All created disks are independent, named, root-private and bootable.
- Each guest has unique libvirt UUID, Windows generation ID, MAC,
  NVRAM and private swtpm state; cloned source TPM must not be reused.
- Guest hostnames WIN11-1..N and static IPv4 addresses are applied
  INSIDE Windows, survive reboot, and match CAPE inventory.
- If any step fails, no blind deletion or retry may overwrite a
  partially staged guest. Recovery/resume and rollback are tested.

## C. Independent network containment
- Host network subnet and dedicated bridge are nonoverlapping; no
  unintended default NAT, extra guest NIC or gateway is configured.
- Dedicated CAPE/INetSim nft/libvirt rules do NOT flush or alter
  unrelated Docker/libvirt/campus traffic.
- Firewall/lab state survives host service restarts AND full reboot.
- IPv4 and IPv6 negative external-egress tests actually pass from an
  isolated TEST guest, while intended CAPE/INetSim service paths work.
- ONLY after the independent guard and persistence tests pass may
  guest NICs be attached to the dedicated isolated bridge.

## D. Benign Windows/CAPE acceptance
- Exact VM hostnames, MACs, IPs, guest NIC and Python/agent status are
  verified inside Windows, including reboot and parallel operation.
- CAPEv2 has correct per-VM libvirt snapshot and IP/name mapping.
- At least two Windows analysis guests simultaneously complete an
  authorized BENIGN test with no cross-guest identity/IP collision.
- INetSim services and CAPE paths are positive-tested, with external
  egress negative-tested for IPv4 and IPv6.

## E. Cold checkpoint and recovery
- Per-VM independent QCOW2, UEFI VARS and swtpm persistence is saved
  in an atomic cold-consistent checkpoint after clean Windows shutdown.
- Checkpoint restore is safely guarded, no master/shared state touched.
- Restore+reboot repeatedly preserve Windows identity, TPM, CAPE agent,
  static IP, negative egress and master snapshot protection.
- A fresh machine demonstrates the full two-command sequence without
  manual per-VM Windows intervention.

## Current evidence (not a release certificate)
- On SSL-55, only the original and one independent clone were
  actually boot-verified; clone remains ZERO NIC. 37 earlier offline
  tests passed, while newer integrated VM/network/Windows test CI
  results and all physical scaling acceptance remain pending.
- New code stages ZERO-NIC guests and prepares JSON guest configs on
  a separate host, but a verified guest bootstrap/config transport,
  isolated networking apply with persistence and full restore remain
  unfinished. A production two-command deployment cannot be claimed.

Until EVERY section is witnessed and documented on a separate
approved machine, Command 2 remains DEVELOPMENT and Command 3 LOCKED.