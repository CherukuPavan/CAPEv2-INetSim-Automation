# Command 1 and Command 2 reference-build reconciliation (2026-10-09)

**Source material provided by operator:** `Finalpdf.pdf`, *CAPEv2 Malware
Analysis Sandbox — Complete Build & Configuration Guide*, Parts 2–12 and 20.
This is an operator guide, **not a completed, machine-portable unattended
installation specification**. Do not store the PDF, ISO, passwords or virtual
disk images in this GitHub repository. Track only non-sensitive findings.

## What the reference guide actually establishes

| Step in guide | Reference procedure | What the current automation can verify |
| --- | --- | --- |
| Part 2 | Ubuntu host virtualization and resource checks | Existing read-only host and prereq auditors |
| Parts 3–6 | CAPE source, upstream QEMU/SeaBIOS/libvirt compilation, host installer vars, base installer, Python deps | Source and controlled-package bootstrap, risk analysis; **not** a full idempotent replacement for upstream custom host-wide installers |
| Part 7 | **Windows 10** media, virt-manager wizard, 4 CPU, 5000 MiB, 100 GiB QCOW2, manual XML device/CPU/timer customization | Libvirt XML validation/template cloning; **no proven Windows 11 ISO unattended install** |
| Part 8 | Inside-Windows policy, Sysmon, antidetector testing and GUI/security settings | User reports a completed hardened master; **no verified equivalent fully unattended Windows 11 guest configuration script** |
| Part 9 | Python **3.10.11 x86/32-bit**, pillow, pywintrace and pinned pyOpenSSL/cryptography | Guest disk is copied for clones; **no automatic fresh-guest package install/reboot acceptance** |
| Part 10 | Inside-Windows static IPv4, mask/gateway/DNS, host ICMP check | Command 2 has clone-only *offline* Windows Registry personalization; compatibility must be tested on Windows 11 with the real guest disk |
| Part 11 | `agent.py` on port 8000, administrator privileges, auto-start and curl after reboot | Clone host ping + direct curl identity checks; master/agent setup still depends on manual reference preparation |
| Part 12 | Running-state snapshot while CAPE Agent is reachable; confirm exact libvirt snapshot name | Clone-specific explicit external RAM and disk snapshot, post-shutdown backing-image `rk`, reboot and revert tests in **offline-tested** code |
| Part 20 | Each additional VM must have distinct domain name, guest IP, virtual disk, MAC and valid snapshot; CAPE machinery registration | Command 2 proposes/creates distinct identities; **machine registration is intentionally deferred to Command 3** |

## Important source/version differences

The guide's initial VM was **Windows 10** and 100 GiB, with 5000 MiB
memory and an example `win10` name. SSL-55's operator-completed
reference VM is **Windows 11 Pro**, 64 GiB, 4 GiB, 4 vCPUs, named
`win11`. Its current cold source is `finalshutoffversion`, with
external snapshot chain:

```
win11.finalshutoffversion -> win11.Afterfull
                           -> win11.basicinstallwinsnapshot -> win11.qcow2
```

The guide's `192.168.122.*` addresses and `default` bridge describe a
NAT reference topology, **not** an approved live-malware isolation design.
The first and second command cannot silently deploy analysis guests onto
the real campus/public-Internet-facing `default` NAT network just to
make old guide examples pass. A distinct verified nonforwarding lab
network is a prerequisite to benign clone start. The separate INetSim
simulated services are installed later in Command 4.

## Evidence required before calling Commands 1 and 2 FINAL

- **Supported OS/build matrix:** exact Ubuntu, QEMU, libvirt, KVM, firmware,
  swtpm, CAPEv2, libguestfs/virt-win-reg and Windows 11 build compatibility.
- **Command 1 fresh install:** missing host dependencies installed
  idempotently, source hashes/version pins, no unexpected global security,
  kernel, GRUB or other-user service changes, a genuine licensed
  Windows 11 ISO or authorized unattended installation mechanism,
  and an *automatically configured and tested* Windows guest matching
  the recorded first-master procedure.
- **Guest policy/install audit:** actual registry/software/service state
  after restart, 32-bit Python and packages, agent startup and curl,
  Sysmon/anti-evasion checks; unknown values must not be assumed to pass.
- **Snapshot integrity:** completed guest's clean running-state snapshot
  and independent shut-off clone-source backup, no unresolved QEMU
  locks, libvirt correct restore, backing files, AppArmor, TPM/NVRAM state.
- **Command 2 on real SSL-55:** isolated bridge and negative egress
  test, cold disk export from live master inventory, offline
  Windows Registry IP/hostname modification checked *inside* the
  test clone, QEMU/TPM/AppArmor startup, ping/curl **from expected MAC**,
  actual external snapshot and revert checks.
- **Scale:** start with ONE disposable clone, then TWO, then user-chosen
  count, verify capacity, resource consumption, restart after host
  reboot, concurrent safe operation and interruption/retry recovery.
- **Independent fresh-host acceptance:** repeat on a supported different
  machine without assuming SSL-55's installed QEMU, user, network,
  snapshot names, guest ISO or hardcoded paths.

**Passing mocked GitHub Actions tests does not satisfy these physical-host
requirements.** Therefore `command1_pre_vm.sh`, the new
`command1_master_checkpoint.py`, and `command2_clone_vms.sh` remain
developer-stage entrypoints, **not final approved installers**. The user
has already completed Windows 11 manually on SSL-55; do not rerun the
host/CAPE/Windows installers there.

## Recommended next host evidence

One consolidated, **read-only** host acceptance report should record
non-secret details required to finish scripting:
- running/stopped status and source VM/snapshot chain;
- exact versions and provenance of `virsh`, `qemu-img`, `virt-win-reg`,
  `swtpm`, `apparmor_parser` and libvirt networking;
- Windows guest ISO availability and its official/version provenance;
- `/opt/CAPEv2` machinery config **allowlisted** fields only;
- available storage/RAM, guest network XML, bridge, DHCP range and IPv6
  forwarding (never dump user secrets or Internet-route credentials);
- read-only snapshot XML and UEFI/TPM definitions.

This report may be generated via the developer-stage `audit_clone_master.py`
plus host dependency audits, without changing the master or creating a
clone. Details cannot be fabricated from the 128-page guide.
