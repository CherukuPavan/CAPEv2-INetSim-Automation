# Real harmless QEMU + swtpm RAM/UEFI snapshot experiments (2026-10-16)

**Scope: disposable Ubuntu 26.04 container only.** These checks used
official signed distro QEMU 10.2.1 / swtpm 0.10.1 with TCG CPU emulation,
a blank synthetic guest disk, and **no network device**. They did not run
the private Windows 11 master, real CAPE samples, a production libvirt VM
or host KVM. Physical SSL-55 and SSL-46 were never accessed.

## Two successful experiments

1. [Real QEMU + swtpm native two-revert job](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38901660195)
   ran `scripts/test_command2_real_swtpm_snapshot_tcg.py`. QMP
   `savevm CAPE_BENIGN_QEMU_TPM` saved guest RAM to a standalone blank
   QCOW2. `info snapshots` saw it; **two** QMP `loadvm` calls succeeded
   with the same swtpm socket attached.
2. [Real QEMU + OVMF QCOW2 + swtpm two-revert job](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38901934894)
   ran `scripts/test_command2_real_ovmf_tpm_tcg.py`. The blank guest
   used real OVMF CODE, an independently converted QCOW2 writable VARS,
   standalone QCOW2 OS storage, and swtpm. QMP `savevm BENIGN_OVMF_TPM`
   and **two** `loadvm` calls succeeded. Offline `qemu-img info`
   confirmed named snapshots in **both** the OS disk and writable
   firmware VARS image.

These experiments establish that native QEMU components support the
chosen basic checkpoint shape on this architecture and distro.
They do **not** establish a CAPEv2-ready full running snapshot.

## Mandatory additional acceptance

- The real **libvirt** driver must register a named, full-system RUNNING
  snapshot and successfully revert it twice with a per-VM TPM emulator.
  Direct QMP `savevm` alone does not create libvirt snapshot metadata.
- A benign **Windows 11 TPM guest witness** must prove that guest TPM
  NV state, keys, PCR-dependent operations, UEFI configuration and
  applications remain usable after repeated real restores, not merely
  that the QMP command returned a success string.
- A separate physical KVM host must prove CAPE Agent reachability and
  simultaneous VMs without external IPv4/IPv6/L2 egress to campus or
  public internet during sample execution, including after reboot.
- Full deployment-scoped package/service/network/guest/swtpm rollback
  receipts and permissions must be physically verified.

References:
- [QEMU TPM emulator and migration specification](https://www.qemu.org/docs/master/specs/tpm)
- [libvirt snapshot documentation](https://libvirt.org/kbase/snapshots.html)
- [libvirt domain TPM configuration](https://www.libvirt.org/formatdomain.html)
- [libvirt snapshot-create CLI documentation](https://www.libvirt.org/manpages/virsh.html)

**Release policy:** keep any partial substage marked as incomplete;
never print final production three commands based solely on synthetic
or firmware-only tests. No real Windows image, credential, source host,
or untrusted executable was used in these experiments.
