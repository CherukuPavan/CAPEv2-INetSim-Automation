# Signed Cloud Archive feasibility (not production)

Canonical publishes Ubuntu Noble Cloud Archive pockets including epoxy and flamingo. A future read-only verifier must validate the Canonical InRelease signature, signed SHA256 package index, package versions, and expiration before planning any hypervisor upgrade. This does not authorize package installation, snapshot restore, or three-command deployment.

Source: https://ubuntu-cloud.archive.canonical.com/ubuntu/dists/noble-updates/

## Verified 2026-10-16 Canonical signed APT comparison

Disposable GitHub Actions runners tested `cloud-archive:epoxy`,
`cloud-archive:flamingo` and `cloud-archive:gazpacho` separately on
Ubuntu 24.04 LTS with APT's signed-index verification. All three
continued to select QEMU 8.2.2 and libvirt 10.0 for `qemu-system-x86`
and `libvirt-daemon-system`. The signed cloud pockets did **not**
solve the native running-checkpoint version floor without an additional
separately sourced and assessed hypervisor.

A second disposable job tested **official signed Ubuntu 26.04 LTS**
(Resolute) repositories, without enabling a PPA or third-party archive.
Actual candidate versions on 2026-10-16 were QEMU 10.2.1
(`1:10.2.1+ds-1ubuntu3.2`) and libvirt 12.0.0
(`12.0.0-1ubuntu5.5`), above the project floors. A separate Docker
container job actually installed distro QEMU, libvirt, OVMF and swtpm
binaries and inspected their runtime versions and firmware files.
Neither job booted Windows, instantiated a libvirt guest, synchronized
swtpm NV/volatile state, performed a live snapshot, or proved isolation.
Original reference host and production machines were never modified.

The tracked base APT component now offers an **experimental optional
Ubuntu 26.04 profile** including `qemu-system-x86`, `qemu-utils`,
`libvirt-clients`, `libvirt-daemon-system`,
`libvirt-daemon-config-network`, `ovmf`, `swtpm`,
`swtpm-tools` and `virtinst`. It checks candidate version floors,
rejects externally shadowed virtualization binaries, simulates all
transitive package changes, refuses any existing-package upgrades and
records a root-private before/after package inventory under the same
Command1 transaction before applying new APT packages. Ubuntu 24.04
continues to stage its old seven base packages only.

This does not prove a viable Windows 11/CAPE runtime or complete
deployment-scoped rollback. In particular, swtpm persistent/volatile
state is not automatically tied to a libvirt running snapshot merely
because package versions are recent. The TPM-coherent two-cycle
physical reversion gate remains mandatory.

Official references:
- https://documentation.ubuntu.com/release-notes/26.04/changes-since-previous-interim/
- https://documentation.ubuntu.com/security/software-integrity/archive-verification/
- https://ubuntu-cloud.archive.canonical.com/ubuntu/dists/noble-updates/
- https://www.libvirt.org/formatsnapshot.html
- https://qemu-project.gitlab.io/qemu/specs/tpm.html

