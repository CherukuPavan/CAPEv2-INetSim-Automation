# CAPE isolated Python 3.12 and libvirt full-snapshot experiments

**Date:** 2026-10-16. **Environment:** disposable Ubuntu 26.04 LTS
containers in GitHub Actions, never the user's reference SSL-55/SSL-46,
personal Drive, or any physical KVM analysis host.

## Verified by actual process execution

- The distro provides Python **3.14.4**, not the CAPE-tested Python 3.12.
  Its direct Python ABI cannot resolve CAPE's pinned `greenlet==3.0.3`
  binary wheel (negative run
  [38903950660](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38903950660)).
  Installing CAPE into system Python 3.14 is forbidden by this release
  strategy.
- A **separate** uv-managed CPython **3.12.12** in `/tmp/cape-py312`
  installed and imported exact upstream native
  `greenlet==3.0.3` and `gevent==24.2.1` while system Python remained
  3.14.4 ([38904463809](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38904463809)).
  The upstream repository was checked out at exact commit
  `004d73c51dcd12dacb97b3657262bdea8376d710`.
- Full `uv pip compile` of CAPE `pyproject.toml` with a temporary
  isolated builder succeeded when source-distribution metadata was allowed:
  [38905060401](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38905060401).
  Binary-only compilation had previously failed due to pure-Python
  `bs4==0.0.1` shipping no wheel; that was a test-mode limitation,
  not proof the dependency was irrecoverable.
- **Actual installation of 170 resolved CAPE dependencies** into the
  disposable Python 3.12 environment succeeded, and `gevent`,
  `greenlet`, `Django`, `SQLAlchemy`, and `yara` imported:
  [38905628677](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38905628677).
  `uv pip install --editable CAPEv2` was rejected correctly because
  upstream Poetry declares non-package mode; compiled PEP-621
  `[project].dependencies` was installed instead.
  Source-distribution build hooks were permitted **only** in this
  isolated no-credentials disposable runner, not authorized as a
  production root installer.

## Real libvirt/RAM+disk+firmware experiment

- [38905822665](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38905822665)
  succeeded in a networkless synthetic TCG domain with official
  Ubuntu26 QEMU 10.2.1, libvirt 12.0, OVMF writable QCOW2 varstore and
  an emulated swtpm2. `virsh snapshot-create-as --atomic` created a
  **registered libvirt** full-system snapshot, and **two real**
  `virsh snapshot-revert --running` calls returned successfully.
  This resolves the earlier distinction between only QMP savevm and an
  actual libvirt snapshot registration.
- Restricted GitHub containers do not have working system cgroups or
  normal `trusted.*` extended attributes. The CI harness relaxed
  libvirt DAC security and QEMU/swtpm runtime ownership ONLY inside
  that disposable container, and it had no guest network interface.
  It must **never** copy those insecure settings to a physical host.
  Both `virsh destroy` and `virsh undefine` timed out during
  container-local teardown. The CI job logged both failures; GitHub
  discarded the **entire container**. This is NOT evidence that
  deployment-scoped VM cleanup/rollback works on a physical host.

## Release-critical evidence still required

- Repeated **Windows 11** running snapshot revert and a guest witness
  proving persistent+volatile swtpm state, UEFI variables, PCR/keys,
  agent responses and installed applications actually survive.
- A privileged **physical KVM host** with normal AppArmor, DAC, cgroups,
  QEMU user and libvirt authorization. A restricted synthetic TCG
  container is not representative of the final KVM security model.
- Actual receipt-backed CAPE database and five-service orchestration,
  isolated NIC, IPv4/IPv6 and L2 containment, no unintended NAT,
  reboots, N cloned Windows guest identities, and complete
  deployment-owned repair/rollback.
- Separately provisioned authorized read-only key and decryption access
  to the real encrypted SSL-55 master; public GitHub source availability
  does not provide access to this protected asset.
- An acceptable pinned, hash-verified and audited supply chain for
  external uv CPython 3.12 and all CAPE dependency artifacts before
  installing them on an operator host.

These results make the candidate host design more concrete. They are
**not** the complete Command 1, 2 or 3 installation acceptance.

**CI references:** source files are
`.github/workflows/command1-resolute-cape-venv-install-lab.yml`,
`.github/workflows/command2-real-libvirt-tpm-running-snapshot.yml`, and
`scripts/test_command2_real_libvirt_ovmf_tpm_snapshot.py`.
