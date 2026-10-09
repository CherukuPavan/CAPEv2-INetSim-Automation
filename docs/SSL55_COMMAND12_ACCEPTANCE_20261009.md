# SSL-55 Commands 1–2 host acceptance — 2026-10-09

**Evidence:** Operator-provided read-only TXT from `CAPE_Command12_SSL55_ReadOnly_20261009_212430_X6aGRz9m.txt`.
The source TXT remains in the conversation; this repository note intentionally
omits internal campus IPs, host UUIDs and sensitive path-specific metadata.

## Confirmed

- Host is Ubuntu 24.04.3 LTS, x86_64, KVM available, roughly
  62.5 GiB total RAM, 55.7 GiB available during check, and **242 GiB
  free** on the single filesystem containing the libvirt images.
- Custom virtualization stack: `virsh` reports **11.1.0**,
  `qemu-img` reports **9.2.2**, `swtpm` reports **0.7.3**.
  All are present, as are Python 3.12.3, AppArmor, ping and curl.
  Never replace the custom libvirt/QEMU deployment with distro
  defaults just to satisfy a missing optional package.
- The operator-created master `win11` was **shut off**.
  Current libvirt snapshot: `finalshutoffversion` (`shutoff`,
  `memory snapshot=no`). Earlier `Afterfull` is a running-state
  external-memory snapshot, with `basicinstallwinsnapshot` below it.
- Current active disk has **four QCOW2 layers**, with the correct
  backing links and no QCOW2 `corrupt` flags in `qemu-img info`.
  These checks are structural; independent source integrity, stable
  snapshot restore and clone boot are **not** yet established.
- The template VM has a 4 GiB memory allocation, 64 GiB virtual disk,
  UEFI variable store and emulated TPM 2.0. Only the `default` libvirt
  NAT network was registered in the audit.
- `virtqemud.service` was active. `libvirtd.service` being inactive
  is not itself an error on a modular libvirt deployment. CAPE service
  states were mixed; final web UI/service checks belong to Command 3.

## Command 2 deployment blockers on this host

1. **Offline Windows IP customization:** `virt-win-reg` and `guestfish`
   are absent. Ubuntu 24.04's `guestfs-tools` package includes
   `/usr/bin/virt-win-reg`; first simulate its dependency impact
   with `scripts/plan_guestfs_dependency_impact.sh`. Do **not**
   blindly install `libguestfs-tools`, replace QEMU/libvirt, or
   edit a live Windows image. Guestfs Registry merge is inherently
   risky: test on a disposable independent cold clone disk only.
2. **Isolation:** The only libvirt network is `default` NAT; its
   DHCP pool covers nearly the entire /24. A distinct, explicitly
   approved, non-forwarded lab network and address plan must exist
   before any VM-clone startup. Even a non-forwarded XML configuration
   does not by itself prove campus/Internet/IPv6 containment.
3. **Available disk:** 242 GiB of filesystem headroom is less than
   **4 × 64 GiB + 30 GiB reserve**. Current Command 2 pessimistic
   full-virtual-capacity accounting permits **at most three** clones
   here (3×64+30=222 GiB), assuming no meaningful concurrent disk
   consumption. Actual sparse export usage may be lower but must
   be measured rather than silently overcommitted.
4. **Guest IP evidence:** Existing CAPE machinery fields contain stale
   `cuckoo1` and two machine sections with the same address. Do NOT
   infer the **actual Windows master IPv4** from those stale entries.
   Command 2 must acquire independently confirmed in-guest IPv4/mask
   and assign collision-free clone IPs. Command 3 owns correcting
   CAPE registration and starting the UI.
5. **Acceptance:** One disposable clone must independently verify
   `virt-win-reg` compatibility, Windows boot with an independent
   NVRAM/TPM state, exact MAC identity, ICMP and CAPE-agent curl,
   snapshot shutdown/restart/revert, and negative external egress.
   Neither the evidence TXT nor offline GitHub tests prove those.

## Safe immediate action

Run a **read-only APT transaction simulation** (no host changes) and
review whether the candidate `guestfs-tools` package would unexpectedly
install, replace or remove crucial host libvirt/QEMU components:

```bash
bash scripts/plan_guestfs_dependency_impact.sh
```

For hosts without working GitHub authentication, the same
`apt-get -s --no-install-recommends install guestfs-tools` commands
can be executed directly in the terminal and captured in one private
report. If a real install is approved later, use a narrowly scoped
transaction that preserves existing virtualization packages, then
re-run read-only host version checks.

**Master policy:** Never modify, export with `-U`, chown recursively,
rebase, restore or delete the master or its snapshots to work around
dependency conflicts.

**Release status:** Commands 1–2 are still developer-stage; the completed
manual master is confirmed, **automated deployment is not yet accepted**.
Commands 3–4 are reserved for the later user-led phase.

## Follow-up APT simulation — 2026-10-09 21:29 UTC

The operator uploaded a complete read-only `apt-get -s
--no-install-recommends install guestfs-tools` report. Result:
**0 upgraded, 50 newly installed, 0 removed, 151 not upgraded;
exit 0.** Crucially, it proposed Ubuntu `qemu-system-common`,
`qemu-system-data`, `qemu-system-x86` and `qemu-utils` at **8.2.2**,
`seabios` **1.16.3** and `libvirt0` **10.0.0**. Meanwhile the
existing custom host runs QEMU **9.2.2** as a held `qemu` package
and libvirt tooling **11.1.0**.

**Decision: REJECT host-level `guestfs-tools` APT installation as
simulated.** APT reporting no package removals does not establish
safe coexistence, binary file ownership, executable resolution,
library ABI or daemon compatibility. Older distro QEMU components
and custom QEMU/libvirt may conflict. The APT package cache also
contains both Ubuntu Noble and Focal candidates for some packages;
do not mix suites or run `autoremove` to "resolve" this.

The development-only `plan_guestfs_dependency_impact.sh` now reports
`DEPENDENCY_DECISION=BLOCKED` if a guestfs APT plan introduces or
removes QEMU/libvirt/firmware stack packages, or if the simulation
fails. It cannot authorize installation automatically, even for
plans without those package names.

**Safer next investigation (read-only):** Check whether the host already
has a supported isolated tool environment (Docker/Podman/other
container runtime) for `virt-win-reg` on a temporary *detached,
flattened clone QCOW2*. Alternatively evaluate minimal offline
Windows Registry access dependencies without a host libvirt/QEMU
replacement. A container-based method is only a **candidate** and must
be assessed for file permissions, QEMU nested execution, container
privilege requirements, filesystem locking, NTFS/Windows 11 and
trusted/pinned images. Do not blindly pull or run third-party
container images. All writes must be limited to an independent
clone disk; no master backing layer or TPM secrets may be exposed.

Neither route is validated on SSL-55 yet. Do not create guests, alter
CAPE machine registration or bypass the restricted network gate.


## Follow-up offline tools audit — 2026-10-09 21:32 UTC

The user supplied another read-only host report:

- `qemu-nbd`, `qemu-img` and `qemu-system-x86_64` all resolve to
  `/usr/bin/` and are owned by the held custom `qemu` package.
- `ntfs-3g` is present (Ubuntu Noble version
  `2022.10.3-1.2ubuntu3.2`).
- `virt-win-reg`, `guestfish`, `hivexregedit` and `hivexsh` are
  missing. `python3-hivex`, `libhivex0` and `libwin-hivex-perl`
  have Ubuntu Noble `1.3.23-1build7` candidates.
- Docker client `29.2.0` is installed, but the unprivileged account
  received **permission denied** on the Docker daemon socket. Docker
  usability as root, preexisting images and container security have
  **not been established**.
- APT candidates include packages from **both Noble and Focal**; never
  install an Ubuntu 20.04 candidate into the Ubuntu 24.04 host.
- Storage remains approximately **242 GiB free**, and `qemu` remains
  held.

**Candidate safer backend:** `python3-hivex` + `libhivex-bin`, with
the already installed `qemu-nbd` and `ntfs-3g` *only on a disposable
independent flattened clone*. This is an engineering hypothesis, not
a verified guest customizer or approval to attach a Windows disk.
Hivex works directly with offline Windows Registry hives. The
official Hivex documentation warns that Registry writes can still
damage hives; copy and validate standalone clone disk and hive first.

A new `scripts/plan_minimal_hivex_backend.sh` performs read-only
APT transaction simulation for that smaller backend, flags focal
candidate packages, and surveys NBD and root-authorized Docker
availability. It refuses to auto-install anything. Docker access may
require an authorized root user; **do not add the account to the
docker group** just to bypass the current permission error, because
Docker daemon control is effectively privileged host access.

No Hivex Registry-writing or QEMU-NBD guest-mount operation has yet
been approved or tested. The current Command 2 apply mode still
requires the existing `virt-win-reg` backend and must **not** be
run until an independently reviewed compatible offline guest-IP
customizer is available, network isolation is checked, and physical
host acceptance succeeds.


## Follow-up APT simulation — 2026-10-09 21:36 UTC

The operator supplied `CAPE_Minimal_Hivex_Check_20261009_213608_0fbBOWoc.txt`:

- All three requested packages are Noble `1.3.23-1build7`:
  `libhivex0`, `libhivex-bin`, `python3-hivex`.
- APT simulation: **0 upgraded, 3 newly installed, 0 removed**,
  exit code **0**. Neither `qemu`, `qemu-utils`, `qemu-system-x86`,
  nor libvirt packages appear in the installation transaction.
- The source list still exposes Focal candidates, but the selected
  three versions were explicitly listed from **Ubuntu 24.04 Noble**.
- The existing `qemu` package remains held.
- The kernel `nbd.ko.zst` module exists, but no `/dev/nbd*` device
  is currently present. Do not `modprobe` or `qemu-nbd --connect`
  on any original master image.
- `sudo docker version` reports client/server **29.2.0**. This does
  not establish a safe, approved container image for guest Registry
  editing and does not justify broad Docker user permissions.

**Decision:** the three exact-version packages may be considered for
a **guarded, explicitly authorized, minimal installation**. This
does not complete the Windows clone personalization backend; Command 2
still expects `virt-win-reg` and must not be run in apply mode.

The repository now includes `scripts/install_minimal_hivex_guarded.sh`,
which defaults to a read-only transaction plan. Explicit `--apply`
requires Ubuntu Noble, a held QEMU package, a successful transaction
containing only the three pinned Hivex packages and zero removals, and
verifies that the existing QEMU executables have not changed. It
captures its transaction and verification in a single private TXT.

Next milestone after installation: implement and independently test a
Hivex backend that edits an **extracted independent clone-only** SYSTEM
hive, with rollback-safe backup and post-write checks, then safely
reintegrate the hive into its *own* powered-off clone disk.
Do not substitute `hivexregedit` for `virt-win-reg` in an existing
command without verifying Windows control sets, interface GUIDs and
IPv4/hostname semantics.

