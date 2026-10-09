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


## Confirmed installation evidence — 2026-10-09 21:40 UTC

The operator uploaded `CAPE_Hivex_Installation_20261009_214039_QU6qVO8K.txt`
after executing the guarded three-package installation:

- Installed `libhivex0=1.3.23-1build7`,
  `libhivex-bin=1.3.23-1build7` and
  `python3-hivex=1.3.23-1build7` from Ubuntu **24.04 Noble**.
- Apt transaction: **3 newly installed, 0 upgraded, 0 removed**.
- `/usr/bin/python3 -c 'import hivex'`: **PASS**.
- SHA-256 of `/usr/bin/qemu-img`, `/usr/bin/qemu-nbd` and
  `/usr/bin/qemu-system-x86_64`: **identical before and after**.
- QEMU version remains **9.2.2**, libvirt version remains **11.1.0**,
  and the existing `qemu` package was held.
- The installer did **not** install `virt-win-reg`, so Command 2's
  existing apply-path `personalize_clone_windows.py` is **still
  blocked**, deliberately.

**New safe development component:** `scripts/inspect_standalone_windows_hive.py`
reads only an individually extracted, detached clone's Windows SYSTEM
Registry hive (Hivex read-only). It discovers `Select\\Current`
and parses `ControlSetNNN\\Services\\Tcpip\\Parameters\\Interfaces`
for uniquely matched static IPv4 interfaces. The parser has mocked offline
tests in `scripts/test_inspect_standalone_windows_hive.py`.
The parser **does not** mount guest disks, alter Windows settings, write
the hive, or change the master VM.

**Next acceptance gate:** perform a reviewed, independent *cold-source
disk export* to a previously unused staging destination, without starting
the clone or touching the source. Confirm sufficient disk space, intact
backing chain and guest operating-state metadata first. Only after a
disposable clone exists should a separately approved, read-only NTFS
hive extraction be considered. Do **not** mount the master or its
backing layers through NBD or attach them with write access.

The remaining isolated-network, offline-hive write-back, guest first
boot, exact ping/curl identity and snapshot rollback checks are not
finished. **Commands 1 and 2 are not yet final.**


## First cold-clone export preflight — 2026-10-09 21:45 UTC

The user ran the requested **read-only** standalone host inspection and
uploaded `CAPE_First_Clone_Export_Preflight_20261009_214539_e03nyNYI.txt`.
Result: **COLD EXPORT PREFLIGHT PASSED**.

- `win11` was **shut off** with current snapshot `finalshutoffversion`.
- Verified backing layers: `win11.finalshutoffversion` →
  `win11.Afterfull` → `win11.basicinstallwinsnapshot` → `win11.qcow2`.
- Virtual capacity **64 GiB**, free storage **241.12 GiB**, minimum
  proposed single-export capacity plus host reserve **94 GiB**.
- Proposed standalone staging disk:
  `/var/lib/libvirt/images/cape-clones-staging/win11_1.qcow2`.
- **No disk export was performed**. No VM or original disk change occurred.

Next step is an **explicitly authorized** cold-disk flatten/copy of the
verified master chain into a brand-new, unique standalone QCOW2 file.
No guest start, network attachment, snapshot revert, Registry edit, or
CAPE configuration change is part of that export. A completed exported
file is not a ready-to-boot clone: its Windows static IP, hostname,
UEFI/TPM and agent identity are still inherited and must be changed
before any guest startup on an analysis network.

Perform a fresh shutdown/snapshot/backing-chain verification immediately
before export and again before publish; check QEMU image integrity,
final no-backing property, file owner/permissions, source-image metadata
and available disk capacity. Refuse overwrite/symlink targets and do not
use QEMU's `-U` unsafe shared-image option. Failure cleanup must touch
only the new incomplete export, never the master or snapshot chain.

## First independent Windows 11 image exported — 2026-10-09 21:50 UTC

The operator uploaded the completed export report
`CAPE_First_Clone_Export_20261009_215054_QqsqRl7U.txt`. The guarded
export succeeded using the shut-off `win11` source at its
`finalshutoffversion` snapshot and validated all four backing layers.

- New detached flattened disk:
  `/var/lib/libvirt/images/cape-clones-staging/win11_1.qcow2`.
- QCOW2 image virtual capacity **64 GiB**; actual allocated storage
  **29.53 GiB**; remaining host filesystem space **211.6 GiB**.
- Conversion completed in **37.7 seconds**.
- `qemu-img check` succeeded; the output reported **NO backing
  dependencies**.
- No new libvirt VM was defined or started, and the source `win11`
  disk and snapshots were not intentionally modified.

**Critical release boundary:** the exported image is not yet safe to
start on the network. It still has the master's Windows static IPv4,
hostname, machine identity and other disk-stored properties. It has
no independently generated per-clone UUID, UEFI NVRAM or TPM state.
Its Windows network interface configuration has not been inspected
or changed by Hivex. The master must remain shut off until further
staged inspections are approved.

**Next authorization gate:** any QEMU-NBD based read-only inspection
may load an NBD kernel module, attach a block device and mount NTFS
through host filesystem parsers. QEMU specifically warns that mounting
untrusted VM images may trigger kernel/filesystem vulnerabilities.
Even with read-only flags, this affects temporary host kernel/mount
state and therefore requires explicit operator approval on a shared
machine. It must target only the detached, flattened clone and
must have guaranteed disconnect/unmount cleanup. Do not attach or
mount the master image or its backing layers.

A root-private, non-network-boot, no-write clone hive inspection is a
possible next step **after operator approval and review**. Any actual
Registry write-back and analysis-guest boot remain blocked by the
independent guest IP and isolation acceptance gates.
