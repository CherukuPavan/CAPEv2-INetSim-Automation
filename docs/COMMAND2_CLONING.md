# Command 2: Count-driven Windows analysis-VM cloning

## Goal and status

**Developer-stage implementation on `development`, not a certified
one-command production installer.** The operator manually completed/hardened
`win11`, including Windows Python/CAPE agent, static IPv4 and two final
snapshots. The verified cold snapshot is `finalshutoffversion`. The snapshot
image depends on three older QCOW2 layers. A temporary read+lock AppArmor
repair was proven necessary to restart the master. The new clone pipeline
exports a **flattened independent image** to avoid inheriting broken
backing paths. It never changes the master QCOW2 images or snapshot metadata.

The requested final behavior is:

1. `bash scripts/command2_clone_vms.sh` asks **how many additional VMs?**
2. Names: `win11_1`, `win11_2`, ... `win11_N`.
3. Each VM gets its own independent flattened Windows disk and otherwise
   preserves the chosen CPU, memory, controllers, OS, installed programs,
   Windows Python/CAPE agent, and compatible guest configuration.
4. Each receives a new libvirt UUID, locally administered unicast MAC,
   fresh UEFI NVRAM file, separate swtpm per-UUID runtime state, and a
   distinct Windows hostname (e.g. `WIN11-1`; Windows hostnames cannot
   use underscores).
5. Before boot, the **offline** copy's actual Windows static network
   interface is discovered by its *old IP* in the current Windows SYSTEM
   Registry ControlSet. The tool refuses ambiguous NICs and updates the
   copy's IPv4, netmask, gateway, DNS and Windows hostname, then verifies
   the IP registry result. This is a **clone-only** modification, never
   a change to `win11`.
6. Guest NIC attaches only to the explicitly approved nonforwarding
   libvirt network. Libvirt graphics ports are automatically allocated,
   and USB redirection plus the SPICE clipboard channel are omitted to
   protect the shared host. Immediately after defining the clone,
   libvirt's actual UUID, disk, MAC, NIC, NVRAM and emulated TPM are
   read back and compared with the intended configuration. A per-clone
   swtpm AppArmor socket exception is validated **before** boot.
7. Boot the clone for harmless connectivity checks. Ubuntu must
   successfully ping the new IP **via the selected analysis bridge**,
   verify that its IPv4 ARP neighbor MAC matches the exact clone's
   assigned MAC, and run a direct **curl --interface** request to the
   CAPE agent on port 8000. The HTTP response must identify the
   CAPE agent and report administrator privileges. A different
   machine answering at that IP is not an acceptable PASS.
8. Create a running-state CAPE analysis snapshot; shut down; restart and
   recheck ping/CAPE agent; restore the fresh clone's analysis snapshot
   and recheck ping/CAPE agent. This avoids merely assuming that an
   untested snapshot is reusable.
9. Once **every** clone is healthy, update CAPE KVM machine registration
   from a protected, backed-up config file, retaining existing defined
   machines and removing *undefined stale names from the active list*.
   The original comments and unrelated sections are preserved.
10. Leave guests shut off, record a per-step journal and operator report.
    CAPE service restarts and independent malware containment signoff
    are a separate operational gate.

**No actual SSL-55 clones have yet been created or started.**
The repository's GitHub Actions tests are synthetic/offline and cannot
prove Windows guest boot, NTFS/Registry compatibility, TPM/BitLocker
handling, CAPE agent availability, snapshot rollback, or network isolation.

## Deployment profile (one-time, required)

[Safe sample profile](../config/command2-profile.example.json)

The sample uses RFC documentation-only IPs and a deliberate placeholder
network name. **It must not be run as-is.** A reviewed, root-controlled
configuration file must be installed at
`/etc/cape-clone/command2.json`, e.g. owned by `root:root` mode `0600`.
The actual master IPv4 and Windows interface must be verified independently
from **inside the completed Windows guest**, not inferred merely from the
existing stale CAPE `cuckoo1` KVM configuration.

The profile must supply:

- `master=win11`, `snapshot=finalshutoffversion`
- The approved analysis-only libvirt `network` and subnet's
  `first_ipv4`, `mask`, `gateway`, `dns`
- Actual original Windows `old_ipv4`, not a guessed value
- Existing root-controlled `disk_dir` and `nvram_dir`
- `cape_config=/opt/CAPEv2/conf/kvm.conf`
- Consistent future `snapshot_name`, distinct reserved IPv4s
- `benign_test_only_acknowledged=true` for explicit apply mode only

The profile is intentionally external to GitHub. Do not commit
institutional network maps, secrets, malware samples, Windows images,
or guest passwords.

### Required host dependencies

The authorized installer stage must **discover and verify** Python 3,
`virsh`, `qemu-img`, `virt-win-reg` (libguestfs/hivex), usable
KVM/libvirt, AppArmor and Windows/UEFI/swtpm support. The master inventory
indicated no `guestfish` or `virt-sysprep` in PATH; **that does not prove
`virt-win-reg` is installed**. Do not install random apt packages or
rerun upstream hypervisor installers on the mixed-package SSL-55 host.
A reviewed dependency bootstrap must fill provisionable gaps without
replacing host-wide virtualization components.

### Execution contract (not yet approved on SSL-55)

```bash
# From an authenticated development checkout; no GitHub account password.
# Do NOT run on SSL-55 until independent compatibility/isolation approval.
bash scripts/command2_clone_vms.sh --plan
# Same command, prompts for number and applies only after all gates pass:
bash scripts/command2_clone_vms.sh --apply
```

Command 2 in `--apply` mode is **not a harmless dry-run**: it creates
independent disk files, updates *clone* Windows registry settings, creates
libvirt domains/NVRAM, starts benign Windows guests, creates/reverts clone
snapshots, and updates CAPE machinery configuration. Plan mode does none
of those changes. Each generated report is under
`/var/log/cape-clone/`, root-readable by default, and can be copied to
the operator's account after inspection and redaction.

## Safety and failure handling

- A missing/uncertain snapshot, changing source, incomplete image chain,
  insufficient conservative disk/RAM resources, duplicate VM names/IPs,
  existing CAPE IP registrations, libvirt DHCP pools/reservations, an
  occupied target analysis network, malformed/unsupported guest definition,
  unavailable offline Registry backend, missing NVRAM, or NAT/forwarding
  network **blocks apply**.
- The master is required to remain shut off. Export uses native QEMU
  locking; no unsafe `-U` bypass. No disk rebasing on the master.
- IP personalization is attempted **before any clone is networked**;
  the old static IPv4 is never deliberately enabled in parallel.
- If guest ping/CAPE agent verification fails, no other clone is started.
  The orchestrator attempts to stop only the currently failed new guest
  **after independently verifying its exact libvirt UUID**. It never
  destroys the master or other students' VMs. Disks and definitions remain
  for investigation; a partially modified clone can require disposal and
  recreation rather than unsafe in-place retry.
- Crash, SIGKILL, power loss, unexpected libvirt QEMU behavior and partial
  package updates are **not** fully transactional. The apply command holds
  a root-owned nonblocking **flock**, preventing two Command 2 instances
  from provisioning simultaneously. Each stage writes a private, fsynced,
  uniquely named journal event, including rapid same-second operations.
  Re-running with an existing destination refuses to overwrite it.
  Journal entries support recovery but do not certify automatic rollback.
- The MAC, UUID, Windows hostname and IP changes intentionally diverge
  from the master. UEFI variable state is copied, while emulated TPM
  runtime state must remain separate. A guest using BitLocker or other
  TPM-bound secrets may need supported recovery/resealing and cannot be
  guaranteed to boot from a fresh TPM without independent checks.
- Clones preserve existing installed applications/files; software that
  binds to hostname/activation/hardware identifiers may require checks.
- Boot checks use harmless Windows startup and CAPE's GET / endpoint.
  **This does not authorize live malware execution.** The current master
  network was `default` NAT. A no-forward network XML is necessary but
  NOT enough to independently certify host/guest firewall, IPv6, campus
  gateway isolation or permitted CAPE management flows. Actual negative
  network reachability tests and institutional authorization are mandatory
  before live samples. See
  [containment policy](LIVE_MALWARE_CONTAINMENT_POLICY.md).


### Per-clone TPM/AppArmor access

SSL-55's completed `win11` originally needed a narrow AppArmor
allowance for its `swtpm` Unix socket. The cloned domains use distinct
`*-win11_N-swtpm.sock` socket names, so a new guarded
`scripts/guard_vm_tpm_socket.py` creates a per-clone-named, exact-suffix
read/write socket path allowance and syntax-checks the policy before
a benign test boot. It refuses conflicts, missing include mechanisms
or changed VM UUIDs, and attempts to remove its own rule if validation
fails. The permission is stored in the **shared** QEMU abstraction even
though the allowed socket *path* names only one clone. Shared policy
isolation must be assessed before real malware deployment: the rule
is not equivalent to a fully separate per-VM AppArmor profile.

### Operator default

`bash scripts/command2_clone_vms.sh` now defaults to the **read-only
`--plan`** mode. Only an explicit `--apply`, after an approved
isolated network and host-specific dependency tests, can create a
new VM. It always asks for a count, then uses names `win11_1`,
`win11_2`, and so forth.

## Known blockers on SSL-55 right now

1. The master's reported network is `default` NAT. No separately
   verified, non-NAT/non-forwarding analysis network was established
   in the latest inventory. Command 2 will refuse to deploy on NAT.
2. `kvm.conf` still actively lists absent `cuckoo1` while the master is
   `win11`. The guarded CAPE config renderer can retain valid existing
   libvirt guests and replace stale active machine IDs *only after*
   successful clone verification, but has not been tested on SSL-55.
3. No QEMU Guest Agent channel is available; offline Windows Registry
   changes via `virt-win-reg` are the candidate, not a verified Windows
   guest customization result. `virt-win-reg` compatibility and
   BitLocker/TPM state require real-machine checks.
4. Approx. 250 GiB free in the latest inventory. Five **full 64 GiB**
   virtual-size image copies plus a 30 GiB reserve exceed capacity.
   The default conservative gate allows no overcommit guess.
5. The shared college host's explicit institutional authorization
   to run live malware has not been independently documented. Benign
   clone/agent tests only after isolation review.

Do not mark the overall three-command installer complete until Command 2
passes a separate, independent host acceptance matrix and end-to-end tests.
