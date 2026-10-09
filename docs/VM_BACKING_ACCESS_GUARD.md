# External QCOW2 snapshot startup guard (developer-stage)

## Purpose and observed SSL-55 failure

The verified SSL-55 Windows 11 analysis VM `win11` uses:

```
win11.Afterfull -> win11.basicinstallwinsnapshot -> win11.qcow2
  active RW          intermediate RO             oldest RO
```

After shutdown, QEMU initially failed to open `win11.qcow2` (permission denied).
A read-only AppArmor exception changed the failure to `Failed to lock byte 100`.
Adding **read + lock (`rk`)** for the two backing images allowed QEMU to start.
The user confirmed Windows reached the desktop and restarted after a normal
shutdown. That verifies this specific repair on SSL-55, **not** portable clone
deployment or snapshot rollback. No backing image was rebased or deleted.

The SSL-55 host lacks a `libvirt-qemu` account and uses a custom virtualization
stack; NEVER hardcode the Ubuntu distro's presumed QEMU service user/group or
blindly `chown` an image. The checked-in helper does not relax Unix DAC.

## Implementation

`scripts/guard_vm_backing_access.py` discovers the **destination VM's**
libvirt UUID, active QCOW2 disk and backing chain at runtime. It checks:

1. VM is shut off and has exactly one file-backed QCOW2 disk.
2. `qemu-img info --output=json --backing-chain` has a complete, ordered,
   noncyclic external QCOW2 chain (2–16 layers).
3. Every path is normalized, a regular image, and free of symlinks or
   AppArmor glob/metacharacter injection.
4. AppArmor is enabled and the host's libvirt QEMU abstraction contains the
   supported `include if exists <abstractions/libvirt-qemu.d>` directive.
5. The override directory is root-controlled; there are no conflicting
   existing policy files.

**Plan only (read-only, no changes):**

```bash
sudo python3 scripts/guard_vm_backing_access.py --vm win11_1 --mode plan
```

**Explicit preparation of an approved, shut-off VM** (requires containment
checks by a future orchestration layer):

```bash
sudo python3 scripts/guard_vm_backing_access.py --vm win11_1 --mode apply
```

**Confirm installed rules without starting a guest:**

```bash
sudo python3 scripts/guard_vm_backing_access.py --vm win11_1 --mode verify
```

The helper creates a deterministic root-owned `/etc/apparmor.d/abstractions/
libvirt-qemu.d/99-cape-qcow2-<UUID>` file with exact-path `rk` permissions
for each **backing** image, never `w` on a backing image. It does not
override other files. Creation is atomic, serialized under a root-only runtime
lock, syntax-checked, and reloaded if a generated guest profile exists.
If validation fails after file creation, it attempts to remove **only** its
own matching policy and re-parse the profile. Idempotent repeated invocation
does not duplicate policy files. An interrupted process or incompatible
configuration can still require operator intervention; read the error.

**Important:** This is a **shared libvirt AppArmor abstraction**. The policy
only authorizes specific paths, but those path grants can be inherited by
other QEMU guest profiles. Do **not** equate narrow path matching with per-VM
confinement. A later production design must review isolation, potentially
switching to stronger per-VM policy generation. This helper does not certify
a source tree or dynamic `virt-aa-helper` behavior on an untested host.

## Integration contract for eventual three-command installer

The future clone deployment step must:

1. Prove institutional authorization and safe, independently verified guest
   **network isolation** before ever running live samples (see
   `docs/LIVE_MALWARE_CONTAINMENT_POLICY.md`).
2. Verify destination host supported OS/QEMU/libvirt, resources, source image
   integrity/consistency, snapshot chain completeness and destination capacity.
   Copy the **entire chain**, or construct a correctly referenced new chain;
   never `cp` only the active overlay.
3. Allocate unique VM names, UUIDs, MACs, storage paths, guest static IPs,
   CAPE machine entries, guest hostname/identity, and independently valid
   rollback targets. Apply policy **after** those allocations and before VM
   startup. Beware guest Windows activation, guest identifiers and cloning a
   running guest. Confirm destination disk XML references the expected image.
4. Run `--mode plan` then `--mode apply` per guest; if unsupported or
   conflicting, **stop that VM**, do not disable AppArmor or file locks and do
   not silently grant `chmod 777` or alter snapshot disk ownership.
5. Run a separate, containment-gated `virsh start`, verify it remains running
   and boots a harmless validation workload; if startup fails, collect QEMU,
   AppArmor and Unix DAC evidence in one report. A genuine concurrent disk
   lock must never be bypassed with QEMU unsafe `-U` sharing flags.
6. Confirm each guest's CAPE/agent integration, network-isolation negative
   tests, safe snapshot restore/restart and post-reboot behavior. Track
   operation state in a durable journal and provide a human-recoverable failure
   report. Do not claim rollback is transactional across every host change.

This helper deliberately **does not** create clones, modify Windows, start
or stop guests, connect networks, install hypervisors, touch image contents,
change `qemu.conf`, disable AppArmor, or run samples. It is one building block,
not the completed Command 2. There is **no zero-error guarantee** across
unverified distributions, custom hypervisors, permission models or hosts.

## Testing and release status

The offline unit tests exercise chain validation, safe policy rendering,
idempotence, conflict refusal and rollback on parser failure:

```bash
python3 -m unittest discover -s scripts -p 'test_guard_vm_backing_access.py' -v
```

GitHub CI does not use real libvirt disks, load AppArmor, or boot Windows.
Required before marking production-ready: independent destination-host tests,
AppArmor profile generation/reboots, snapshots that share bases, DAC identities,
parallel VM starts, concurrent locks, interruption/retry, new-host permissions,
NAT/bridge containment, CAPE integration, and safe snapshot restore.

**Repository branch:** `development` only; SSL-55 has not been modified by
these repository commits.
