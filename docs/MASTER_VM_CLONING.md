## 2026-10-09 — actual master inventory results

The operator supplied a final read-only inventory. **Source selection is now
evidence-based:** the VM was shut off, `finalshutoffversion` was current,
and the recorded state was `shutoff` with no saved RAM in that snapshot.
Its disk is the top of a **four-layer** QCOW2 chain:

```
finalshutoffversion -> Afterfull -> basicinstallwinsnapshot -> win11.qcow2
    current cold      parent RAM snapshot     older layer          base
```

The running-state `Afterfull` snapshot has an external memory file.
**Do not** use it as an ordinary cold-copy disk or delete that RAM file.
The snapshot state and clean guest shutdown make `finalshutoffversion`
the *candidate* for a consistent clone source, but the image requires a
controlled, read-only integrity and independent export check. A disk
snapshot does **not** automatically include swtpm private state or UEFI
NVRAM; future clones need their own valid state.

Other observed facts (without committing host-private identifiers):

- `/opt/CAPEv2/conf/kvm.conf` still lists `cuckoo1` and contains no entry
  for the actual master `win11`. Two legacy machine sections refer to the
  same guest IP. Correct CAPE machine/snapshot mapping must be validated
  before deploying additional analysis guests.
- The guest uses the libvirt `default` **NAT** network. NAT is not an
  isolation certificate; automatic analysis-VM startup stays blocked.
- The VM reports **no QEMU guest agent channel**. CAPE's Python agent is a
  separate service; no verified command-execution mechanism for guest IP
  changes is currently available to the automation.
- The master has 4 vCPUs, 4 GiB RAM, and a 64 GiB virtual disk. The
  reported destination filesystem had approximately **250 GiB free**
  during the inventory. As a deliberately conservative upper bound,
  count × 64 GiB plus a 30 GiB reserve supports only 3 clones on that
  filesystem. Sparse QCOW2 actual allocations may be less; no capacity
  relaxation is justified before measured independent-copy testing.

### Initial offline clone-plan module

`scripts/plan_vm_clones.py` is an **offline-only, fail-closed planner**.
It accepts the private master inventory and either `--count N` or an
interactive count prompt. It proposes deterministic unique VM names
(`win11_1`, `win11_2`...), libvirt UUIDs, locally administered MACs,
and optionally IPv4 addresses on an **explicitly named, inventoried**
network and subnet. It checks for collisions with the inventory's CAPE IPs,
existing machine registration, RAM/storage budget, snapshot consistency,
and NAT/forwarding indicators. It never starts or creates VMs.

For a read-only proposed plan with **no** guest IP allocation:

```bash
python3 scripts/plan_vm_clones.py \
  --inventory /PATH/TO/private_master_inventory.txt \
  --count 2 \
  --output "$HOME/cape_clone_plan_$(date +%Y%m%d_%H%M%S).json"
```

A proposed IP range can be supplied **only after** an approved isolated
network and addressing plan is established (use `--network`,
`--subnet`, `--first-ip`, `--master-ip`, `--reserved-ip`). Neither
a plan nor a custom-created network proves containment. An unknown
network, one marked NAT/forwarding, absent CAPE master mapping or guest
IP-customization mechanism causes a blocking result.

The plan result will intentionally remain `BLOCKED_NOT_DEPLOYABLE`
until those remaining release gates are implemented and tested. Candidate
IDs/IPs are proposals, not actual verified or reserved allocations.
Future apply mode must reconcile real libvirt definitions, CAPE entries
and DHCP/ARP/host observations before allocating them. Do not feed this
plan directly to `virsh define` or start any proposed guest.

### Cold-master disk export module (offline-only stage)

`scripts/export_cold_master_disk.py` is an optional **explicit**
cold-source exporter, with safe-by-default `--mode plan` and separate
`--mode export`. It does not create a domain or touch the original.
It requires a verified shut-off master, the *current* shut-off snapshot,
a complete externally backed QCOW2 chain, one source disk and an unused
`*.qcow2` target path in an **existing root-controlled directory**.
The plan checks conservative free space (full 64 GiB virtual capacity
plus 30 GiB reserve) and files, and refuses to clobber existing data.

The export operation uses QEMU's regular image locking (never `-U`)
to flatten the chain through `qemu-img convert` into a temporary file.
It checks the new image and its absence of a backing dependency, checks
that the master remains shut off and the source images are unchanged,
then publishes the output without overwriting an existing path.
Failure attempts to remove only the temporary output. Interrupted
processes or concurrent operations can still require manual
investigation; this is not a transactional snapshot-backup system.

**Do not run export on SSL-55 yet.** We have reviewed the inventory and
synthetic tests, but we have not audited live CAPE activity/snapshot
writers, destination disk ownership, or applied source-integrity checks
on the physical host. This is an implementable building block rather
than approved unattended deployment.

When approved, commands follow this pattern (paths are illustrative,
not precreated):

```bash
sudo python3 scripts/export_cold_master_disk.py \
  --vm win11 --snapshot finalshutoffversion \
  --output /APPROVED/SECURE/STAGING/win11_1.qcow2 --mode plan
# Only after confirming safeguards and capacity, explicit authorized action:
# sudo python3 scripts/export_cold_master_disk.py ... --mode export
```

**Do not boot an exported disk before Windows guest identity/static IP,
UEFI NVRAM, TPM state, domain XML, CAPE registration, and isolation
have been established.** It is a private staging image, not a ready
analysis VM. A flattened image is independently copyable, but will not
reproduce libvirt's parent snapshot metadata or the running snapshot's
RAM state; per-clone analysis/rollback snapshots must be created later.

### Status of the implementation

**Implemented and offline-tested:** master inventory parsing, snapshot
metadata/source checks, candidate VM identity and IP planning, collision
and high-level resource checks, and the separate QCOW2/AppArmor backing
access guard.

**Not yet implemented end-to-end:** deployable source export with physical-host acceptance, complete clone VM definition,
UEFI/swtpm duplication/re-initialization, offline Windows hostname/IP
customization, true isolated network validation, CAPE registration,
guest snapshot creation, rollback and cross-host validation. The
three-command installer remains incomplete and is not production-ready.

The user does not need to reconfigure the completed master simply to
allow *planning*. Any eventual temporary guest access needed to set
unique static IPs will require a separately verified, guest-specific
mechanism that cannot expose several identical-IP clones on one network.


---

# Windows 11 master-to-clones: evidence collection and release gates

## Verified origin

SSL-55's `win11` Windows 11 Pro guest was manually configured/hardened by the
operator. On 2026-10-09 the operator reported completed static networking,
agent setup, successful Ubuntu-to-Windows curl/ping checks, and **two final
snapshots: one of a running VM intended for CAPE's kvm.conf and a separate
shut-off backup**. Those latest snapshot names, storage types, memory handling,
and CAPE entries have not yet been independently inspected by automation.

A previous snapshot chain was `win11.Afterfull ->
win11.basicinstallwinsnapshot -> win11.qcow2`. Its backing-image AppArmor
access required `rk` (read + lock). It is **not safe** to assume those
remain the currently selected snapshot names or images.

## Stage 1 — Gather a single read-only report

From a checked-out `development` branch on SSL-55, while the master remains
in its normal state:

```bash
cd /PATH/TO/CAPEv2-INetSim-Automation
git switch development
sudo -v
python3 scripts/audit_clone_master.py --vm win11 \
  --report "$HOME/win11_master_clone_inventory_$(date +%Y%m%d_%H%M%S).txt"
```

The script outputs exactly one **private, mode-0600, JSON-formatted TXT file**.
It uses `sudo -n virsh` only for **read-only** operations and never calls
`virsh start`, `virsh shutdown`, `virsh snapshot-revert`, `qemu-img convert`,
`guest-exec`, any networking mutation, or any package installer.

It records the persistent VM's storage, network, TPM and guest-agent
configuration, libvirt snapshot state/parents/memory/disk metadata,
VM-attached networks and whether NAT/forwarding is configured. It also
reads only allowlisted CAPE KVM machine fields (name, label, IP, snapshot,
platform, interface) from recognized installation paths, never passwords or
complete config contents. If none of the paths is accessible, it records
that as unverified rather than guessing. When the
VM is **running**, it intentionally skips `qemu-img info` on the active
disk to avoid touching a potentially in-use image; if shut off, it attempts
a read-only backing-chain inspection. Any CAPE machine list or static
Windows IP requires separate verification. Report paths, MACs, addresses,
hostnames, UUIDs and network names can be sensitive: review the report
before sharing outside the development collaboration.

**Known limitation:** `domifaddr --source agent` works only if the QEMU
guest agent (distinct from the CAPE agent) is installed and reachable.
Lack of QGA must not cause automatic activation of the same static IP in
multiple clones.

## Stage 2 — Choose and verify the clone source (not yet implemented)

A CAPE running-state snapshot and a cold, powered-off backup have different
semantics. The cloning source must be demonstrably consistent:

- Running-state snapshot may include RAM state, TPM/NVRAM state and an
  external disk overlay. Raw copying of an active overlay is forbidden.
- Shut-off backups can be safely copied only once verified consistent,
  independent of any writer, and with all required base/backing disks.
- Cloned VM NVRAM and swtpm storage must not accidentally be shared.
- Preserve the original source, write clones to fresh paths only and
  never rebase/rewrite the master image.
- Inspect live vs inactive domain XML, **actual** running-state memory,
  disk chain and backup snapshot metadata before selecting a source.
- If neither backup is a verified consistent clone image, stop and request
  a supported cold export rather than inventing a procedure.

## Stage 3 — Unique machine provisioning (design contract)

Required unique fields per destination include:

`win11_1`, `win11_2`, ...; libvirt UUID; per-NIC MAC; clone storage
paths; UEFI variable store; swtpm storage/identity; Windows hostname;
Windows static IPv4/mask/gateway/DNS; CAPE `kvm.conf` machine identifier
and snapshot mapping; and routing/agent reachability. Windows activation
and guest identity mechanisms must be reviewed.

The Windows IP is **inside the guest**. Changing a libvirt MAC or CAPE
registration does NOT change the Windows static IPv4 configuration. Clones
must be isolated from one another until IP customization is complete and
verified. Use only an explicitly tested guest-configuration mechanism
(e.g. preinstalled QEMU guest agent with authenticated restricted
management and one-at-a-time provisioning). Without such a mechanism,
automated parallel cloning must **stop**, not start identical-IP guests.

## Host/network gates

- Supported Ubuntu/libvirt/QEMU versions, kernel, available disk/RAM/CPU,
  source QCOW2 chain hashes or equivalent integrity provenance.
- Isolation from campus LAN, public Internet and unintended services,
  including IPv6, routing and bridges, with guest-side negative tests.
- Correct per-destination AppArmor read+lock rules *and* DAC file access.
  The existing guard is a preparatory component and uses a **shared**
  abstraction, so multi-VM policy design still requires safety review.
- Agent reachability and working snapshot rollback for **each** clone.
- Support crashes, reruns, exhausted disk, duplicate IP/VM/MAC, partial
  setup, conflicting runtime locks, libvirt/NVRAM/TPM and CAPE failures.
  Failed clones must not interfere with the original.
- Use benign connectivity tests only until institutional authorization
  and containment requirements in `LIVE_MALWARE_CONTAINMENT_POLICY.md`
  have been independently satisfied.

The final planned three-command workflow is still under development.
This stage collects facts and prepares a safe deployment design. Do not
assume that the only machine-dependent field is the Windows static IP:
host interface, paths, libvirt user, QEMU capabilities and several unique
guest identifiers also vary.

See `VM_BACKING_ACCESS_GUARD.md`, `PORTABILITY.md` and `WORKFLOW.md`.
