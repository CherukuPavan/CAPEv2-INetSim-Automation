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
