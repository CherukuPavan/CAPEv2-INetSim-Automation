# Command 2 — portable target-host preflight (development only)

**Status:** READ ONLY, tested with mocked host profiles, NOT yet accepted on
any real fresh deployment machine. DO NOT create additional VMs on SSL-55.
No software installation, libvirt domain definitions, NIC changes,
firewall rules, snapshots, VM shutdown, TPM reads, or malware execution.

## Purpose

The eventual portable Command 2 must work on a **separate approved host**
with a freshly completed Command 1 Windows master and a verified,
standalone Windows template. It must not assume the Ubuntu host has the
same Ethernet name, routes, subnet allocations or storage paths as SSL-55.
A VM count is the TOTAL desired count: 5 plans win11_1..win11_5.

New development component:
- scripts/command2_target_host_preflight.py
- scripts/test_command2_target_host_preflight.py

The preflight uses /etc/os-release, /proc/cpuinfo, /proc/meminfo,
statvfs, /dev/kvm and read-only virsh and ip commands to discover:
1. Candidate Ubuntu release (22.04 or 24.04, **not yet real-host certified**),
   x86_64, exposed VMX/SVM, /dev/kvm existence and current-user access.
2. Presence of virsh, qemu-img and ip (missing items become **blockers**;
   future Command 1/bootstrap must install/configure them where approved).
3. Existing win11 master in shut-off state and a regular independent
   64-GiB QCOW2 source template using qemu-img info metadata only;
   actual guest identity and cleartext verification remain separate gates.
4. Read-only libvirt domain names and target artifact-path collision checks.
5. Usable available memory (minimum planning assumption 4096 MiB per
   guest + 8192 MiB shared-host reserve; this is a planning heuristic,
   NOT the final host hardware sizing specification).
6. Storage free on the target disk directory. Conservative plan uses
   N*64 GiB virtual-disk maximum + 30 GiB reserve, NOT actual QCOW2
   allocated size or proof of adequate performance.
7. Existing IPv4 routes, host interface addresses and all libvirt IPv4
   subnets, including inactive libvirt networks. Any overlap with the
   proposed analysis subnet **blocks** the plan. This does not change
   routing or firewall configuration and it does not establish egress
   isolation. IPv6 overlap/egress is NOT yet tested.
8. Kernel-only read-only outbound route lookup:
   ip -j -4 route get 1.1.1.1.
   This does NOT send packets to 1.1.1.1. The chosen **interface
   name** is extracted dynamically (eno1/enp0s31f6/wlp...), without
   logging campus source IP or next-hop values. Never hardcode
   SSL-55's enp0s31f6 into the portable program.
10. If the requested analysis CIDR overlaps a host route, assigned
   address or existing libvirt network, the plan **fails closed**. It
   may recommend a free candidate from a limited private-subnet pool,
   but it does NOT automatically replace the explicitly requested CIDR,
   assign guest IPs, or configure networking. The operator must approve
   any nondefault subnet and the subnet candidate is not a full
   IPv6/egress safety proof.
9. Immediate refusal when hostname identifies the SSL-55 reference host
   (defense-in-depth only; any future write-capable entrypoint requires
   stronger operator/host authorization).

## Example — only on a future separate approved host

After the prior Command 1 outputs and paths have been inspected:

    python3 -B scripts/command2_target_host_preflight.py \
      --count 5 \
      --disk-dir /var/lib/libvirt/images/cape-analysis \
      --nvram-dir /var/lib/libvirt/qemu/nvram \
      --template /path/from/command1/verified_template.qcow2 \
      --subnet 192.168.240.0/24

The example paths are placeholders, not instructions to make these
directories or fetch/modify the template. The program only inspects.
A printed "preflight_pass: true" means only THESE discovery checks passed;
"deploy_authorized" remains false. Failure exits nonzero and returns
machine-readable blockers. Sensitive network addresses and swtpm data are
never intentionally printed. There is no need to execute this on SSL-55.

## Unfinished portable deployment gates

- Actual supported Ubuntu/libvirt/QEMU/swtpm/OVMF compatibility and
  hypervisor permissions, including install/bootstrap if missing.
- Source Windows template provenance, software/BitLocker readiness,
  protected master proof and independently prepared swtpm identity.
- Per-host resource tuning, CPU scheduling, configurable and verified
  VM RAM/CPU sizes; swap/CPU oversubscription policy.
- Dedicated no-egress lab network, persistence guards without flushing
  Docker/libvirt rules, runtime IPv4+IPv6 negative and CAPE positive tests.
- Proper guest-side Windows hostname/static-IP assignment, NIC GUID
  mapping after connection, initial boot/agent acceptance.
- Verified cold restore including QCOW2, dedicated UEFI, swtpm, and
  simultaneous analysis testing on a separate sufficiently provisioned host.
- Authenticated, documented staging action with irreversible-operation
  previews, crash-safety journals and idempotent resume.
- Real target-host and multi-VM acceptance evidence. The current model
  cannot certify that an arbitrary machine supports the deployment.

**Never interpret this preflight as permission to stage VMs or run samples.
SSL-55 will not be used for additional VM setup.**
