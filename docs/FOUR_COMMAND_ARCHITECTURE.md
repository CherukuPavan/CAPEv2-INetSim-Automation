# Four-command CAPEv2 + INetSim architecture (revised 2026-10-09)

**Branch:** `development`. **Canonical build:** SSL-55 manual host/Windows master.
**Release status:** NOT a finished production installer. Offline tests are not a
substitute for an actual fresh-host build, clone boot, isolation and recovery test.

## Exact four-command contract

| Command | Responsibility | Handoff | Current implementation |
| --- | --- | --- | --- |
| **1 — Host + master** | Discover actual host OS, CPU virtualization, resources, network/uplink, users, packages, hypervisor and CAPE dependencies; safely install/verify approved missing components; create one configured Windows 11 master `win11`; install approved in-guest software/CAPE agent, assign static IP, validate harmless host↔guest connectivity; create analysis running-state snapshot and independent shut-off clone-source backup, verify chain and restart. | Host-specific, read-only **master checkpoint** with actual cold snapshot, UUID, disk chain and evidence. | **PARTIAL:** prereq/source/virt audits and conditional installers exist in `command1_pre_vm.sh`; `master-checkpoint` now validates the actual completed guest's snapshot structure. Custom QEMU/SeaBIOS/CAPE base installation and unattended Windows guest preparation/GUI/hardening/snapshot creation are **not** yet fully automated. |
| **2 — Clone N VMs** | Ask for N, use this host's **own** verified cold master snapshot, create independent `win11_1`…`win11_N` disks/VM identities, customize each Windows static IP before networking, preserve installed guest apps/packages, perform benign ping and genuine CAPE-agent `curl`, create/restore/test a per-clone analysis snapshot, maintain logs. | Root-private **Command 3 handoff** with verified VM names, IPs, libvirt UUIDs, snapshot names and bridge. | **DEVELOPER-STAGE:** `command2_clone_vms.sh` (read-only plan by default, explicit `--apply`); synthetic/offline CI checks. No SSL-55 clone deployed yet. Missing physical-host acceptance/dependency/isolation approvals. |
| **3 — CAPE finalization/UI** | Read and independently revalidate Command 2 handoff, update machinery `kvm.conf` and any required CAPE configuration, resolve stale registration, validate snapshots and paths, start/restart only approved CAPE services, verify CAPE web UI and benign analysis task. | Functioning CAPE interface and separately verified analysis readiness; malware samples **only** under approved containment. | **RESERVED.** User will perform/document the canonical manual process after Commands 1 and 2 are developed and accepted. No existing host configuration should be changed automatically by Command 2. |
| **4 — INetSim** | Provision/configure the isolated INetSim service or dedicated Ubuntu VM as the approved design specifies; connect CAPE guests exclusively through verified segregated network; exercise simulated DNS/HTTP/etc., deny live campus/public Internet and prove negative egress. | Verified INetSim network plus repeatable report/recovery instructions. | **RESERVED.** Implement only after the user records Command 4's actual working manual procedure. |

**The order above is intentional:** Command 2 does not edit `kvm.conf` or
restart CAPE, and Command 3 does not silently install INetSim. A non-forwarded
analysis network is required **before any Command 2 guest boot**, regardless of
whether INetSim is deferred until Command 4. CAPE UI alone does not certify
suitability for live malware execution.

## Machine-portability invariants

Each supported host builds **its own first master VM** using Command 1. Then
Command 2 discovers the actual libvirt UUID, cold snapshot, QCOW2 backing
chain, OVMF firmware/NVRAM, TPM, disk capacity and network. No golden disk or
compiled package is blindly copied from SSL-55 to another physical host.
No hardcoded `enp0s31f6`, `eno1`, `virbr0`, Windows disk path or snapshot
name is a portability substitute.

- Windows **libvirt** name: `win11` master; clones `win11_1` ...;
  Windows **hostname** uses distinct valid identifiers like `WIN11-1`
  (Windows hostnames do not accept `_`).
- Install-state inheritance comes from the independently exported Windows
  disk image, not reinstalling each app. Clone **storage, UUID, MAC, IP,
  hostname, UEFI NVRAM, TPM state and snapshots** necessarily differ.
  Software whose activation relies on TPM, SID, hardware identifiers or
  licensing requires independent validation; disk copying cannot guarantee
  everything behaves identically.
- A master shutdown snapshot can have multiple backing layers and a prior
  running RAM snapshot. Do **not** copy only the top overlay, merge/rebase
  the master, mutate a shared base, or restore the master during automation.
  A flattened independent clone disk is the safer proposal.
- The master static IP exists **inside Windows**. The current proposed
  implementation uses offline `virt-win-reg` on a *new clone disk* before
  the clone is attached or started. Libguestfs warns that editing Windows
  Registry and unsupported guest combinations can make a VM unbootable:
  real-host tests must confirm this first.
- Guest agent `ping` plus `curl` must come from the CAPE host via the
  **intended isolated bridge** and match the exact cloned MAC. Replies
  from a different machine are failure, not success.
- An OS-level no-forward libvirt network is necessary but insufficient
  proof of isolation. Test guest IPv4/IPv6 egress, host/campus connectivity,
  Docker/VPN bridges, local proxies, routing, forwarding, DNS and firewall
  behavior before running live samples. Never disable host security for
  installer convenience.
- The reference machine is a shared college host. Do not change unrelated
  student VMs, packages, network bridges, IP allocations, system accounts or
  global security policies. A newly created failed VM may be stopped only
  after verifying ownership and its deterministic UUID.
- Explicit `--plan` must not start, define or change any guest.
  `--apply` must check prerequisites, refuse duplicate paths and guard
  concurrent runs. A VM/host failure can still require operator review:
  **zero failures cannot be promised**.

## What is verified / what is not

**Operator-verified on SSL-55:** one hardened/configured Windows 11 master,
successful basic Ubuntu↔Windows reachability, both running and shut-off
snapshots, and restored Windows startup after AppArmor `rk` backing-image
exception. A read-only audit identified `finalshutoffversion` as the
current cold snapshot and a four-layer backing chain.

**Not yet physically validated by the automation:** fresh Ubuntu host
installation start-to-finish, complete guest-app/registry automation, clone
boot with fresh TPM/NVRAM, actual guest IP change, safe analysis network,
repeated clone snapshot rollback, concurrent N VM performance, CAPE machine
registration, live malware containment, and INetSim installation.

**Known reference host obstacles:** `default` libvirt NAT, stale CAPE
`cuckoo1` registration, missing QEMU guest agent channel, libguestfs
Registry-tool availability/compatibility unknown, approximately 250 GiB
free at last audit, and several custom host-installed virtualization
components. Offline tests cannot resolve these.

## Development-stage operator entrypoints

```bash
# Command 1: existing pre-VM tools and finished-master checkpoint
bash scripts/command1_pre_vm.sh audit
bash scripts/command1_pre_vm.sh master-checkpoint --vm win11

# Command 2: interactive VM count, read-only plan by default
bash scripts/command2_clone_vms.sh --plan
# Only after approved host-specific profile & isolated network acceptance:
# bash scripts/command2_clone_vms.sh --apply

# Command 3: RESERVED — pending verified manual CAPE configuration/UI steps
# Command 4: RESERVED — pending verified INetSim manual steps
```

The Command 2 profile sample is
[`config/command2-profile.example.json`](../config/command2-profile.example.json).
It contains placeholder documentation IPs and **cannot be applied as-is**.

## Next implementation milestones

1. Replace remaining risky upstream QEMU/CAPE base installer behavior with
   version-pinned, idempotent, least-impact Command 1 automation. Add
   Windows unattended/guest-prep checkpoints with actually supported media,
   license and guest agent version; audit final snapshots.
2. Verify Command 2's master checkpoint parser, offline Windows Registry
   editor, clone source export, per-VM firmware/TPM, MAC-IP allocation and
   AppArmor startup on SSL-55 using harmless tests only.
3. Obtain evidence of a non-NAT/isolated libvirt analysis bridge without
   disrupting the shared host; verify IPv4 and IPv6 negative egress.
4. Run an isolated **single clone** full lifecycle first, then 2 clones,
   then bounded requested N; test error interruption and reboots before
   claiming portable deployment.
5. After Commands 1–2 reach acceptance, start user's Command 3 manual
   recording. Complete and certify Command 4 only after the separate
   INetSim setup evidence.

Cross-machine support requires an actual independent fresh-host test,
not simply dynamically reading a hostname or network interface.
