# Step 7 — Final network, group and host-security diagnostics (SSL-55)

**Date of user-run observation:** 2026-10-09. **Source:** `SSL55_Step7_FinalDiagnostics_20261009_030314.txt`, user-uploaded read-only report, 67 physical lines (68 displayed/indexed). **Result:** confirmed default NAT exposure and host-persistence/security issues. This is evidence about SSL-55 **only**.

No host changes were performed by the assistant. Do not publish the uploaded file's institutional uplink/subnet addresses, libvirt UUID or MAC, usernames other than the already public installation reference, or credentials. This document summarizes only necessary generalized facts.

## Confirmed observations

| Area | Result from uploaded report | Interpretation and action gate |
|---|---|---|
| Libvirt network status | `default`: active **yes**, persistent **no**, autostart **no**, bridge `virbr0` | A **transient** network definition; active does not mean durable across libvirt restarts or reboot. Do not make existing NAT default persistent merely to clear a check. |
| Libvirt network XML | `<forward mode='nat'>`, bridge `virbr0`, IPv4 `192.168.122.1/24`, DHCP guest range within that subnet | **NAT positively established**, not merely inferred from its name. This network is **not approved for live malware-analysis guests**. XML alone cannot prove full containment even if forwarding were removed. |
| Bridge operational display | `virbr0 DOWN 192.168.122.1/24`, route to bridge subnet has `linkdown` | No guests have been reported attached. A disconnected virtual bridge may show no carrier/operational DOWN; not automatically proof of libvirt malfunction. Do not force it UP from this observation alone. |
| Host routes | Ethernet `enp0s31f6` default metric **100**, Wi-Fi `wlp0s20f3` default metric **600** | There are **two** default routes. Lower metric makes Ethernet the expected main-table choice, corroborating the user's earlier `ip -4 route get 1.1.1.1` result. Routing can change due to policy, metrics, link and target; avoid assuming unique permanent uplink. |
| Existing Docker networks | Existing container bridge routes remain visible | Important preservation constraint. Do not flush firewall, rename existing bridges or pick overlapping isolated guest subnets. |
| Non-root account groups | User account database lists `kvm` and `libvirt`, current `id` session does **not** | Account membership is set but session credentials have **not refreshed**. A new authenticated login (when appropriate) typically refreshes supplemental groups. Do not add redundant membership entries or treat `sudo virsh` as proof of unprivileged access. |
| KVM module configuration | First line `-e blacklist kvm_intel` is **invalid syntax**; second is valid `blacklist kvm` directive | Can produce libkmod parse errors and influence automatic module loading after reboot. Working KVM now does **not** prove persistence. Inspect intended local/security policy and back up before manually fixing; do not blindly delete a legitimate intentional blacklist. |
| Active security sysctl | `net.ipv4.tcp_syncookies = 0` | Kernel SYN-cookie protection **disabled**; not an appropriate production default for this host without an explicit separate security policy. |
| Persistent sysctl matches | `/etc/sysctl.conf:77` and `/etc/sysctl.d/99-sysctl.conf:77` both report `net.ipv4.tcp_syncookies = 0` | **Do not assume these are separate files.** On Ubuntu they can be symlinked or otherwise equivalent. Check canonical paths/inodes and precedence before proposing an approved one-time backup/change. |
| Sleep/power policy | Four targets are masked | Confirmed installer-wide setting; whether allowed depends on workstation/server policy. Do not unmask or preserve this as a universal default automatically. |
| Guest analysis isolation | No test of Windows guest, INetSim guest, host firewall, IPv6, service pathways or unauthorized LAN reachability | **Not verified.** No malware execution permitted by this report. |

## Refined interpretation of Step 7

The **previous** post-build report (user-run, same date) confirmed QEMU 9.2.2, libvirt 11.1.0 system connection and KVM acceleration. The **new** report conclusively shows that the active `default` network has NAT enabled. This is not a contradictory conclusion: hypervisor command-line functionality can be healthy while the guest network remains unsafe/ephemeral and host settings need correction.

No Windows VM has been evidenced. `virbr0 DOWN` may be due to no attached guest, so avoid treating it as its own installer failure. Distinguish **host outbound route** from **guest-analysis network**: `INTERNET_IFACE=enp0s31f6` on SSL-55 is supported for a destination-specific host route, but does not authorize NAT or Internet access for live analysis guests.

## Safe manual remediation proposal — requires user approval and change plan

**No commands below are instructions to run immediately, and no modifications have been made.** Before any authorized reboot:

1. **KVM module configuration:** Confirm file contents and expected module-loading policy. Back up this specific file; fix its malformed `-e` prefix without converting a real blacklist into an unintended allowance. Review necessity of `blacklist kvm` in the proposed KVM-using host. After correction, perform a read-only `modprobe` configuration validation and schedule functional verification after an explicitly authorized reboot.
2. **Host SYN cookies:** Check whether `/etc/sysctl.d/99-sysctl.conf` and `/etc/sysctl.conf` are the same underlying file (`readlink -f`, `stat`) and identify effective sysctl precedence. If the host security owner approves, back up the canonical configuration and restore a reviewed safe setting (typically `net.ipv4.tcp_syncookies = 1`); verify active and persistent values. Do not invoke a blanket `sysctl --system` on this mixed-configuration host without reviewing other settings first.
3. **Account login:** On an appropriate user-controlled occasion, use a newly authenticated login to refresh membership; verify `id`, `/dev/kvm` permissions and non-root libvirt access. Do not restart libvirt merely to refresh user group credentials.
4. **Guest network:** Do not autostart/persist the **NAT default** solely for CAPE. Design a **separate**, no-uplink malware-analysis libvirt network and safe INetSim service topology, validate nonoverlapping CIDR, bridge and host firewall. Runtime negative connectivity tests (LAN, Internet, Docker, host management, IPv4/IPv6) are required; no VM execution before the containment gate passes.
5. **Power management and reboot:** Compare masked targets and GRUB changes to the intended local host policy. Any reboot must be explicitly approved and preceded by recovery/console access planning. After reboot verify QEMU/libvirt/KVM functionality, intended networks and routing again.
6. **Package/firmware issues:** The earlier source build purged packaged libvirt and force-overwrote firmware descriptors; follow up with version/ownership validation before more package operations. Do not rerun `kvm-qemu.sh all` as a repair.

## Automation acceptance criteria

- Parse existing libvirt XML and detect **any** `<forward>` for a candidate isolated analysis network. Explicit `mode='nat'` is an immediate fail for that role. Confirm network definition persistence separately from runtime active status; do not implicitly select the distro's `default` network.
- **Separate preflight roles:** assess host uplink/routing for controlled administration only; check analysis network bridge/listener IP, DHCP, firewall and approved INetSim service paths independently. Account for multiple default routes, route metrics, policy rules and future changes.
- Detect inoperative/no-carrier guest bridges but don't equate DOWN with a broken configuration until expected guest attachment and interface lifecycle are considered.
- Validate user **database** and **current session** supplemental groups separately; don't mistake a source-built libvirt runtime for missing packages.
- Detect malformed modprobe lines/blacklist policy and security regressions such as `tcp_syncookies=0`; fail with a precise reason rather than silently overwrite institutional policy. Detect sysctl symlink/alias/precedence to avoid unintended duplicate modification.
- Avoid auto-starting/auto-persisting default NAT, disabling SYN-cookie protection, globally masking sleep, forcing apt package ownership changes, or rebooting merely to make scripts exit successfully.
- Report observed topology and settings in private, redacted logs only. Require fresh supported Ubuntu host and real guest isolation tests before releasing final three-command deployment.

## References within repository

- [STEP_LOG.md](STEP_LOG.md) — canonical user-executed step history.
- [STEP7_POSTBUILD_AUDIT.md](STEP7_POSTBUILD_AUDIT.md) — preceding runtime verification.
- [DYNAMIC_NETWORK_DISCOVERY.md](DYNAMIC_NETWORK_DISCOVERY.md) — host uplink selection versus dedicated analysis bridge.
- [LIBVIRT_NETWORK_STEP6.md](LIBVIRT_NETWORK_STEP6.md) — initial libvirt baseline and CAPE configuration.
- [PORTABILITY.md](PORTABILITY.md) — fresh Ubuntu safety and dependency constraints.

**Status:** Step 7's QEMU/libvirt/KVM basic runtime checks passed previously; **final host configuration, network containment and post-reboot persistence remain unresolved**. No host-side action is implied by this documentation.
