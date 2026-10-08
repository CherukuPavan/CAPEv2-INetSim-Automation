# Dynamic network discovery — Step 6 correction and portability requirements

**Last updated:** 2026-10-09. **Branch:** `development`. **Status:** Host uplink **read-only detector draft** has tests; isolated libvirt network provisioning and deployment integration remain **not implemented/validated**.

## Canonical SSL-55 correction

The original Step 6 `cape2.sh` assignment `INTERNET_IFACE=eno1` was later **superseded by a user-executed correction** to `INTERNET_IFACE=enp0s31f6`. The user also reported `ip -4 route get 1.1.1.1` selected `dev enp0s31f6`. The final settings shown in the user's terminal were:

```text
NETWORK_IFACE=virbr0
IFACE_IP="192.168.122.1"
INTERNET_IFACE=enp0s31f6
PASSWD=[REDACTED]
```

This evidence is for **one host at one time** and one route lookup destination. The lookup does **not** itself test whether the destination is reachable. It does not prove which interface an application will use for all destinations, VPN policy, or whether any Windows/INetSim VM is safely isolated. Do not commit the upload's institution-specific source/gateway IPs or the literal password.

## Role separation

- **`NETWORK_IFACE`**: CAPE capture/analysis network bridge used in its auxiliary configuration; this is **not necessarily** the host's egress interface.
- **`IFACE_IP`**: the corresponding guest-facing host/listener IPv4 address, discovered from selected libvirt network XML and host interface state.
- **`INTERNET_IFACE`**: host outward route/uplink, used only where the approved host workflow requires it. It must **never** be treated as blanket authorization for malware guests to use actual Internet connectivity.
- **Secret `PASSWD`**: do not echo, hardcode, commit or include in diagnostics. It is not the system login password. Rotate disclosed credentials where reused.

## Implemented now — discovery draft

`scripts/discover_host_uplink.py` uses standard Python 3 and `iproute2` commands to examine the actual host, without sending traffic or altering its networking:

1. `ip -4 route get <destination>` (default example `1.1.1.1`) identifies a **destination-specific** selected egress interface, source IPv4 and possible gateway. It supports the normal indented `cache` output from `ip route get`.
2. `ip -j -d link show` checks interface identity, administrative and reported link state, and recognizable Docker/libvirt/virtual bridge/tunnel types.
3. `ip -4 -j addr show` verifies that the route's source IPv4 is configured on the selected device.
4. `ip -4 -j route show default` checks whether there are multiple default routes/interfaces, even if metrics would favor one route.
5. `ip -4 -j rule show` identifies nonstandard policy routing requiring manual review.
6. The optional `--override IFACE` must identify an existing interface **and agree with the observed route for the requested target**; a conflicting override is not silently accepted.
7. The optional `--report /absolute/path.json` creates a new file using mode `0600`; it does not overwrite an existing file. Host IP addresses in this local report are sensitive infrastructure data and should not be published.
8. Result distinguishes `usable_as_host_uplink_candidate` from `internet_reachability_tested` and `safe_for_malware_analysis`. The latter two are always **false**, because no connection is made and no guest isolation is inspected.
9. Missing `ip`, JSON incompatibility, unavailable routes/interfaces or ambiguous topology cause a nonzero result with a diagnostic, not an automatic interface change.

A read-only example, **only when the user chooses to run it on a host**:

```bash
python3 scripts/discover_host_uplink.py --target 1.1.1.1
```

The module is a **preflight component**, not one of the three deployment entrypoints. Its exit 0 means only that the **host route candidate** passed the currently implemented checks; it is **never a malware-isolation certification**.

## Verified tests / limitations

- **19 isolated synthetic unit tests passed** on 2026-10-09 using anonymized interface IP fixtures, plus Python syntax check.
- A read-only smoke test also succeeded using the **separate test environment's** networking stack, not SSL-55.
- The committed modules match the locally tested Git file contents: `scripts/discover_host_uplink.py` blob `1912a1de101643b76be47b09c0d5756849556bcf` and `scripts/test_discover_host_uplink.py` blob `62deac977d7e2747d862e98498b1bc4d731dbead`.
- **Not tested:** actual SSL-55 read-only execution, supported fresh Ubuntu variants, Wi-Fi device hardware, VPN production policies, ECMP/multipath under all layouts, connectivity, privilege-specific routes, or changing/multi-namespace network configurations. Current selection is host-network-namespace and IPv4 specific; IPv6 is not implemented.

## Libvirt analysis network — outstanding implementation

The existing [read-only libvirt/CAPE network auditor](../scripts/audit_libvirt_cape_network.py) can analyze an **explicitly named** existing libvirt network from XML. Automatic isolated network selection/creation is **not implemented**. The final installer must:

1. Enumerate existing networks with `virsh -c qemu:///system net-list --all` and query each candidate's XML and state, verifying active, persistent, bridge name, IPv4 CIDR, DHCP and DNS as needed.
2. Distinguish libvirt **default NAT** networks from dedicated analysis networks with **no real-world forwarding**. Never treat `virbr0` or `192.168.122.1` as portable defaults for malware analysis.
3. Check host routes, firewalls (nftables/iptables/UFW), Docker bridges and existing libvirt networks for address overlap, routing, DNS and bypass paths.
4. Select or create **a dedicated** analysis network only under the approved deployment architecture after version/privilege/collision checks. Preserve unrelated virtual networks and host interfaces; support idempotent reruns, backups and recovery plans.
5. Update `NETWORK_IFACE` and `IFACE_IP` using the **actual verified guest bridge**, not the physical egress. Use version-aware CAPEv2 settings with safe secret injection; do not execute or source an untrusted installer simply to read values.
6. Verify with Windows and INetSim guest probes, including **negative attempts** to reach institutional LAN, host management, Internet and other external routes over both IPv4 and IPv6; prove guest INetSim access only on intended services.
7. Stop/fail closed if any containment test or permitted destination restriction fails. Never enable global forwarding/NAT for analysis guests by default.
8. Test fresh supported Ubuntu builds, preexisting software and partial failures before marking the final three-command automation production-ready.

**Next work stage:** Complete further user-led installation evidence and the final dedicated guest-network design, then implement and test the **authorized** configuration/provisioning stage. Read-only preflight code does not install dependencies; the future bootstrap must verify `python3`, `iproute2` and `libvirt-clients` and install missing supported packages only when authorized.

**Operational boundary:** No actions on SSL-55 were performed by the assistant. This GitHub change does not alter CAPEv2 runtime files, libvirt networks, or host firewall policies.
