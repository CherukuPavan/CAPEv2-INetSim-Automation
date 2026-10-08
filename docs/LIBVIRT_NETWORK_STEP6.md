# Step 6 — Libvirt packages, default bridge, and CAPEv2 configuration: safety audit

**Status:** User-led manual commands are recorded from the uploaded terminal transcript. **No malware-ready network has been verified.** The automation work is an early **read-only diagnostic draft**, not a deployment command or permission to operate live samples.

## Grounded manual evidence

Source: user-uploaded terminal text (523 displayed lines in the attachment), plus a screenshot suggesting packages and a default-network activation workflow. Only commands actually present in the terminal transcript count as **performed**. The uploaded log contained a **real-looking secret** in the `PASSWD` setting. **Its value is intentionally omitted from all project files**, test cases and example commands. It must not be used as a project default.

Chronological user-performed commands:

```bash
sudo apt update
sudo apt install -y libvirt-clients libvirt-daemon-system
sudo virsh net-list --all
ifconfig
cd ~/CAPEv2/installer
sudo sed -i 's/^NETWORK_IFACE=.*/NETWORK_IFACE=virbr0/' cape2.sh
sudo sed -i 's/^IFACE_IP=.*/IFACE_IP="192.168.122.1"/' cape2.sh
sudo sed -i 's/^INTERNET_IFACE=.*/INTERNET_IFACE=eno1/' cape2.sh  # first value, later superseded
# The user also changed PASSWD using sudo sed with a literal secret;
# REDACTED: never reproduce/commit that command's original secret.
grep -E '^(NETWORK_IFACE|IFACE_IP|INTERNET_IFACE|PASSWD)=' cape2.sh
# Correction completed later, after destination-specific routing check:
ip -4 route get 1.1.1.1
sudo sed -i 's/^INTERNET_IFACE=.*/INTERNET_IFACE=enp0s31f6/' cape2.sh
grep -E '^(NETWORK_IFACE|IFACE_IP|INTERNET_IFACE|PASSWD)=' cape2.sh
```

The screenshot suggests `sudo virsh net-start default` and `sudo virsh net-autostart default`, **but neither command is in the terminal transcript**. The actual observed `virsh net-list --all` output already showed the network `default` **active / autostart yes / persistent yes** after package installation. Do not record the two start/autostart commands as performed.

### Verified installation state (user-supplied terminal evidence only)

- APT installed `libvirt-clients`, `libvirt-daemon-system` and dependencies, including `libvirt0` `10.0.0-2ubuntu8.19`, `qemu-system-x86` `1:8.2.2+ds-0ubuntu1.18`, `seabios` `1.16.3-2`, `ovmf` `2024.02-2ubuntu0.10`, and supporting packages.
- Package transaction: **51 new packages, 2 upgrades (`libxml2:amd64` and `libxml2:i386`), 0 removed, 195 not upgraded**. APT metadata refresh had previously shown **197 upgradeable packages**. No `apt autoremove` was performed.
- Libvirt services and default network were enabled by package setup; the transcript includes `update-initramfs` and socket/service symlink creation.
- `virbr0` was shown with `192.168.122.1/24`; `enp0s31f6` and `wlp0s20f3` were active uplink candidates. Existing Docker bridges persisted. Site-specific host addresses/MACs are **not reproduced in GitHub**.
- `cape2.sh` echoed these changed settings:
  ```text
  NETWORK_IFACE=virbr0
  IFACE_IP="192.168.122.1"
  INTERNET_IFACE=enp0s31f6
  PASSWD=[REDACTED]
  ```
  **Updated after the user's correction.** The earlier `eno1` setting is superseded, not the current SSL-55 state. The user-supplied `ip -4 route get 1.1.1.1` output selected `enp0s31f6`, supporting the route decision for that destination only. This **does not prove Internet connectivity** or service reachability. No `cape2.sh` installer execution was supplied for this step.

### Important unresolved problems (must not silently "fix")

1. **Uplink setting corrected:** The earlier `eno1` assignment did not match any observed interface; the user subsequently set `INTERNET_IFACE=enp0s31f6` after `ip -4 route get 1.1.1.1` selected Ethernet. This resolves the configuration typo **for the observed destination**. Internet connectivity, alternate destinations, multiple default routes, policy routing and future interface changes still require checks. Do not assume a singular default route or rename interfaces.
2. **NAT is not malware isolation:** The standard libvirt `default` network is normally **NAT-forwarded**, with guest outbound access. `virsh net-list` and `ifconfig` do **not** show forwarding policy, so actual XML/host forwarding was not verified from the uploaded log. The official [libvirt network XML reference](https://libvirt.org/formatnetwork.html) documents `default` with `<forward mode='nat'/>`, and the difference between NAT and networks with no `<forward>`. **Never attach an analysis VM used for malware to default NAT without a separately validated containment design.** Dedicated non-forwarding analysis network, INetSim integration, firewall/routing checks and guest negative-connectivity tests remain mandatory. Do not destroy an existing default network or apply global firewall resets.
3. **Password disclosure:** The `PASSWD` assignment in the uploaded log contains a literal credential. Upstream `cape2.sh` uses this value for PostgreSQL account/connection configuration and some password-protected operations. It is **not simply a Linux login password**. Do not commit or echo its value. Rotate the supplied credential wherever reused and later in dependent services if provisioning already occurred. Future automation must generate/obtain and store secrets through a reviewed method, avoid command-line and shell-history disclosure, and protect any generated settings.
4. **Mixed APT suites:** `apt update` reported Ubuntu `noble` (24.04) *and* older `focal` (20.04) repository entries, plus third-party `jammy` MongoDB repos. It repeated duplicate VirtualBox target warnings and architecture-support notices. **Do not assume cross-release repositories are safe**. The eventual bootstrap should inspect OS release and APT source compatibility and stop on unsupported mixes; never rewrite third-party sources without informed authorization.
5. **Malformed modprobe configuration:** During libvirt installation and initramfs regeneration, libkmod repeatedly logged: `/etc/modprobe.d/blacklist-kvm.conf line 1: ignoring bad line starting with '-e'`. This may affect module configuration reliability. It requires read-only inspection and approved remediation; do **not** overwrite this file, blindly reload KVM or reboot as an automation "fix".
6. **Potential source-built QEMU/SeaBIOS conflict:** The user's planned `kvm-qemu.sh` workflow involves a custom QEMU/SeaBIOS installation, while APT has now installed Ubuntu-packaged versions. Pin/install planning must analyze executable paths, package ownership and conflicts before replacing hypervisor components. Upstream `cape2.sh` also describes a separate `LIB_VERSION` requirement; do not infer compatible versions from package installation alone.

## Upstream source reviewed

[`kevoreilly/CAPEv2/installer/cape2.sh`](https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh), Git blob SHA `1bb76ccb84b5f67ca877ad863550b63687f51e37` at inspection; equality to SSL-55's local checkout remains **unverified**:

- `NETWORK_IFACE` sets the CAPE/tcpdump capture interface and is written into `conf/auxiliary.conf`.
- `IFACE_IP` is used for specific routing/transparent proxy listeners; it is not a general proof of network isolation.
- `INTERNET_IFACE` is used by host routing code. The upstream default attempts to identify an interface from `ip route`, which may be ambiguous on multi-homed systems.
- `PASSWD` is used in PostgreSQL provisioning and configuration and other sensitive operations. The upstream installer supports a sourced `cape-config.sh` for overrides, but using that mechanism **securely** still requires reviewing its privilege, file ownership, logging and shell-evaluation implications.

## Draft automation and tests

[`scripts/audit_libvirt_cape_network.py`](../scripts/audit_libvirt_cape_network.py) is **strictly read-only**:
- Parses literal assignment lines in `cape2.sh` without sourcing or executing it; redacts any `PASSWD` value.
- Queries `virsh -c qemu:///system net-dumpxml`, `ip -j link show`, and `ip -j route show default` with bounded timeouts. No `net-start`, `net-autostart`, `apt install`, firewall edits, network creation or password changes.
- Identifies NAT/forwarding, bridge/IP mismatches, non-existing uplink interfaces and ambiguous dynamic expressions. This existing auditor is **not** a complete destination-route resolver; see the new companion module below.
- Reports hazards in structured JSON. **`safe_to_use_for_malware` is always false** because XML+interface checks cannot substitute for runtime guest isolation/negative connectivity testing. The command exits nonzero until a separate complete safety gate exists.
- Optionally writes a sanitized, non-overwriting JSON report to an explicitly provided path (do not publish host topology unreviewed).
- Depends on Python 3, `iproute2`, `virsh`; eventual bootstrap must check/install supported dependencies when authorized.

[`scripts/test_audit_libvirt_cape_network.py`](../scripts/test_audit_libvirt_cape_network.py) contains **11 independently executed synthetic tests**, all passed, covering standard NAT hazard, absent `eno1`, safe password redaction, installer nonexecution, invalid XML, bridge mismatch, duplicated/missing/empty settings, unsafe shell expressions, and isolated-XML-without-runtime-proof refusal. Committed Git blob SHAs match locally tested files:
- Auditor `79bcc46500f0c3c28f9f5652cbe79f2b3eae2f9f`
- Tests `c0ef2075d021cdcc9b37afe0a815eb11cfae59a9`

**Not yet tested:** Actual SSL-55 runtime audit; fresh Ubuntu/libvirt installation; guest-connected topology; audit of system firewall rules; network packet negative tests; use with complete CAPEv2 runtime or INetSim; actual isolation. This draft is **not** production ready.

## Additional dynamic host-uplink component (correction, 2026-10-09)

The user supplied both a route lookup (`ip -4 route get 1.1.1.1`) and a second `cape2.sh` grep proving `INTERNET_IFACE=enp0s31f6`. This replaces the previously recorded current value of `eno1`, without changing the historical chronology. The password remains fully redacted.

[`scripts/discover_host_uplink.py`](../scripts/discover_host_uplink.py) is a new **read-only** route selection draft that validates route destination, selected interface existence, interface status, source IP address assignment, default route multiplicity, policy rules, network-interface class (including bridges and VPNs), and optional operator override. It neither sends packets nor enables forwarding, NAT or guest access. The optional report is created with mode `0600` and never overwritten. Configuration is **not** automatically edited.

There are **19 passed synthetic unit tests** in [`scripts/test_discover_host_uplink.py`](../scripts/test_discover_host_uplink.py), and a limited read-only smoke test on a **separate execution environment**. The Git blob hashes of the committed Python files match the locally tested files. Tests cover Ethernet-only, Wi-Fi-only, multiple routes/default routes, policy routing, VPNs, container bridges, disconnected interfaces, unassigned source IPs and overrides. No SSL-55 runtime test has been performed.

For dedicated analysis-network selection, the existing libvirt XML auditor can inspect one named network. Automatic discovery, provisioning and isolation verification of a suitable analysis network are **not complete**. See [DYNAMIC_NETWORK_DISCOVERY.md](DYNAMIC_NETWORK_DISCOVERY.md).

## Release design rules

1. Preflight the OS/APT setup, CPU/KVM, host services, available network interfaces/subnets, and libvirt/packaged QEMU state.
2. Bootstrap missing `libvirt-clients` and required daemon components only when authorized, **after checking versions, package provenance, conflicts, and installation impact**; prefer no-op on existing suitable versions.
3. Query whether existing libvirt network is defined, active and persistent. **Do not automatically start the default NAT network as an analysis network.**
4. Use a **dedicated** verified isolated analysis segment for Windows and INetSim; choose nonconflicting CIDR, validate XML/no forwarding and host firewall, and prove guest negative routes to host management, Docker, LAN, and Internet.
5. Resolve necessary uplink from multiple interfaces/routes only for explicitly allowed management/downloading purposes, not guest routing. Never hardcode `eno1` or an organization's network interface.
6. Configure CAPE through version-aware, safe settings; avoid editing upstream installer until backup, diff and compatibility checks. Never embed the secret in command arguments, Git, an insecure log or default config.
7. Fail closed if module warnings, APT source incompatibility, missing secrets or isolation tests remain unresolved; preserve existing host workloads. Maintain a separate mutable install journal and redacted diagnostics.
8. Run all provisioning and network cases on an independent supported clean Ubuntu test host before promoting from `development` to `main`.

**Step 6 acceptance:** Package installation/network existence and four text assignments are evidenced; **network safety, correct uplink, correct secret handling, and end-to-end installer functionality are NOT verified**.
