# Command 2 — Windows guest personalization (development)

Components:
- scripts/command2_windows_guest_config.py (pure, NO host writes)
- scripts/command2_guest_personalize.ps1 (executes INSIDE a Windows 11
  guest only, when invoked by a future trusted Command 1 guest bootstrap)
- scripts/test_command2_windows_guest_config.py (Python synthetic tests)
- Windows GitHub Actions powershell AST syntax parser (never executes
  the script in CI).

**Status: NOT integrated into a portable two-command deployment and
NOT verified on a booted Windows clone.** The per-VM script is a
component intended to be preinstalled by Command 1. Merely staging a
libvirt domain does not execute this script in Windows, and no agent or
config-drive automation has been proven.

## Config and security properties

The Python generator maps the unique reservation row into a JSON
config containing expected SMBIOS/libvirt UUID, WIN11-N hostname,
reserved unicast MAC, static IPv4 with prefix, isolated subnet and a
null default gateway. It refuses mismatched identity, subnet, MAC,
disk or UEFI destination. It never modifies Windows, files or libvirt.

Inside an isolated Windows guest, PowerShell requires a config file
and its expected SHA256 from the trusted host orchestration channel.
Before ANY identity/IP changes it compares Win32_ComputerSystemProduct
SMBIOS UUID with expected libvirt UUID, validates the guest hostname/IP
and MAC schema, requires no default gateway and refuses unsafe or
unexpected NIC state.

Four modes:
- Plan: read-only, no changes. Reports candidate identity and NIC count.
- Identity: requires local Administrator and **ZERO guest NICs**;
  issues Rename-Computer to WIN11-N and may restart only when explicitly
  requested. A later read-only verification must confirm the rebooted
  name. Does not configure networking.
- Network: requires *separately proven* host IPv4/IPv6 isolation,
  firewall persistence, approved isolated NIC attachment, matching
  reserved MAC, EXACTLY ONE physical guest NIC, expected hostname and
  no IPv4 default route. It then configures the on-subnet IPv4
  address without adding a default gateway. This gating switch is an
  operator/host-side assertion, NOT cryptographic proof of containment.
- Verify: read-only confirmation of hostname, matching NIC MAC,
  desired IPv4 and absence of an IPv4 default route.

No host firewall, DHCP, shared LAN interface, Windows Defender policy
or Windows Update settings are changed here. Guest IPv6 remains a
separate host containment and negative-egress test requirement;
the script alone cannot prove guest isolation.

## Major missing end-to-end integrations

1. Command 1 must place and configure a trusted privileged Windows
   bootstrap mechanism in the final clean Windows template, or a
   separately audited offline guest-configuration transport must be
   designed. No default remote shell/NIC allowed.
2. Host Command 2 must generate and securely deliver a distinct
   integrity-pinned config for each cloned VM BEFORE guest hostname
   personalization. Config must not leak credentials.
3. Zero-NIC guest identity stage must be verified inside each guest
   after reboot, then ensure full UEFI/swtpm cold restore safety.
4. Only after host reboot-persistent IPv4+IPv6 containment is proven may
   an isolated NIC be attached; then the guest applies static IP.
5. Validate CAPEv2 agent, host<->guest traffic, INetSim intentional
   fake-services path, no external egress, and parallel VM capacity.
6. Real Windows boot and PowerShell execution acceptance is required on
   a **separate approved target machine**, not SSL-55.

Never enable a NIC simply to execute the PowerShell guest bootstrap.
Do not run guest identity/network operations on the protected source
master or any other unrelated Windows VM. Do not claim these components
complete Command 2 until the full test matrix has passed on an approved
machine.
