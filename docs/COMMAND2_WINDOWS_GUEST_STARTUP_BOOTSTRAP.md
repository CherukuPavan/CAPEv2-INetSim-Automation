# Windows Command 2 optical bootstrap (development stage)

Files:
- scripts/command2_guest_startup_autoconfig.ps1
- scripts/command2_guest_personalize.ps1
- scripts/test_command2_guest_startup_autoconfig.py

**Not yet tested executing inside Windows. Not automatically delivered
or installed by the current Command 2 frontend.** The Windows GitHub
Actions job only parses syntax. Neither file executes from CI.

## Command 1 source-master installation and read-only proof (2026-10-12 hardening)

The pre-existing Windows script now offers a separate `-Mode Verify`.
Both `-Mode Install` and `-Mode Verify` require the exact **reviewed**
SHA-256 values of the bootstrap runner and guest personalizer, as well as
the expected source Windows SMBIOS UUID. These inputs must come from a
trusted pinned repository revision, NOT from an untrusted optical disk.

The bootstrap's `Verify` mode rejects a different source UUID, missing or
modified local `ProgramData\\CAPECommand2` scripts, a disabled or missing
`CAPECommand2GuestInit` scheduled task, a principal other than privileged
SYSTEM ServiceAccount, extra/unexpected triggers/actions, or an action
that does not run the precise installed script at startup. It only reads
local state; it never boots/renames the guest, attaches a NIC, or installs
the task. `Install` likewise checks both exact reviewed source script
hashes BEFORE copying and verifies the registered task immediately
after installation. The user must explicitly approve installation.

**Illustrative Windows Administrator PowerShell syntax** (values are
unresolved placeholders; do NOT execute without reviewing the original
Windows VM, correct source paths and approved SHA-256 values):

```powershell
# Execute from the directory holding BOTH reviewed .ps1 files.
.\\command2_guest_startup_autoconfig.ps1 -Mode Verify `
  -ExpectedTemplateUuid '<EXACT_COMMAND1_MASTER_SMBIOS_UUID>' `
  -ExpectedRunnerSha256 '<REVIEWED_SHA256_FROM_PINNED_REPO>' `
  -ExpectedPersonalizerSha256 '<REVIEWED_SHA256_FROM_PINNED_REPO>'
# For first-time installation only, use -Mode Install and -ApproveInstall
# with the exact same reviewed UUID and SHA arguments; never silently
# register this task in the original protected SSL-55 master.
```

The updated `command2_guest_personalize.ps1` refuses duplicate or
prefix-mismatched addresses and treats a coincidentally matching DHCP
lease as **not** a proven static IPv4 address. `Verify` fails closed if
DHCP is enabled, the exact static IPv4 is missing, or any IPv4/IPv6
default route remains on the analysis NIC. Network apply re-reads the
live Windows address, DHCP and both route families after writing.

**Development limitation:** this improves guest payload integrity and
read-only acceptance, but `command1_pre_vm.sh` does NOT yet deliver,
install or verify the Windows task inside the Command 1 source Windows
master. Until that transport is implemented and exercised on real Windows,
Command 1 is NOT fully automatic and clone identity/IPv4 application
remains unverified. Powershell parser and Python static regressions do NOT
prove a real Windows scheduled-task execution or network acceptance.

## Purpose

Command 1's approved golden Windows analysis VM will eventually receive
a registered startup task once. Every cloned Windows VM inherits it;
the task then reads its own identity/IP configuration from an offline
CD-ROM labeled CAPE_CMD2 and invokes the existing guest personalization
script. This is the mechanism that will eliminate manual per-clone
Windows hostname/static-IP changes after host integration is finished.

The task only installs with local Administrator privilege, exact
current Windows SMBIOS UUID and explicit -ApproveInstall. It refuses
overwriting a different existing bootstrap script or task.
At boot it waits for the optical disk. If absent, it does nothing.

## Proposed per-VM optical disk layout

- guest-config.json : Command2 generated Windows guest config with
  guest name, Windows hostname, static RFC1918 address, expected
  SMBIOS UUID, expected dedicated NIC MAC and zero default gateway.
- guest-config.sha256 : exact hex SHA256 of guest-config.json.
- network-approved.json : OPTIONAL host-generated approval that names
  the same VM UUID, name, MAC and explicitly verifies real host IPv4
  and IPv6 negative egress, reboot persistence, L2 segregation.
- network-approved.sha256 : hash of network-approved.json.

Phases:
1. ZERO physical Windows guest NICs: verify guest UUID and hashes;
   request guest identity rename to WIN11-N and explicit reboot.
2. If exactly one NIC is present but network-approved.json is ABSENT:
   WAIT; do not assign an IPv4 address.
3. If exactly one NIC and host-issued approval matches all fields:
   call the Windows guest-personalization Network mode which requires
   the reserved MAC, Windows hostname, no default route and no
   contradictory existing IPv4 before applying planned static IP.
4. Auto task may run idempotently on later restarts. It never boots
   a libvirt guest, connects a NIC, changes host routes/firewall,
   or permits a Windows default gateway.

Important: SHA files on the SAME ISO guarantee accidental corruption
detection, NOT independent authentication; whoever controls ISO content
can change both. The host-side generator/attach stage must be
restricted to the approved host and private reservation, use durable
manifests and validate exact ISO hash. The guest cannot independently
prove host nftables effectiveness from a JSON flag.

## Still required to call this automatic

- Command 1 must safely install the startup task in the accepted
  golden Windows template, or an existing clone under explicit pilot
  approval. Do NOT change protected win11 on SSL-55 without a separate
  narrow review of current disk/snapshot and network state.
- Command 2 host must create one private read-only ISO for each
  exact reservation, attach it to the shut-off guest, stage the
  host-isolation approval only after real IPv4/IPv6 tests, then
  verify the guest hostname/IP after reboot and CAPE agent HTTP 8000.
- CAPE snapshot must include running memory/disk and demonstrate
  benign revert, with independent QCOW2/OVMF/swtpm cold recovery.

Other target host portability and actual guest execution are NOT yet
accepted. SSL-55 first-clone pilot requires the read-only
scripts/command2_ssl55_win11_1_readiness.py report before any
NIC, bridge, Windows, firewall or snapshot modifications.