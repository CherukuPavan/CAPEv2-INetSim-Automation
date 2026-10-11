# Command 2 — current handoff after first independent clone boot (2026-10-10)

**CANONICAL CODE BRANCH = `development`. NEVER commit to `main`.**
## 2026-10-11 20:56+ UTC — ISO mounted but existing WIN11-1 guest has UNKNOWN DEFAULT ROUTE; no Windows IP set

User uploaded CAPE_Command2_WindowsISO_20261011_204246.txt:
host correctly created ISO /var/lib/libvirt/images/cape-clones-staging/win11_1.command2_firstboot.iso and inserted into
running win11_1 sdb via virsh change-media --live --config. VM disk unchanged.
Screen capture in Windows elevated PowerShell showed first user-typed one-liner
Get-CimInstance Win32_LogicalDisk -Filter DriveType=5 => Invalid query,
then corrected PowerShell script running read-only Plan blocked:
COMMAND2_ONE_NIC_BLOCKED: Unexpected IPv4/IPv6 default route
(do not configure under uncertain routing). No Windows IP/hostname changes
were applied. User cannot conveniently copy/paste commands into offline VM
and asks to avoid future manual Windows PowerShell typing.

Resolution in development: scripts/command2_windows_one_nic_diagnostic.ps1
and scripts/command2_windows_one_nic_CHECK.cmd provide a double-click
READ-ONLY Windows CD-ROM diagnostic (route next-hop/interface, NICs, IPv4/IPv6
addresses, current hostname and SMBIOS UUID) that writes a Windows Public
Documents TXT and opens Notepad, ready for screenshot. NO IP/firewall/route
changes; never bypass the default-route guard before identifying it.
GitHub Actions run 38174511351 PASS dual Python + real Windows AST checks.
Next user action: on SSL55 replace EXISTING sdb firstboot ISO with a new
immutable GitHub pinned small DIAG-only ISO via virsh change-media
--update --live --config (no --force, preserve original ISO), then
Windows GUI File Explorer -> CAPE_DIAG CD -> double-click CHECK.cmd;
user uploads Notepad screenshot to review default routes. The next
approved guest configuration can similarly be launched by double-click
a .cmd from ISO, no Windows terminal copy/paste or internet.

Remaining goal unchanged: finish real SSL55 win11_1 benign static IP
192.168.240.101, WIN11-1 hostname, prove guest/host IPv4/IPv6 no egress,
CAPE Agent port8000, running disk+memory snapshot + benign revert;
then automate Command2 for N independent clones and work Command3,
full 3-command tests on separate host. INetSim service deferred.

## 2026-10-11 20:27 UTC: SSL55 win11_1 BENIGN boot confirmed; Windows static-IP path next

Uploaded CAPE_Command2_Win11_1_Boot_20261011_202713.txt:
win11_1 UUID 732b2256-ee99-41fa-881d-fbf5c476d960
RUNNING after guarded virsh start, reserved MAC
02:0a:30:6a:3f:50 on cape-analysis-isolated,
bridge cape-lab0. win11 master and win11_trial_1
remain SHUT OFF, no snapshot. Windows target
WIN11-1 and IPv4 192.168.240.101/24 (no gateway)
still NOT applied/read back. Guest actual IPv4/IPv6
external egress, agent HTTP 8000, running snapshot
and revert NOT tested. No malware/sample execution.

Critical existing-guest pilot detail: the previous
command2_guest_personalize.ps1 -Mode Identity
requires ZERO NIC; pilot now has ONE NIC. Do not
reuse its zero-NIC phase or silently detach MAC.
Added generic portable 1..16 Windows PowerShell:
scripts/command2_guest_one_nic_firstboot.ps1.
Modes Plan/Apply/Verify; guards actual SMBIOS
UUID, reserved locally-admin MAC, one physical
NIC, sequential 192.168.240.(100+N)/24, rejects
any guest IPv4/IPv6 default route and any
unexpected existing guest IPv4; explicit admin
-ApproveBenignSetup required before apply.
Apply sets static IPv4 WITHOUT gateway/DNS,
requests WIN11-N rename if needed, and refuses
to claim analysis readiness. It NEVER disables
security software or Windows firewall or reboots
guest implicitly. Actual Windows state unknown;
PowerShell validity checked in GitHub Windows AST
job and synthetic source tests, NOT live Windows.
GitHub Actions #38172575972 SUCCESS offline+Windows
parser. Need determine FAST transport: check whether
Windows QEMU guest agent supports guest-exec; if yes
deliver pinned PowerShell automatically with a
host guard and read-only Plan first; otherwise use
offline read-only optical config media/Windows console.
Do not assume Windows guest agent installed.

USER ASKED speed and stay on LAST GOAL:
finish SSL55 Command2 pilot, automate count-selected
1..16 guest clone hostname/IP, isolation and CAPE
running snapshots, then develop Command3, then
physical full 3-command acceptance on new host.
INetSim optional deferred. No new host VM or
large QCOW2 copies on SSL55.


## 2026-10-11 20:20 UTC: user uploaded successful NIC report; benign Windows boot next

Source: CAPE_Command2_Win11_1_NIC_20261011_202005.txt.
Host report shows exact result SSL55_WIN11_1_BENIGN_ONLY_NIC_SAVED_SHUTOFF:
one e1000e NIC MAC 02:0a:30:6a:3f:50 attached to saved
win11_1 uuid 732b2256-ee99-41fa-881d-fbf5c476d960,
cape-analysis-isolated network, clone still SHUT OFF;
master and trial remain untouched. Windows static IP,
external IPv4/IPv6 isolation, CAPE agent HTTP and running
snapshot are NOT yet verified. DO NOT repeat NIC attach.

User explicitly asked SPEED UP and concentrate on final goal:
finish SSL55 reference Command2, make truly count-driven
N independent Windows guest static IP/hostname/agent/
running snapshot automatically, develop Command3, then
accept ALL three commands together on a later separate host.
INetSim services deferred, network safety NOT deferred.

New scripts/command2_ssl55_win11_1_benign_boot.py + 7 offline
tests (scripts/test_command2_ssl55_win11_1_benign_boot.py).
Safely inspect protected current-boot CAPE guard and service,
isolated active manually started bridge, exact ONE saved
win11_1 NIC with original UUID/disk/UEFI/TPM, original master/
trial saved identities and shutoff, no other running VMs,
autostart disabled, no snapshots. Only explicit typed
BOOT-ISOLATED-WIN11_1-BENIGN-ONLY can issue virsh start win11_1.
Postchecks ensure same one-NIC clone running with no
other running VMs. Does not install Windows IP, invoke CAPE
agent or run samples; no snapshots or further host changes.
CI run 38172118517 PASSED offline+Windows syntax.

NEXT: user runs SHA pinned guarded benign guest BOOT script
once on SSL55 and uploads one TXT. If PASS proceed directly
to single Windows guest hostname/static IP and CAPE agent
benign checks. Important: existing
scripts/command2_guest_personalize.ps1 Identity phase
requires ZERO NIC and will NOT work on win11_1 AFTER the
NIC was attached. Need choose a safe ONE-NIC Windows
configuration path for this existing pilot, not blindly invoke
Identity. For future count-driven clones install startup
bootstrap in golden template BEFORE clone NIC creation or
provide approved offline config delivery. Snapshot gate
still requires actual benign network tests, TPM/UEFI and
CAPE-agent live validation.


## 2026-10-11 ~20:13 UTC: bridge success, BENIGN-only single existing win11_1 NIC stage prepared

User uploaded CAPE_Command2_Bridge_20261011_201302.txt.
`SSL55_ISOLATED_BRIDGE_ONLY_ACTIVE_WITH_NO_GUEST_NICS`
reported success: cape-analysis-isolated ACTIVE, bridge cape-lab0
192.168.240.1, current CAPE guard present, nft table inventory
unchanged, protected win11/win11_1/trial SHUT OFF, win11_1 and
trial still ZERO saved NICs. Guest IPv4/IPv6 negative egress, L2,
agent HTTP, snapshots still NOT verified. Do not re-run net-start.

Committed SSL55-specific scripts/command2_ssl55_win11_1_benign_nic.py
and scripts/test_command2_ssl55_win11_1_benign_nic.py with 11 synthetic
tests on development. Separate-host NIC attachment script unchanged.
No actual host write has happened yet.

The SSL55 script verifies protected exact win11_1 UUID, saved unique
independent disk/UEFI/TPM, bridge active and isolated port yes,
no libvirt NAT/IPv6/DHCP/DNS, empty bridge ports,
no other running libvirt VM, correct current boot CAPE nft guard,
base nftables disabled, prior win11 saved NIC intact, unique MAC
02:0a:30:6a:3f:50, and no clone snapshots.
Only explicit typed ATTACH-ONE-BENIGN-NIC-WIN11_1-SSL55 under root
exclusive lock can call ONE virsh attach-interface --config on the
SHUT OFF existing win11_1. No VM boot, static IP, firewall edits,
snapshot or other clone created. On PARTIAL halt and inspect.
GitHub Actions run 38171586986 PASSED Windows parser+Python offline.

NEXT operator step: single SHA-pinned script fetch, read-only plan,
operator-typed saved NIC config attach, one TXT report.
Then separate Windows guest safely monitored benign network
qualification, identity/IP, agent HTTP, running snapshot, benign
revert. No malware execution until actual IPv4/IPv6 containment proven.



## 2026-10-11 20:05 UTC: live SSL55 reboot test PASS; bridge-only stage next

User uploaded CAPE_Command2_RebootVerification_20261011_200314.txt.
Pre/post boot IDs differed (actual reboot). Dedicated CAPE nft guard
unit now enabled and ACTIVE/SUCCESS after restart; journal shows it
RESTORED legacy inet cape_analysis_guard at 20:04:57. Base nftables
service remains disabled/inactive; protected three Windows VMs
remain shut off, zero-NIC clone/trial unchanged, CAPE network remains
inactive, autostart disabled. Initial guard boot replay is PROVED;
external IPv4/IPv6 and L2 packet containment is NOT proved.
No second reboot necessary now. No bridge/NIC/VM started yet.

Committed scripts/command2_ssl55_bridge_only_activation.py and
9 offline mock tests; only existing libvirt cape-analysis-isolated
net-start can occur on explicit guarded interactive mode, without
NIC/VM start. Strict preflight requires current boot guard service
ACTIVE/SUCCESS, exact protection/VM state, inactive no-NAT/DHCP/DNS
isolated bridge with port isolated=yes, no CIDR collisions. The
post-start checks verify intended bridge IPv4, no global/site IPv6,
unchanged nft table inventory and zero NIC/no running VMs.
Unexpected post-start state is PARTIAL, no automatic destructive
rollback, no permission to attach NIC or analyze samples.
CI workflow 38171061727 passed BOTH offline and Windows syntax jobs.
Docs: docs/COMMAND2_SSL55_REBOOT_PASS_BRIDGE_NEXT.md.

NEXT ACTION: one SHA-pinned bridge-only plan/optional interactive
activation command on SSL55; report back before NIC attachment.
The protected master must remain shut off and untouched.


## 2026-10-11 ~19:41+ — OPERATOR AUTHORIZED SSL55 DEDICATED GUARD UNIT INSTALL+ENABLE

User explicitly replied 'yes carry on' to approval for ONLY a
dedicated CAPE guard systemd service on SSL-55, with existing
nftables, VMs and CAPE analysis network left INACTIVE/unchanged.

New code scripts/command2_ssl55_guard_service_installer.py and
11 synthetic test methods on development; all source dependencies
pinned by Git blob SHA, no overwrite/symlink, root-only install.
- `--mode plan`: strict root READ-ONLY host checks and deterministic
  report SHA256 including exact candidate systemd unit text and
  selected ACTIVE libvirtd.service or virtqemud.service backend.
- `--mode install`: must match reviewed SHA256, interactive literal
  INSTALL-ENABLE-ONLY-CAPE-GUARD-SSL55, exclusive root flock;
  revalidates all protected VMs/guard/base firewall/network, then
  creates only /usr/local/libexec/cape-command2 root-only scripts,
  /etc/cape-command2/ssl55-guard-replay-approved.json (0600),
  and /etc/systemd/system/cape-analysis-guard.service (0644).
  Validates unit via `systemd-analyze verify`, then ONLY calls
  `systemctl daemon-reload` and `systemctl enable cape-analysis-guard.service`
  WITHOUT --now. Never starts bridge/VM, edits nftables.conf,
  enables base nftables.service, writes nft rules or adds NIC.
  Post-check asserts service enabled but inactive, base nftables
  disabled/inactive, original guard and VMs unchanged.
  On partial error leaves files intact and warns against blind retry.

GitHub Actions workflow 38169636288 PASSED both offline and
Windows jobs, aggregate Python 3.10 339/339 tests PASS. These are
only mocked/offline, not host acceptance. Installer not yet run
on SSL55 at time of this handoff. Next step: user runs immutable
GitHub SHA pinned installer+plan launcher in SSL55 terminal and
uploads one TXT report of plan/guarded apply or BLOCKED details.
NO reboot/guest network/NIC commands yet. Dedicated service
enablement is not a proved reboot-persistence or external egress
guarantee. `win11_1` still shut off with zero NIC and no snapshot.

Installer instructions: docs/COMMAND2_SSL55_GUARD_SERVICE_INSTALL.md.


## 2026-10-11 15:30 UTC — SSL55 boot-persistence report uploaded, replay design in development

Source file: CAPE_Command2_BootPersistence_20261011_153057_wtbVV8dC.txt.
Actual report fields:
- `nftables.service`: LoadState=loaded, UnitFileState=disabled,
  ActiveState=inactive, boot_enabled_observed=false.
- `cape-analysis-guard.service`: LoadState=not-found,
  ActiveState=inactive, boot_enabled_observed=false.
- `/etc/nftables.conf`: root-owned trusted regular file, 243 bytes,
  global_flush_present=true, guard_reference_present=false,
  includes_present=false. DO NOT enable/restart `nftables.service`;
  it might flush Docker/libvirt/campus firewall rules.
- Original 3 VMs (win11, win11_1, win11_trial_1) all SHUT OFF,
  all autostart disabled; original win11 NIC previously restored.
- CAPE isolated network defined, persistent, but ACTIVE=no,
  AUTOSTART=no, no forwarding/DHCP.
- Existing `cape_analysis_guard` expected shape PRESENT but not
  reboot-persistent; external IPv4/IPv6 negative tests and CAPE
  agent unchanged/not performed. safe_to_attach_win11_1_nic=false.

New development components COMMITTED, not applied on SSL55:
- `scripts/command2_ssl55_persistence_design.py`: pure strict
  host report-to-repair-model and 6 synthetic tests.
- `scripts/command2_ssl55_guard_scoped_replay.py`: root-only,
  explicitly authorized optional `--mode reconcile`, which
  retains any valid existing guard and can ONLY atomically
  add missing fixed-hash (`58b84446ad74ac7ea8b14aa57d94c19945baa3db7330e54c7fb2312a9577ea14`)
  inet CAPE table. Never changes nftables.service or master/clone.
  Read-only `--mode plan` default. Nine synthetic tests.
  No root-only authorization manifest installed on SSL55.
- `scripts/command2_ssl55_guard_systemd_unit_plan.py`: pure
  candidate isolated systemd unit text for libvirtd.service OR
  virtqemud.service dependency; neither dependency was verified
  from the user report. FOUR synthetic tests. NO unit installed,
  started or enabled and reboot persistence not proven.
- `docs/COMMAND2_SSL55_GUARD_PERSISTENCE_DESIGN.md`: root
  cause/requirements. Strict fail-closed no-flush deployment path.
- CI run 38152196804 SUCCESS for guard replay tests; CI
  run 38152466068 SUCCESS for added systemd candidate unit and
  entire offline + Windows parser jobs.

Next work: determine actual SSL55 libvirt service unit, review and
implement tightly scoped root-controlled installer + approve a
dedicated CAPE-only service; verify it after reboot without
disrupting general host firewall, then perform benign guest
network qualification before assigning 192.168.240.101 and
capturing RUNNING snapshot. The real guest remains NIC-less.
Do not repeat master NIC repair, make extra VMs/disks on SSL55,
or treat passing offline CI as host acceptance.


## 2026-10-11 15:16 — SSL55 CAPE nft guard report received; staged benign NIC fix

Operator uploaded CAPE_Command2_GuardNetwork_20261011_151629_yRxE0i87.txt:
- Existing CAPE nft `inet cape_analysis_guard` PRESENT, three
  expected chain hooks/priorities, verdict lists
  cape_forward drop/drop, cape_input accept/drop,
  cape_output accept/drop, bridge and TCP8000 expected tokens.
- The analysis cape-analysis-isolated / cape-lab0 is persistent
  but ACTIVE=no, AUTOSTART=no, no forward/NAT/DHCP.
- win11 UUID 289d89be-68ec-4c62-90e1-ea930849266f
  shut off and has 1 inactive NIC (restoration verified).
- win11_1 UUID 732b2256-ee99-41fa-881d-fbf5c476d960
  shut off, 0 NICs, NO running CAPE snapshot.
- win11_trial_1 UUID e75f6fef-347d-462f-9738-4de3df6bfa74
  shut off, 0 NICs.
- Candidate win11_1 MAC 02:0a:30:6a:3f:50 COLLISION-FREE in
  current host/libvirt inventory. Windows target WIN11-1, IPv4
  192.168.240.101. MAC still NOT RESERVED nor attached.
- SYSTEMD status for nftables.service and cape-analysis-guard.service
  was 'unknown' in the audit due to `systemctl is-enabled` and
  `is-active` nonzero exit statuses, NOT proof of missing services.
- IPv4/IPv6 actual egress, L2 and reboot guard persistence NEVER
  tested. safe_to_attach_analysis_nic=false.

**Critical architectural fix:** previous scripts/command2_guarded_isolated_nic.py
required guest-level negative egress and CAPE agent readback BEFORE
the guest possessed a NIC: CIRCULAR ACCEPTANCE BLOCK. Added
scripts/command2_quarantined_benign_nic.py and 10 synthetic tests.
It is for separate approved hosts ONLY; guards SSL55. After
verified host-only non-NAT bridge + installed scoped nft policy +
root-only operator receipt, it can attach one config-only e1000e
NIC to shut-off guest for BENIGN egress testing, never granting
CAPE, snapshot or malware approval. Checks exact existing MACs and
kernel IPv4 routes/address collision. Legacy higher-trust attach
mode remains, but no longer the initial benign testing path.
See docs/COMMAND2_BENIGN_QUARANTINE_NIC_STAGE.md.

Added scripts/command2_ssl55_boot_persistence_readonly.py and
8 synthetic tests. This read-only script imports existing guard
audit and obtains `systemctl show` LoadState/UnitFileState/ActiveState
with clear missing vs disabled vs enabled distinctions; inspects
root-owned /etc/nftables.conf metadata for guard and flush mention;
checks libvirt autostart for all 3 protected VMs. NEVER activates
bridge/NIC, writes rules, or grants boot persistence.

GitHub Actions run 38151326848 on `development`: SUCCESS offline
and Windows PowerShell syntax jobs after strict route/address
collision check, and run 38150998250 also green. CI is SYNTHETIC
only. Next user step: single sha-pinned read-only SSL55 boot service
state TXT before any live network/guest change.

Do not use shared host as proof of full separate-host Command2
readiness. No additional VMs/disks allowed on SSL55. Do NOT start
Command3 until agreed development gates, but user ultimately wants
three-command physical acceptance together on other machine.


## 2026-10-11 14:53+00 user-uploaded SSL55 win11_1 readiness, NEW live-state finding

User uploaded CAPE_Command2_Win11_1_Readiness_20261011_145324_kJ5Azpm5.txt.
Current existing win11_1 UUID 732b2256-ee99-41fa-881d-fbf5c476d960
SHUT OFF, zero saved NICs, independent QCOW2/UEFI paths, TPM2 emulator.
cape-analysis-isolated persistent inactive autostart=no, no NAT/forward/
DHCP/IPv6 network elements, cape-lab0 192.168.240.1. No route/address
collision for 192.168.240.0/24. Legacy nft inet cape_analysis_guard
present with forward/input hooks; newer candidate
cape_analysis_cmd2_guard NOT installed. No clone snapshots.
Images fs only 95.59 GiB available; no new VM disks/copies on SSL55.
Windows static IP, port8000, IPv4/IPv6 negative egress, reboot
persistence, full cold restore and running snapshot NOT verified.

New repo scripts/command2_ssl55_existing_guard_readonly.py and
scripts/test_command2_ssl55_existing_guard_readonly.py make a
CONSERVATIVE additional no-write observation: exact expected three
nft cape_analysis_guard base chain hooks/priority and accept/drop
order, bridge+address+TCP8000 tokens, systemd nftables/guard service
enablement, and proposed deterministic locally administered MAC for
win11_1 after all libvirt/host link collision checks. Still reports
ALL packet/reboot/L2/agent acceptance FALSE, and no approval to attach.
GitHub Actions run 38149589815 SUCCESS offline+Windows parser.
Docs: docs/COMMAND2_SSL55_WIN11_1_PILOT_NEXT.md.

User is expected to run a single SHA-pinned, read-only SSL55
guard+persistence+MAC audit TXT and upload for actual live rule
review BEFORE any shared-host network/guest state modification.
No host modifications made through assistant. Original win11 NIC
already restored and must remain untouched. Command2 not done,
Command3 not yet started. INetSim service integration can wait;
safe isolation/agent/snapshot cannot wait for live win11_1 pilot.


## 2026-10-11 later Command2 guest autoconfiguration milestone

User expects not just static IP PLANS but actual per-Windows-clone
automatic hostname+IP configuration after creating the N VMs.

Committed scripts/command2_guest_startup_autoconfig.ps1 opt-in
Windows startup task bootstrap: Install requires exact local SMBIOS
UUID+Administrator+-ApproveInstall; installed into approved golden
Windows template once by future Command1. In future cloned guest,
boot-time startup task reads read-only CAPE_CMD2 optical media
with exact guest-config.json and companion SHA256. With ZERO NIC,
invokes Identity/hostname rename+reboot through existing script.
With one approved NIC, requires host network-approved.json matching
VM UUID/MAC and all host IPv4, IPv6, reboot persistence, L2
containment flags TRUE before invoking Windows static-IP mode.
WITHOUT approval it waits and refuses IP changes.

Added scripts/test_command2_guest_startup_autoconfig.py (4 source
tests) and CI Windows AST parser now validates BOTH Windows
PowerShell files. GitHub Actions run 38148724851 completed
SUCCESS for Ubuntu offline tests and Windows script syntax.

IMPORTANT STILL MISSING: host-side per-VM optical ISO generation,
binding/attaching to shut-off guest, trustworthy proof distribution
and boot/reboot verification; source Windows startup task not actually
installed; neither current SSL55 original master nor win11_1 guest
has been modified by these commits. Windows static IP has NOT
been applied anywhere by the assistant. Capturing and testing a
running CAPE snapshot for win11_1 still requires live SSL55
read-only audit and independent shared-host isolation approval.
INetSim-specific services may be deferred; basic external egress
containment and agent positive reachability cannot be deferred.

Latest handoff reference: docs/COMMAND2_WINDOWS_GUEST_STARTUP_BOOTSTRAP.md
and docs/COMMAND2_SSL55_WIN11_1_PILOT_NEXT.md.


## 2026-10-11 latest user direction: Finish SSL55 win11_1 pilot, then Command3 implementation, then test all 3 on OTHER host

User explicitly emphasizes remaining win11_1 isolated NIC, Windows
static IP, CAPE agent, *RUNNING* snapshot and revert. Original
protected win11 master NIC restoration is already verified but does
NOT confer a NIC on win11_1. Last known win11_1 RUNNING ZERO NIC.
User prefers IP +1 compared with the previous **verified analysis VM**.
Do NOT increment source win11 master NAT address on other subnet.
Example: win11_1 192.168.240.101, win11_2 .102, win11_3 .103.
No skipped/colliding next IPs, no extrapolation from unverified guest.

New development components:
- scripts/command2_sequential_guest_ip.py and 9 unit tests: pure
  previous Windows analysis guest verified IPv4 + 1 allocator,
  IPv4 overlap and collision blocks, 1/5/16 fresh guest count.
- Integrated cross-check in scripts/command2_portable_zero_nic_entrypoint.py
  for FRESH hosts only: actual Windows static-IP setting still
  requires secure guest-side command delivery and host isolation.
- scripts/command2_ssl55_win11_1_readiness.py + 7 offline tests:
  STRICT READ-ONLY reference-host single-clone audit: live/inactive
  NICs, exact UUID, isolated network forward/DHCP status, nft guard
  presence, `ip -j` route/interface CIDR overlap, existing
  snapshots, UEFI/TPM/disks and free images filesystem GiB.
  Does NOT create/attach/define/boot anything, alter host nft,
  write snapshots, or prove external egress containment.
- docs/COMMAND2_SSL55_WIN11_1_PILOT_NEXT.md records requested
  order and exact remaining piloting/blockers.
- GitHub Actions run 38148326580 GREEN, offline Python+Windows syntax.

Resolution of order: Complete and ACTUALLY VERIFY SSL55 existing
win11_1 Command2 PILOT to permitted extent without creating new
VMs/large artifacts on shared reference host; then Command3
IMPLEMENTATION may proceed, followed by real 3-command portability
ACCEPTANCE on separately approved hardware. INetSim-specific
service simulation may be added later, but IPv4+IPv6 anti-egress
and CAPE host/guest safety MUST NOT be deferred.

NEXT USER ACTION: one read-only SSL55 readiness TXT report to
approve any state-changing isolated network/snapshot procedure.
Until reviewed, no connecting win11_1 NIC, bridge activation,
firewall changes, Windows IP assignment, or snapshot operation.
Still no additional guests or disk clones on SSL55.


## 2026-10-11 ~14:23 UTC — newly implemented Command2 CI fully GREEN

Operator screenshot at ~14:17 showed many failed development workflows
and ChatGPT UI 'Error in input stream'. Actual GitHub Action jobs inspected
directly, not inferred from screenshot:

- GitHub workflow 38146769987 ran 262 offline Python unittest cases;
  260 passed, 2 failed. Root causes: a REAL Python bug using
  Path.chown (nonexistent), and an overbroad test that searched the
  safety docstring for a systemctl reference. Earlier jobs had
  additional non-root CI lock fixture and regex mismatch failures.
- Production full cold restore fixed to use os.chown for per-guest
  swtpm directory; mocks now use real os.chown patch with strict root
  policy preserved. Python tests updated to correctly mock privileged
  lock fstat and Path replacement instead of immutable Path methods.
- CAPE config module side-effect regression now scans executable
  module content rather than a descriptive forbidden-word docstring.
- Workflow run 38146865474 (commit 489e312cc84221be6168f0605f9e815d97e83f3d)
  COMPLETED SUCCESS: offline Ubuntu and Windows PowerShell syntax jobs.
- Most recent workflow run 38146877542 (commit
  a1c2fe7b306e2a0d281d56bd62f1e790cbabac1d) also
  COMPLETED SUCCESS. Offline job had all individual tests green;
  aggregate Python 3.10 test discovery includes 262 tests.

IMPORTANT: Old FAILED workflow runs are historical and won't turn
green. The latest passing run confirms synthetic code gates ONLY.
The project remains NOT production release approved: actual separate
target host networking, Windows guest script auto-delivery, verified
native guest static IPv4, independent stateful TPM/UEFI cold boot
recovery, live CAPE running snapshot capture+revert, no IPv4/IPv6
egress and parallel benign CAPE/INetSim end-to-end tests PENDING.

Original SSL55 win11 e1000e NIC restoration previously verified;
do not rerun. win11_1 intentionally has no NIC, no new VM/network
operations permitted on SSL55. No SSL55 changes made during CI work.
Command3 BLOCKED pending real fresh-machine Command2 acceptance.


## 2026-10-11 verified major Command2 development + GitHub CI GREEN

User explicitly asks ALL Command2 features before starting Command3:
existing win11_1 isolated network, automatic static IPv4/hostnames,
running CAPE snapshot and fully restorable independent guest state.
SSL55 original win11 NIC was previously restored successfully;
win11_1 remains ZERO NIC intentionally until host isolation is proved.
No new VMs, NICs, snapshot copies or host changes on SSL55.

New development modules committed (full details in
docs/COMMAND2_NETWORK_RUNNING_SNAPSHOT_INTEGRATION.md):
- command2_guarded_isolated_nic.py: authorized OTHER-host,
  exact one-NIC shutoff libvirt CONFIG attachment with root-only
  acceptance record, live nft/libvirt readback and host protection.
  Does NOT create/start network, define firewall or boot guest.
- command2_cape_agent_probe.py: strictly bounded read-only
  CAPE Agent HTTP GET guest_ip:8000 with expected JSON/admin proof.
- command2_running_cape_snapshot_gate.py: operator-guarded
  running CAPE snapshot creation; enforces one INTERNAL memory
  and disk snapshot after live agent and network acceptance.
- command2_benign_snapshot_revert_gate.py: guarded destructive
  separate-host BENIGN running-snapshot revert; verifies agent
  after revert; does not assert unproven TPM/UEFI integrity.
- command2_portable_cold_bundle.py: guarded full shutoff clone
  disk+UEFI+swtpm capture/sha256 and deliberate restore. Stores
  old clone artifacts and durable intent so crash requires review.
  Python3.10 bug Path.chown fixed to os.chown.
- command2_cape_kvm_config_plan.py: emits CAPE KVM machine labels,
  guest IPv4, win11 tags, snapshot names for counts 1 to 16.
- 262 offline unit tests passed in GitHub Python3.10 aggregate run;
  Python 3.12 steps and Windows PowerShell AST syntax check passed.
  Official run 38146877542:
  https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38146877542
  HEAD tested a1c2fe7b306e2a0d281d56bd62f1e790cbabac1d.

Critical release distinction: ALL success is OFFLINE MOCK/STATIC,
no newly provisioned guest, NIC, firewall, boot, internal vTPM
snapshot or actual cold-restore/revert physically verified.
Host isolation receipts are operator assertions, not cryptographic
evidence without independent probes. Command1 trusted Windows
guest first-boot/config transport remains unimplemented/integrated;
host networking/reboot persistence and user Windows guest static IP
cannot be accepted without an OTHER approved KVM host and its
validated Windows master. Do NOT say Command2 complete or go to
Command3 on the basis of green CI.


## Development after verified original win11 NIC restore

Following operator upload of successful restore report at 13:38 UTC,
NO further SSL55 host action is needed for master NIC. Original
master has the saved default e1000e NIC and remains shut off.
win11_1 and trial remain intentionally networkless.

Next GitHub development work: scripts/command2_cape_egress_guard_plan.py
produces ONLY a candidate nft inet table scoped to cape-lab0, with
FORWARD drop toward external routes, host INPUT dropping guest IPv6
and guest IPv4 destined to non-bridge host addresses. It never
applies firewall rules, starts libvirt networks or attaches NICs.
Five offline regression tests added and CI job matrix extended.
Integrated portable count frontend now includes candidate guard
text/sha256 in its resource preview. Explicit real isolation
verification=false and NIC attachment authorization=false remain.
See docs/COMMAND2_CANDIDATE_NFT_EGRESS_GUARD.md for major L2
guest lateral-isolation, existing Docker/libvirt interactions,
spoofing, IPv6 and post-reboot live testing still unresolved.

Latest new module mocked CI results not yet verified. The portable
two-command Command2 has NOT passed a real separate-host deployment;
do not attach guest NICs or proceed to Command3 prematurely.


## SUCCESS: Original SSL-55 master NIC restored (2026-10-11 13:38 UTC)

User uploaded CAPE_MasterNIC_Restore_20261011_133805_Ifv1ismz.txt.
Actual terminal script output: ORIGINAL_SHUTOFF_WIN11_SAVED_NIC_RESTORED.
Script post-apply libvirt verification reported:
- Protected original win11 UUID 289d89be-68ec-4c62-90e1-ea930849266f.
- Exactly ONE saved network interface restored on default libvirt
  network, original backed-up e1000e and MAC 52:54:00:62:a0:00.
- Original master still SHUT OFF and snapshot finalshutoffversion retained.
- win11_1 and win11_trial_1 reported untouched.
- Host firewall untouched, no libvirt network started, no extra VM.
- Earlier plan evidence sha256 dd474f43350c10932fdd3d9abceef1c3f9fe2a74ee79e06edcdfb262f4005f83.

Original master NIC repair is FINISHED per the guarded host apply
script output. DO NOT REPEAT apply or boot master. The original
default-network NIC is NAT-capable if clean master is booted later,
so NEVER run malware through it. Treat win11_1 ZERO NIC as intentional
until isolated network IPv4+IPv6 egress/reboot persistence is PROVEN.
No new VMs/copies on SSL-55. The separate machine portable
Command 2 cloning/guest personalization/network/restore gates
remain unfinished. Command 3 blocked until full Command 2 acceptance.


## OPERATOR SSL-55 NIC RESTORE PLAN verified 2026-10-11 13:35 UTC

User uploaded CAPE_MasterNIC_RepairPlan_20261011_133515_FfV4f1Cf.txt.
Read-only plan PASS: result SSL55_ORIGINAL_MASTER_NIC_REPAIR_PLAN_ONLY;
original protected win11 UUID 289d89be-68ec-4c62-90e1-ea930849266f
remains SHUT OFF, current snapshot finalshutoffversion and snapshot
inventory Afterfull/basicinstallwinsnapshot/finalshutoffversion;
original saved e1000e/default NIC MAC 52:54:00:62:a0:00 is missing.
plan_sha256 dd474f43350c10932fdd3d9abceef1c3f9fe2a74ee79e06edcdfb262f4005f83
Master disk/snapshot unchanged, zero host operations in PLAN.

Next explicitly scoped optional action: operator-run apply using pinned
scripts/command2_ssl55_master_nic_guard.py blob SHA
23d9cb48ab400928bc7a8d2e0fc12e81cff5d42b and the exact
plan SHA. Apply checks state again and requires the literal phrase
RESTORE-ONLY-SHUTOFF-WIN11-SAVED-NIC. Because operator pastes a
bash heredoc, use </dev/tty on Python apply subprocess to satisfy
the script's intentional interactive confirmation requirement.
Capturing the output through tee to one private TXT is recommended.
NEVER apply without phrase and reviewed hash. If any result BLOCKED
or postcondition fails, no blind retry; upload result.

Apply (if invoked) targets ONLY the original master's saved libvirt
NIC --config. It does not activate default network, power any VM on,
attach win11_1 NIC, change nftables, copy disks, make backups, or
restore parallel guest isolation. On success, master original saved
NIC still NAT-capable if booted later; do not use master for malware.
Real-host network isolated-clone acceptance remains separate and
Command 2 / Command 3 release gates are unchanged.


## VERIFIED new uploaded SSL-55 network TXT — 2026-10-11 13:21 UTC

Operator uploaded CAPE_SSL55_NetworkReadOnly_20261011_132144_s2Qf9Jhu.txt:
- win11 protected UUID 289d89be-68ec-4c62-90e1-ea930849266f
  is SHUT OFF and currently has ZERO saved NICs.
- Preserved root-private master backup domain.xml HAS exactly ONE
  e1000e network adapter on libvirt default; current saved definition
  **DIFFERS** from the original. This is an actually confirmed
  missing original master NIC, not an inference.
- win11_1 and win11_trial_1 both RUNNING with ZERO live+saved NICs;
  this was intentional isolation, do not reattach default NAT.
- cape-analysis-isolated / cape-lab0 inactive, autostart no.
- Host isolation/IPv6 and reboot persistence are NOT proven.
- Earlier tool's report says no host changes, NIC repair unauthorized.

Follow-up implementation on GitHub development:
- scripts/command2_ssl55_master_nic_guard.py: two modes PLAN
  (root/read-only, no mutation) and APPLY (ONLY after reviewed plan
  sha256 + typed explicit authorization, original master shutoff,
  exact UUID/snapshot, root-private backup and MAC/PCI checks).
  APPLY attaches exact saved e1000e only to win11 inactive XML using
  virsh attach-device ... --config and rechecks original master
  disk/UEFI/TPM/resource fingerprint, snapshot inventory, powerstate.
  This is NOT executed or accepted on SSL-55 yet. Never auto apply.
- scripts/test_command2_ssl55_master_nic_guard.py: 8 synthetic
  safety regression methods committed; corresponding local design
  received 12/12 passed tests. Actual latest GH CI unverified.
- docs/COMMAND2_SSL55_MASTER_NIC_RESTORE_GUARD.md: plan-first
  workflow and deferred apply authorization. Do not run apply until
  the READ-ONLY plan TXT has been reviewed.

NO SSL55 mutation, VM creation, network attach or configuration
was performed by the assistant. The original master is still missing
its saved NIC until an explicitly authorized guarded repair is run
on the host. Command 2 overall is STILL incomplete; Command 3 locked.



Release gate: docs/COMMAND2_PRODUCTION_ACCEPTANCE_GATES.md records
missing real deployment and recovery acceptance. Command 3 is locked
until Command 2 is proven on a different approved, adequately provisioned
machine. SSL-55 network diagnosis remains strictly read-only.

## 2026-10-11 user requests complete Command2 plus SSL55 NIC fix

New operator request: finish ALL Command2 before starting Command3.
User asks whether any removed NIC configuration on original win11
or isolated clone win11_1 on SSL55 can be restored. DO NOT assume
that a missing NIC is a malfunction. Host state cannot be modified
through the GitHub connector; no SSH/terminal access was granted here.

- Existing read-only SSL55 postrestart host TXT recorded win11_1
  ZERO NICs in live+inactive views, cape-analysis-isolated inactive,
  nonautostart. The previous master/trial NIC listing was empty;
  specific master NIC loss is not yet demonstrated.
- New scripts/command2_ssl55_network_readonly_audit.py and
  command2_ssl55_network_readonly_acceptance.sh compare exact VM
  UUIDs, live/inactive network interfaces, lab network state,
  and the root-private original master backup metadata/domain.xml.
  It NEVER defines/attaches any NIC or modifies Windows, libvirt,
  nftables, master, trial or clone. 6 synthetic test methods added.
  Follow-up should review ONE report before any proposed repair.
- Original win11 may have a backed-up default NAT interface, but do
  not reattach any interface without complete XML and scope review.
  Win11_1 zero NIC is intended until isolation, guest static IP and
  host IPv4+IPv6 guarded containment are independently accepted.
- Portable scripts/command2_isolated_network_xml_plan.py generates
  no-forward/no-NAT/no-DHCP libvirt XML design for different hosts;
  NO host changes. Five synthetic tests added, CI workflow updated.
- Portable and legacy staging added backup-directory sentinel to
  BLOCK additional VM creation on renamed SSL55 reference host.
  Never bypass reference protection or allocate extra backup/disk.
- docs/COMMAND2_SSL55_NETWORK_RECOVERY_READONLY.md explains why a
  guessed network change is not allowed.

Status: STILL NOT COMPLETE as real two-command deployment. Remaining:
Command1 fully portable golden Windows/bootstrap prerequisite;
safe guest config transport and execution; isolated-network
nftables/IPv6 guard and reboot-persistence negative egress;
per-guest Windows hostnames/IP applied and verified after boots;
snapshot/rollback of independent QCOW2/OVMF/swtpm; parallel CAPE
and INetSim benign-path acceptance on a SEPARATE provisioned machine.
Do not start Command3 or declare Command2 production ready.


## 2026-10-11 continued Command 2 engineering — stage + Windows config

User requested to complete Command 2, without any additional
VM/NIC/backups on reference SSL-55. Developed only in GitHub development:

- scripts/command2_portable_zero_nic_stager.py: new guarded,
  privileged, separate-host-only zero-NIC staging engine. Exact root
  reservation manifest, Command 1 source template UUID/QCOW2/UEFI,
  plaintext volume probe and supplied source SHA256, target-host
  real KVM/storage/network preflight, duplicate VM/UUID/MAC paths,
  no other guest sharing master firmware/template, 40 GiB reserve,
  exclusive durable per-VM intent BEFORE conversion, and private
  completion note after virsh define/readback. Each clone is an
  independent shut-off QCOW2 plus independent UEFI with new swtpm
  emulator definition. NO NIC, guest boot or Windows changes.
- scripts/test_command2_portable_zero_nic_stager.py: 13 mocked
  negative/positive-path test methods, including synthetic tiny copy.
- scripts/command2_portable_zero_nic_entrypoint.py integrates count,
  independent source/master check, current host UUID/MAC inventory,
  actual master RAM demand, identity blueprint, exclusive reservation,
  per-VM private Windows JSON config, and separately confirmed staging.
  It is an unapproved development-stage frontend, NOT complete Command2.
- scripts/test_command2_portable_zero_nic_entrypoint.py: seven mocked
  frontend tests: SSL-55 denial, plan-only, interactive/root gates,
  source inventory, staged config manifests, master RAM sizing.
- scripts/command2_windows_guest_config.py: pure strict hostname/IP
  JSON config generator, based on reserved guest identity and subnet.
- scripts/command2_guest_personalize.ps1: guest-local PowerShell
  Plan/Identity/Network/Verify phases. Identity requires ZERO NIC;
  network phase requires independently proven host isolation, one
  exact reserved MAC, no default route; this is NOT yet automatically
  installed, delivered, or invoked in Windows.
- scripts/test_command2_windows_guest_config.py: four offline checks.
- CI workflow updated with Python 3.10/3.12 synthetic tests and
  Windows GitHub Actions AST syntax parse of the guest script.
- docs/COMMAND2_PORTABLE_ZERO_NIC_STAGER.md and
  docs/COMMAND2_WINDOWS_GUEST_PERSONALIZATION.md explain limits.

TEST STATUS: New mocked tests and PowerShell parser have been committed
but their CI conclusions and physical host acceptance remain
**NOT VERIFIED** in this session. Do not claim they passed merely
because source code is in development. The older user-uploaded
37/37 offline preflight tests are confirmed, but do not cover the
new integrated write-capable staging code.

UNFINISHED: fully portable Command 1 prerequisite installer/master
bootstrap; actual Windows config-drive bootstrap/install and verified
guest rename/reboot; independent CAPE and INetSim network guard
persisted without global firewall changes; real IPv4/IPv6 negative
egress; safely attached NIC; verified static IP in Windows; guest
TPM/UEFI cold snapshot and RESTORE; parallel CAPE analyses; independent
fresh-host two-command end-to-end acceptance. No actual VMs were
created/modified in this session. NEVER create more VMs on SSL-55.


## ACTIVE USER DIRECTIVE: finish substantial work before replying

The user explicitly objects to intermediate assistant returns after each
commit or CI success: 'complete the work' and return only at genuine
completion or required operator action. Do not narrate routine
develop/commit/CI tasks as reasons for the user to reply. The hourly
`CAPE Development & CI Watch` automation can carry out discrete GitHub
tasks and report significant milestones or blockers. This does NOT
allow continuous interactive terminal execution; do not claim
background work outside actual scheduled runs.

2026-10-11 new guarded implementation on development:
- scripts/command2_identity_reservation_journal.py: a non-SSL55-only,
  private user-owned 0700-directory, flock-protected, fsync'd,
  exclusive publish reservation record. Exact replay is idempotent;
  altered candidate blueprint conflicts; pending crash artifacts
  fail closed; no VM actions. 10 synthetic tests in
  scripts/test_command2_identity_reservation_journal.py.
- Python 3.10/3.12 Actions run 38137777653 on
  e9452c7b1c1cdff1f669b5973b21b8f37f121e65 completed SUCCESS,
  validating the directory-symlink guard tests.
- scripts/command2_portable_zero_nic_xml.py pure XML renderer validates
  exact supplied source KVM domain, QCOW2, OVMF and emulated TPM2
  paths and replaces UUID/genid, disk, NVRAM; strips all source NICs,
  unsafe attached devices, inherited cdrom media, metadata, and
  binds VNC/SPICE graphics to localhost. No VM started/defined.
- scripts/test_command2_portable_zero_nic_xml.py adds 10 mocked XML
  tests; development Actions run 38137920344 on
  da93ff8ec81bd9c2926ca4b824350d5a5ddf1b56 completed SUCCESS,
  confirming Python 3.10/3.12 offline regression steps.
- docs/COMMAND2_IDENTITY_RESERVATION_JOURNAL.md and
  docs/COMMAND2_PORTABLE_ZERO_NIC_XML.md added.

These are components, not full portable Command 2. Remaining:
actual target-host privileged staging under crash-safe manifest with
authoritative inventory proof; independent QCOW2/UEFI/swtpm full clone;
Windows hostname/static IP automation; safely persisting independent
firewall/network guard; IPv4+IPv6 negative egress; cold restore
verification; real CAPE parallel guest acceptance on OTHER authorized
host. SSL-55 remains NO new VMs, backups, NIC changes, network or
master modifications. No request for further SSL-55 commands now.



## VERIFIED GitHub Actions regression recovery — 2026-10-11 11:54 UTC

Operator's GitHub Actions screenshot showed repeated red runs on
`development`. Examined actual connected GitHub Actions job logs.
Found and FIXED two independent **test-fixture** problems:

1. `scripts/test_command2_cold_checkpoint.py`
   `test_source_change_while_copying_refused` used same-size immediate
   rewrites (mtime/ctime could be indistinguishable on CI); then tried
   to access an SSL-55-only storage path. Changed synthetic write length
   from 30 to 31 bytes, assert failure before any storage check, and
   ensure no output artifact is created. Commit `168edb15ea12add43a9dcf6bb174b9e68a54a487`.
2. `scripts/test_command2_upload_approved_reports.py`
   literal `assertNotIn("sudo ", text)` failed on the safe COMMENT
   `# No sudo or VM access` in uploader. Restrict static prohibited
   command tests to uncommented shell source, add regression proving
   executable sudo remains detected, leave live uploader unchanged.
   Commit `16bebe20adb5e263c92c9dfd6b89473c67c6884f`.

**ACTUAL GitHub Actions evidence:** workflow
`Command 2 cold clone checkpoint (offline)`, run **#44**
(ID `38137282518`), head SHA
`16bebe20adb5e263c92c9dfd6b89473c67c6884f`, final
`status=completed`, `conclusion=success` on 2026-10-11T11:54:49Z.
`https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38137282518`.
Python 3.10 and 3.12 offline test stages passed, including staged
model and count-scaling tests. This is verified CI, but does NOT
prove real VM deployment, networking, guest identity application,
host portability or cold-state restoration.

STOP editing unrelated logic merely to fix previous historical red
runs; GitHub history preserves earlier failures, but run #44 is the
latest validated fix. On new code changes, inspect NEW CI run and
job logs through the GitHub connector's generic fetch endpoint
(`https://api.github.com/repos/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs?branch=development&per_page=10`),
then the run jobs/logs connectors, and do not claim a new run passed
until the run conclusion is SUCCESS.

SSL-55 reference-only hard ban remains. No VM, host, network or
cold-backup actions were executed to fix CI.

## Active development continuation — 2026-10-11

The operator requested independent continuation and a return only for
important completion/blocker notices, not routine pasted-command checks.
Authorized GitHub-only implementation and synthetic offline testing
continue on `development`; **DO NOT operate any new VM on SSL-55**.

New safety/specification module:
`scripts/command2_portable_sequence_model.py` models exact, ordered
no-NIC clone lifecycle and requires separate evidence gates for
durable UUID/MAC reservations, independent QCOW2, UEFI/swtpm,
zero-NIC guest boot, unique hostname, independent IPv4/IPv6 negative
egress plus reboot-persistent isolation, dedicated NIC, static IP,
CAPE reachability, full cold disk+NVRAM+TPM restore and approved benign
analysis. All transitions remain IN-MEMORY SIMULATION ONLY;
real host evidence is explicitly NOT authenticated; no deployment.
`scripts/test_command2_portable_sequence_model.py` adds 13 mocked
state-machine tests and guards against skipping/forging proof states.
Development CI now includes Python 3.10/3.12 tests; no passing
CI result yet confirmed. See docs/COMMAND2_PORTABLE_SEQUENCE_GATES.md.

Portable **planning** count is no longer arbitrarily capped at 16:
pure model safety cap raised to 4096 with network CIDR, RAM, disk
and CPU constraints expected to impose practical tighter limits.
Separate SSL-55-specific staged-clone script remains hard-blocked
and its legacy 16-target size is NOT expanded or run. Added 32-guest
synthetic examples/tests to fresh-host planner, target preflight,
identity blueprint and sequence model. NONE are real VMs.
Read-only host preflight inspects collision artifact paths only
for the requested N, not all 4096 possible indices.

**Current blockers to COMPLETION:** no approved separate target
machine is connected or physical host verification recorded.
Cross-machine Command 1 source baseline, actual clone creation
and durable identity reservation, Windows guest hostname/IP
personalization, fail-closed network guard IPv4/IPv6 runtime
isolation, TPM/NVRAM/disk cold restore, CAPE concurrent acceptance
are unfinished. 37/37 historical offline tests from a different
earlier commit passed via auto-uploaded report; NEW stage/scaling
tests are not yet confirmed passing in real CI/local execution.
No SSL-55 terminal action is requested now.



## 2026-10-11 portable identity allocation milestone (OFFLINE ONLY)

The operator uploaded CAPE_Command2_OfflinePreflightTests_20261011_103641_ZnSj1eKa.txt.
Verified results: fresh-count 7/7, host preflight 17/17, cold
checkpoint 13/13: total **37/37 PASS**; final report marker
COMMAND2_OFFLINE_PREFLIGHT_TESTS_PASS. This is actual SSL55 offline
mock acceptance, NOT a live deployment or restored snapshot.

New development files:
- scripts/command2_portable_identity_allocator.py creates a PURE
  candidate allocation manifest for a validated fresh-count model:
  unique random libvirt UUIDv4 and Windows generation UUIDv4 per VM,
  QEMU unicast locally administered MAC 52:54:00:xx:xx:xx, independent
  TPM directory identity proposal, independent disk/NVRAM destination,
  ordered WIN11-N and 192.168.240.(100+N) proposed guest settings.
  It refuses duplicate MAC/UUID inventory, unsafe row ordering,
  malformed guest flags, insufficient conservative capacity.
  It performs NO IO against libvirt/host and does not persist plans;
  future staging needs a locked, durable, validated journal with
  complete authoritative existing UUID/MAC inventory and full
  host authorization. Random previews are not durable reservations.
- scripts/test_command2_portable_identity_allocator.py contains eight
  new synthetic negative-path tests and covers 1/5/16 VMs;
  tests committed to Python 3.10/3.12 development CI, but ACTUAL
  offline and GitHub Actions results are not yet independently seen.

SSL-55 remains reference-only: NO new guests, copies, snapshots,
network activation, or added disk allocations. The actual staging
engine, safe VM memory/CPU allocation, guest Windows IP application,
AppArmor + TPM boot compatibility, snapshot restore and network
containment remain unimplemented/unverified.

## NEW offline acceptance for portable preflight

- scripts/command2_target_host_preflight_offline_acceptance.sh runs
  synthetic fresh-host planning, 17 new target preflight tests, and
  cold-checkpoint safety regressions under unprivileged Python, writing
  one private TXT report in the operator HOME. It does not call sudo,
  enumerate the live libvirt host, allocate VM disks, or change networks.
- This separate test-only runner MAY be used on SSL-55; it NEVER
  runs the live host preflight or creates additional VMs there.
- The first real test report is pending. Do not claim CI or test pass
  until evidence is reviewed. Any failing test must be fixed in
  development and rerun without modifying the Windows guests.
- The portable live target preflight itself is for another approved
  supported machine, not SSL-55. deploy_authorized remains false.

## NEW development stage — target-host READ-ONLY preflight (2026-10-11)

User requested continued development under hard restriction: no new VMs
and no storage-heavy cold copies on SSL-55. GitHub development only.

- scripts/command2_target_host_preflight.py: read-only real target-host
  inventory/evaluation of candidate Ubuntu 22.04/24.04 and KVM,
  usable resources, virsh/qemu-img/ip, Command 1 master state,
  independent QCOW2 template metadata, collisions, kernel IPv4
  routes/address overlaps, inactive/active libvirt network conflicts,
  and dynamic uplink from a kernel-only ip route get (no traffic).
- scripts/test_command2_target_host_preflight.py: mocked negative-path
  tests including overlap, missing inventory, inadequate resources,
  reference-host refusal, dynamic Ethernet/Wi-Fi interface discovery,
  advisory subnet alternatives, and no mutation commands.
- docs/COMMAND2_TARGET_HOST_PREFLIGHT.md: detailed support and scope.
- Development Python 3.10 and 3.12 CI updated; actual job conclusion
  still needs verification; mocks are not physical acceptance.

Existing scripts/command2_cold_checkpoint.py now refuses CAPTURE
on SSL-55 before inspecting guest or allocating any storage, even if
someone provides a confirmation phrase. Plan/verify are unchanged.
Capture test fixture uses a synthetic NON-SSL55 hostname; the refusal
is tested explicitly. Do not bypass the guard by renaming the host.

Default isolated CIDR remains 192.168.240.0/24; candidate fallback
is an advisory recommendation ONLY, never an implicit IP change.
Preflight never changes routing/firewall/VMs. The candidate Ubuntu
matrix, VM memory plan and max-16 count are not production-certified.
deploy_authorized is ALWAYS false. No target machine tested yet.

## AUTO-REPORT DELIVERY — 2026-10-11 (operator requested no manual uploads)

Verified connector access to private Google Drive folder
CAPE_SSL55_Reports (Drive ID 1sWwYzqTgc2jLC8eC3_UOJ3DFEBBfNcAa).
An hourly conditional ChatGPT report watch has been scheduled.
Actual scheduled Drive read/notification is not yet proven.

New dev-only report pipeline:
- scripts/command2_upload_approved_reports.sh
- scripts/command2_setup_auto_report_sync.sh
- scripts/test_command2_upload_approved_reports.py
- docs/COMMAND2_AUTOMATED_REPORT_DELIVERY.md
The one-time installer is a user-level systemd timer, NOT an SSH
agent or root service. It requires a separate operator-approved
rclone Google Drive OAuth remote named cape_reports with drive.file
scope, creating a separate rclone-owned folder CAPE_SSL55_AutoReports.
Uses only a small user-approved reports directory and an exact
offline-test TXT basename allowlist, excludes symlinks/likely secrets,
max 256KiB; no host VM checks or changes, no unrestricted home sync.
Earlier safe offline test reports can be backfilled by the installer.
The offline preflight acceptance runner now writes into approved
folder if configured securely, otherwise retains old HOME behavior.

CRITICAL: User has not yet configured Ubuntu rclone or run installer.
The reporter-to-Drive link is NOT active until one-time OAuth and
local timer setup succeed. No production upload or alert verified.
Google Drive's ChatGPT connection is distinct from SSL55's local
Ubuntu file access. No passwords, tokens or keys may be pasted.

## Workflow preference and verified offline testing — 2026-10-11

Operator wants to minimize back-and-forth terminal commands/uploads
by allowing a limited approved report-folder or connected-source
workflow. **Do not interpret this as authorization to access SSL-55
by remote shell, request credentials, enable SSH, or perform writes.**
Current Chat session can directly maintain GitHub development; it
cannot independently open SSL-55 terminal or home-directory files.
For future diagnostics, use a single reviewed read-only collector
writing redacted TXT reports to an operator-controlled folder.
User may upload the single report, or deliberately connect a
report-only sanctioned cloud folder if institutional policy permits.
Never upload full TPM state, BitLocker materials, OwnerAuth, keys,
unredacted campus network configuration or malware samples.
SSL-55 remains NO EXTRA VMs and NO COLD BACKUPS; risky actions
require explicit operator review and must target other approved host.

ACTUAL operator report:
CAPE_Command2_OfflinePreflightTests_20261011_103641_ZnSj1eKa.txt.
Verified offline acceptance groups: portable count model 7/7,
target-host preflight 17/17, checkpoint mocked guards 13/13;
37/37 tests passed; final
RESULT: COMMAND2_OFFLINE_PREFLIGHT_TESTS_PASS.
Tests are synthetic and do NOT prove host deploy, egress isolation
or VM snapshot restore. This is the latest REAL operator report.

## VERIFIED end-to-end automatic TXT upload — 2026-10-11 11:33 UTC

New operator's SSL-55 screenshot showed user timer installed and enabled.
The FIRST ACTUAL report transfer subsequently SUCCEEDED without
manual Google Drive upload or another terminal command:

- Auto Drive folder: CAPE_SSL55_AutoReports, ID
  1_cqrywTq5FWD1APk97v3cNXiqOc7IMcH.
- File ID: 1xICk9mTLU68eSV-pm4qk6rzJYthyscie;
  CAPE_Command2_OfflinePreflightTests_20261011_103641_ZnSj1eKa.txt;
  6,046 bytes; Drive created timestamp 2026-10-11T11:33:37Z.
- Assistant actually fetched and read file via the connected
  Google Drive tool, verifying 7/7 pure VM-count tests, 17/17
  synthetic target-host preflight tests, 13/13 mock cold
  checkpoint tests, total 37/37 passed, with explicit
  RESULT: COMMAND2_OFFLINE_PREFLIGHT_TESTS_PASS.
- This is REAL acceptance for the limited TXT upload pipeline
  and Drive read integration, NOT VM deployment, network
  isolation, snapshot restore, or future hourly scheduled runs.
- Initial folder emptiness was expected: setup backfill creates
  local copy with fresh mtime and uploader waits -mmin +1;
  the later timer successfully transferred it.

The hourly CAPE Report Review & Development automation was updated
to treat this specific file as ALREADY REVIEWED, avoiding repetitive
notification or repeat fixes. Future approved offline reports will
be read and safe code fixes may be made on development only.
Neither Cloud Drive nor ChatGPT exposes an arbitrary shell on SSL-55.
Do not claim unattended operation survives user logout without
first verifying the systemd user-manager lifecycle.

The next offline-test acceptance runner now includes pure guest
identity candidate tests so a future approved report can cover
the additional code without changing VM state.

## 2026-10-11 continuation: automatic report verification and candidate identities

Operator SSL-55 screenshot confirms the private user-level
`cape-approved-report-upload.timer` was enabled, with the next
scheduled invocation around 11:32 UTC. The connected Drive folder
`CAPE_SSL55_AutoReports` EXISTS and is readable via ChatGPT,
but during initial follow-up it had **zero report files**.
Do not claim end-to-end auto-upload success until a report is actually
fetched from this folder. Setup copies earlier reports to the allowlist
directory and `find -mmin +1` intentionally delays their selection;
the first manual service trigger may have run too soon.
An hourly condition-watch automation can review new Drive reports and
make safe, narrow `development` GitHub code/test fixes when possible.
It is NOT a remote shell, continuous deployment, or instant notification.

NEW development-only module:
`scripts/command2_guest_identity_blueprint.py` proposes unique candidate
libvirt UUIDs, SMBIOS generation IDs, local-admin MACs, Windows
hostnames and isolated IPv4 assignments for TOTAL N=1..16 using a
preflight record and supplied occupied identity inventories.
Fresh random values are NOT reserved/persisted or applied. It
validates exact guest numbering, artifact paths, CIDR and IP offset,
rejects reference SSL-55, malformed inventories and collisions.
`scripts/test_command2_guest_identity_blueprint.py` adds 13 mocked
tests. Development Python 3.10/3.12 CI includes the new tests, but
the test results and CI conclusion must be independently verified.
`docs/COMMAND2_IDENTITY_BLUEPRINT.md` documents limits and future
durable lock/reservation/rollback acceptance.
Read-only target preflight now includes analysis_subnet in its output.

Still pending: independent target-host real acceptance, full VM
creation/personality, complete disk/UEFI/TPM restore, CAPE network
and IPv4/IPv6 containment validation. NO extra VMs on SSL-55.

## OPERATOR DIRECTIVE — SSL-55 IS REFERENCE-ONLY (2026-10-11)

**HARD RESTRICTION:** DO NOT create, stage, define, boot or allocate
ANY ADDITIONAL Windows VMs on SSL-55. The operator wants to preserve
the existing `win11`, `win11_trial_1` and successfully verified
`win11_1`. Do not create `win11_2`, `win11_3` etc. on this host,
and do not allocate disk-heavy clone images or cold backup copies there
given only ~96 GiB free. Leave CAPE analysis network inactive and
never run malware before isolation acceptance.

**PRIMARY GOAL:** a portable, count-driven Command 2 for a **DIFFERENT,
supported, sufficiently provisioned machine**. After that machine
has its own independently verified Command 1 Windows master/template,
Command 2 asks for TOTAL number of analysis VMs N and produces
`win11_1` ... `win11_N` with unique guest hostnames, MACs, IPs,
libvirt UUIDs, UEFI and TPM, secure isolation, CAPE reachability
and clean restore readiness. Testing counts and failure cases on SSL-55
must use pure models, synthetic mocks, host read-only metadata or
the existing Windows clone ONLY; multi-VM physical acceptance must be
performed on a **separate approved host with capacity**, not SSL-55.

**Code protection:** `scripts/command2_stage_independent_clones.py`
now calls `prohibit_reference_host_staging()` for `--mode stage`
and refuses SSL-55 BEFORE even creating its stage-lock file.
Regression tests cover the hostname and FQDN. This is a safety
refusal for the legacy SSL-55 adapter, not the finished portable
Command 2 installer. Other future write entrypoints must implement
the same reference-host protection.

**LAST OPERATOR TXT REPORT:** `CAPE_Command2A_ColdAndCountPlan_20261011_100418_seoiKLvu.txt`
showed 12 offline cold-checkpoint tests: 10 passed,
1 FAIL and 1 ERROR. Both were **test-fixture bugs**:
  - temp directories made with default modes caused a mocked
    non-root `verify` test to fail before its intended manifest test;
  - mocked complete capture omitted a simulated privileged context in
    its subsequent `verify` call.
The launcher stopped on unit tests and DID NOT run cold-checkpoint or
VM-count host plans. The tests were fixed in `development`; production
owner checks were NOT relaxed. All 22 existing mocked checkpoint and
continuation tests then passed locally as an unprivileged user. Seven
additional fresh-host pure-planner tests also passed locally. The
new GitHub Actions results remain unverified until checked separately.

**NEW portable planning model:** `scripts/command2_portable_fresh_count_plan.py`
generates 1–16 total guest names/IPs from supplied host-specific paths,
CIDR and resources and refuses colliding domains/paths, unsafe example
NAT subnet and insufficient estimated capacity. It performs ZERO host
changes. It is not a portable deployer: actual host discovery,
Windows master validation, unique runtime IDs, isolation and VM
creation are NOT implemented or accepted.

**NO NEXT SSL-55 STAGING COMMAND IS AUTHORIZED.**

This is a state handoff, not a complete deployment approval. User builds
incrementally on shared Ubuntu host SSL-55; user pastes carefully guarded
terminal commands and uploads one report instead of repeated console output.

## 2026-10-11 developer continuation: guarded cold capture + count reconciliation

**NEW DEV-ONLY IMPLEMENTATION; ZERO NEW SSL-55 HOST OPERATIONS.**
- scripts/command2_cold_checkpoint.py implements read-only plan,
  separately confirmed cold capture with exact clone-only disk/UEFI/swtpm
  checksums + private manifest, and read-only verify. It refuses capture
  on running clone or active clone emulator/swtpm; preserves incomplete
  artifacts for manual review and never touches original master.
  There is NO restore/apply implementation and NO host-accepted checkpoint.
- scripts/command2_continuation_plan.py plans TOTAL requested clone
  count, safely preserving existing win11_1; plans only missing
  win11_2..win11_5 when total=5; refuses collisions and never stages VMs.
- scripts/command2_cold_and_count_plan_acceptance.sh performs a single
  read-only TXT plan on the host AFTER offline unit tests.
- Four new unit test modules: 22 local synthetic tests passed, including
  full fake capture/verify, partial failure, peer shared-disk/NVRAM
  collision and malicious path cases.
  New GitHub Actions workflow targets Python 3.10 and 3.12;
  CI conclusion is not yet independently confirmed.
- **Extra shared-host storage safety gate**: capture now needs at least
  104 GiB free (64 GiB max copy +30 GiB reserve +10 GiB margin).
  Last reported 96.11 GiB would BLOCK capture. Four additional clones
  need an estimated 286 GiB at the current 64 GiB-per-clone policy.
- Implementation and future restore limitations documented in
  docs/COMMAND2_COLD_CAPTURE_IMPLEMENTATION.md.

**Immediate next operator gate:** SHA-pinned read-only consolidated
cold checkpoint + total count plan, then upload its ONE TXT report.
Do not shut down VM, start capture, add NICs, enable analysis network,
make master/TPM changes or run malware until review and storage resolution.
Command 2 is NOT complete: snapshot restore, unique guest networking,
guard persistence, isolation tests, dual-VM acceptance and portability
are still outstanding.

## Verified on SSL-55 (actual operator TXT reports)
- Protected original Windows master `win11` (UUID
  `289d89be-68ec-4c62-90e1-ea930849266f`) **SHUT OFF**;
  BitLocker-derived protected QCOW2 chain, original UEFI variables and
  original swtpm must remain unchanged. Original VM currently references
  `/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2`
  in its inactive libvirt domain; master preservation backup:
  `/var/backups/cape-win11-preservation/win11-state-92POdfNc`.
- Independent flat decrypted Windows 11 source:
  `/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2`
  (64 GiB virtual; no backing). Never clone from encrypted snapshot.
- First manually proven `win11_trial_1` UUID
  `e75f6fef-347d-462f-9738-4de3df6bfa74` currently RUNNING, ZERO NICs.
  Windows desktop, Python 3.10.11, CAPE Agent v0.23 localhost TCP/8000
  `/status` confirmed INSIDE **trial only**. This DOES NOT prove that
  the standalone source template or new clone already contains Python/agent.
- **NEW ACTUAL HOST SUCCESS**, operator report
  `CAPE_Command2A_FirstClone_20261010_225052_N9tH7v9D.txt`:
  `INDEPENDENT_ZERO_NIC_CLONES_STAGED`; independent clone `win11_1`
  UUID `732b2256-ee99-41fa-881d-fbf5c476d960` created and registered
  SHUT OFF, ZERO NICs; disk
  `/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2`,
  UEFI variables
  `/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd`.
  Separate swtpm expected at staging; **its first start is now host-verified**
  in the 23:02 operator acceptance report below.
  Planned IP `192.168.240.101`, hostname `WIN11-1`, planned MAC
  `02:75:dc:63:ca:e1` are NOT yet installed or attached.
  No snapshot has been created.
- A pre-existing `win11_1.qcow2` made the earlier plan stop safely.
  **Never delete, overwrite, rename or reuse** this prior unknown disk;
  new Command 2 naming uses distinct `.command2.qcow2` /
  `.command2_VARS.fd` destination files.
- Lab libvirt network `cape-analysis-isolated` DEFINED, INACTIVE,
  autostart OFF, bridge `cape-lab0`, IPv4 `192.168.240.0/24`,
  no NAT, DHCP or libvirt DNS. It has NOT been brought up or given NICs.
- Dedicated live guard `table inet cape_analysis_guard` installed
  (hooks priority -50) matching verified
  SHA-256 `58b84446ad74ac7ea8b14aa57d94c19945baa3db7330e54c7fb2312a9577ea14`.
  **NOT reboot persistent** and **NOT runtime egress tested**. Default
  nftables.service is DISABLED; existing /etc/nftables.conf contains
  `flush ruleset`; NEVER enable/restart it blindly on this shared Docker,
  UFW, libvirt/campus host.
- Private GitHub login from SSL-55 is now confirmed:
  `gh auth login`, `gh auth setup-git`, `gh repo view` returned
  repository name. Do NOT request/reveal tokens or one-time browser codes.

## Latest newly written and OFFLINE-CI-TESTED boot gate
- `scripts/command2_boot_first_cloned_windows.py` checks EXACT
  `win11_1` UUID/disk/NVRAM, original master and running zero-NIC trial,
  inactive analysis network, AppArmor swtpm rule and RAM reserve.
  With operator authorization it installs ONLY a narrow per-clone TPM
  AppArmor policy, starts win11_1 with `virsh start --paused`,
  checks live XML has ZERO NICs / forbidden host devices, and
  `virsh resume` for benign Windows boot. A postresume safety failure
  triggers a bounded attempt to suspend ONLY `win11_1` if exact UUID.
  Script does NOT claim Windows desktop or CAPE agent actually checked.
- `scripts/command2_first_clone_benign_boot_acceptance.sh` is the
  gated **one-report** wrapper; it runs read-only `--mode plan` first,
  prompts `BOOT-NONET-WIN11-1`, then `--mode boot`, emits a private
  `CAPE_Command2A_BenignBoot_*.txt` for review. **The wrapper has now
  passed a real SSL-55 boot acceptance (see below).**
- Synthetic offline Python and Bash checks passed in
  [CI run 38093326064](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38093326064).
  Test pass is NOT proof that real boot works.
- `scripts/command2_stage_independent_clones.py` is the already
  HOST-ACCEPTED staging implementation; count 1-16, independent
  plaintext QCOW2, TPM/EFI identities, zero-NIC shut-off domains,
  partial-failure preservation. Not complete Command 2.
- `scripts/command2_clone_vms.py --apply` legacy encrypted-master
  route is explicitly BLOCKED; do not reenable without redesign.
- `scripts/guard_cape_lab_boot.py` is a tested non-destructive nft
  reconciliation library ONLY; boot service is NOT installed/enabled.
- `scripts/patch_clone_hivex_system_copy.py` is a mocked proof of
  concept for editing only a separate extracted SYSTEM hive. No disk
  writeback, production Windows personalization or NIC GUID mapping
  verified. Prototype hardcodes unverified `OLD_IP`: do NOT assume it
  matches the actual template. Never use it directly against the master.

## NEW HOST-VERIFIED milestone: first automated Command 2A clone benign boot (2026-10-10 23:02)

Actual operator report:
`CAPE_Command2A_BenignBoot_20261010_230239_cgKsSLVY.txt`

- Preflight `COMMAND2A_FIRST_BOOT_PREFLIGHT_PASSED`.
- Boot result `COMMAND2A_NEW_CLONE_BOOTED_ZERO_NICS`.
- `win11_1` UUID `732b2256-ee99-41fa-881d-fbf5c476d960`
  went from SHUT OFF to **RUNNING** after paused QEMU start, zero-NIC live
  XML check and successful CPU resume.
- New clone's exact per-domain AppArmor swtpm socket rule **INSTALLED**.
  This confirms policy preparation and successful QEMU start, **not**
  guest-side TPM readiness or Windows login.
- Master remained unchanged, the running trial remained untouched,
  analysis network remained INACTIVE, NIC count stayed ZERO.
- `windows_boot_verified`, `windows_login_verified`,
  `cape_agent_verified_in_new_guest`, hostname personalization and
  static IPv4 assignment **all remain false** in the operator report.
- No malware execution is authorized. No negative egress tests have
  been performed. **Do not repeat the boot wrapper** on the now-running
  guest; it expects an initially shut-off domain.

## NEW guest-side screenshot acceptance (2026-10-10 23:12-23:15)

Operator supplied four screenshots of the **win11_1 on QEMU/KVM**
virt-manager console. Screenshots establish:
- Windows 11 desktop opened and Administrator Windows PowerShell running.
  This is a guest-session acceptance for newly staged win11_1.
- `python --version` and `py --version` both output Python 3.10.11.
- Local request to `http://127.0.0.1:8000/status` returned a
  series of decimal UTF-8 byte values starting `123 34 109 101 115...`.
  The complete screenshot sequence was **manually decoded and parsed**
  into valid JSON:
  `{"message": "Analysis status", "status": "init", "description": ""}`.
  CAPE localhost agent **status init is GUEST-VERIFIED**. Its software
  version and HTTP response status code are not independently verified
  by this screenshot.
- `Get-NetAdapter` showed no adapters in its default output, consistent
  with the boot-script verified libvirt zero-NIC definition. No active
  guest network is authorized.
- `Get-Tpm` reported TpmPresent, TpmReady, TpmEnabled and TpmActivated
  all True. The operator screenshot also displays a sensitive `OwnerAuth`
  value; **never commit the screenshot or copy that value to documentation**.
  The new guest observation script deliberately outputs only nonsecret
  TPM readiness fields.
- `manage-bde -status C:` showed Fully Decrypted, 0.0% encrypted,
  Encryption Method None, Protection Off, Unlocked, no protectors.
- Operator separately ran `hostname` inside **win11_1** and confirmed
  the exact output `Win` (operator statement, not a screenshot). This is
  the **verified reported current guest hostname**; target remains `WIN11-1`
  and HAS NOT BEEN APPLIED. Guest static IP, network containment,
  snapshot/revert and independent CAPE agent version remain unverified.

## NEW operator screenshot: hostname AND independent guest UUID confirmed

A subsequent Administrator PowerShell screenshot inside the `win11_1`
virt-manager console shows both:
- `hostname` => **Win**
- `(Get-CimInstance Win32_ComputerSystemProduct).UUID` =>
  **732B2256-EE99-41FA-881D-FBF5C476D960** (case-insensitive match
  to this clone's actual libvirt UUID
  `732b2256-ee99-41fa-881d-fbf5c476d960`).

This passes the guest identity read-only gate. **No hostname rename,
Windows restart, snapshot, guest IP or NIC attachment has yet been
observed.** The existing offline hive IP editor has an unverified
source-IP assumption and must NOT be applied.

New reusable script `scripts/command2_guest_hostname_only.ps1` has
a read-only `Plan` default and a separately confirmed `Rename` mode.
It requires the exact guest SMBIOS UUID, current `Win`, target
`WIN11-1`, zero visible NICs, workgroup rather than domain membership,
Administrator token and a typed authorization. The rename mode uses
the Windows-native `Rename-Computer` without auto-restart, and does
not touch host/network/IP/TPM/CAPE configuration. This script was
committed to the **development** branch, but is **NOT YET verified
inside Windows**. No safe host-to-guest code transfer mechanism has
been proven; operator may test an equivalent minimal guarded PowerShell
sequence manually through the local virt-manager display.

The next accepted action is **operator-authorized clone-only hostname
rename**, followed by a deliberately separate Windows restart and
guest+host verification. Do not rename the master or trial clone. The no-NIC libvirt
identity and protected original master must be rechecked after any restart.
**There is no need to repeat the agent localhost test**: JSON `status: init`
was already decoded from screenshots. No network or malware is authorized.

The read-only optional PowerShell observation script now decodes
byte-array HTTP content as UTF-8; this code is not yet guest-executed
and its SHA was revised in development. A no-NIC guest has no guaranteed
copy/paste channel; screenshots are sufficient for this milestone.

## NEW operator screenshot: guest-only hostname rename REQUESTED (2026-10-10 23:29)

In Administrator PowerShell **inside win11_1**, operator executed:

```powershell
Rename-Computer -NewName WIN11-1
```

Windows reported: `WARNING: The changes will take effect after you
restart the computer Win.` This is evidence that the Windows-native
rename request **was accepted**, **NOT** evidence that the machine was
already restarted or that `hostname` currently equals `WIN11-1`.
The shorter manual guest command was used because the VM intentionally
has zero NICs and no verified host/guest clipboard transfer. The
guarded PowerShell script in GitHub remains **unexecuted on the guest**.

Operator separately asked which planned IP to use. **The intended
Command 2 subnet is `192.168.240.0/24`, with `win11_1` target
`192.168.240.101`** (planned bridge `cape-lab0` on isolated
`cape-analysis-isolated`). It is NOT `192.168.122.101`, which
resembles the common libvirt default NAT subnet. No actual guest IP,
NIC attachment, host-side gateway, active bridge or tested IPv4/IPv6
containment is implied by the plan. Planned `192.168.240.1` should
NOT be configured as a forwarding gateway until dedicated guard and
egress tests are complete.

**Historical next gate (NOW OPERATOR-REPORTED PASSED):** controlled *guest-only* Windows restart
of the already running `win11_1`, with zero NICs preserved, followed
by `hostname` readback => `WIN11-1`. Recheck CAPE localhost status
`init`, Python, TPM and no adapters. Do not reboot Ubuntu host,
connect any VM NIC, touch protected original master, or run malware.

## Operator-confirmed Windows hostname persisted after guest restart (2026-10-10)

After executing the Windows-native `Rename-Computer -NewName WIN11-1`
inside the previously identity-verified `win11_1`, the operator restarted
Windows and reports that `hostname` now returns **WIN11-1**. This is a
**guest-operator-reported post-reboot acceptance**, not independently
supported by a new screenshot/TXT upload. It completes the manual
hostname-rename proof, not the reusable scripted rename acceptance.

**Unverified after this restart:** CAPE localhost agent auto-start and
`/status`, Python version, TPM ready state, Windows network-adapter
inventory, host libvirt zero-NIC definition and source-master integrity.
Do not equate successful Windows restart with these checks passing.
No static `192.168.240.101` IP is assigned or guest NIC authorized;
`cape-analysis-isolated` must stay inactive.

**Next minimal guest check:** In **win11_1 PowerShell** run
`curl.exe -sS --noproxy "*" --max-time 8 http://127.0.0.1:8000/status`
and `Get-NetAdapter`. Observe the actual JSON result and absence of
guest adapters after restart. If localhost CAPE status is absent, do
not claim persistent auto-start; diagnose before any networking change.

## NEW screenshot-verified guest post-restart acceptance (2026-10-10 23:33)

User screenshot `image(20261010-233344).png` shows **inside win11_1**:

- `hostname` -> `WIN11-1` after Windows restart: **PASS**.
- `python --version` -> `Python 3.10.11`: **PASS**.
- `curl.exe http://127.0.0.1:8000/status` ->
  `{"message": "Analysis status", "status": "init", "description": ""}`:
  **guest-side localhost CAPE status PASS after restart**.
- `Get-NetAdapter` -> no adapters listed: **guest observation PASS**;
  pre-restart host libvirt XML had zero NICs. A *fresh host-side*
  libvirt check is still needed before changing networking or snapshots.

This advances real Command 2 clone guest acceptance: Windows restart,
hostname change, Python and CAPE local endpoint all verified from screenshot,
no in-guest network adapters observed. **Do not commit screenshots of
Windows TPM OwnerAuth or any other secret.**

Still **NOT verified**: automatic scripted Windows personalization on
additional clones; NIC mapping; the planned `192.168.240.101` static IP;
network activation and safety gates; dedicated nft persistence;
runtime IPv4/IPv6 negative egress checks; cloned snapshot rollback including
UEFI and swtpm state; second VM; CAPE integration; portability.

**NEXT:** Collect one READ-ONLY SSL-55 host checkpoint for exact clone,
original-master and trial state, inactive lab network, disk/NVRAM/TPM
resources and available disk/memory before designing the independent clone
snapshot and networking procedures. Do not start or stop any VM, run
`qemu-img check` on a running guest disk, touch master snapshots, attach
NICs or enable/restart global nftables.service.

## NEW development-only next acceptance: read-only SSL-55 host checkpoint

- `scripts/command2_postrestart_host_checkpoint.sh`: guarded,
  **read-only**, one-report host acceptance after guest-side successful
  Windows restart. The only write is a 0600 TXT report under the
  invoking operator's HOME. Checks exact original/trial/new guest
  states and UUIDs; reads active/inactive `win11_1` XML for exact
  separate disk, UEFI variables, TPM emulator and zero NIC/host
  passthrough; lists libvirt clone snapshots; checks the lab network
  is inactive/non-autostart and dedicated nftables guard table exists;
  collects file metadata and host free resources.
- `scripts/test_command2_postrestart_host_checkpoint.py`: offline
  Bash syntax, no-mutation and safety-marker regressions.
- The guard's existence **is not proof** of reboot persistence,
  IPv4/IPv6 containment or safe network attachment. The checkpoint
  does not snapshot, start/stop guests, read live QCOW2 contents,
  change AppArmor, modify firewall, or create networks.
- This next acceptance is **NOT HOST EXECUTED YET**. The actual report
  must be examined before a clone-only snapshot/restore plan can be
  approved. No new VM, port or network may be enabled as a result
  of the preflight alone.

## ACTUAL host-verified SSL-55 postrestart acceptance (2026-10-10 23:37)

Operator uploaded **both**:
- `CAPE_Command2A_PostRestartHost_20261010_233741_bINonScB.txt`
- `CAPE_Command2A_AuditRunner_zITqBcvd.sh`, the executable auditor.
The local Git blob hash of the uploaded runner matches the previously
reviewed GitHub script SHA `e5bc083bb1e5eeed8103a65a374543648c14318c`.

The actual TXT report ends:
`RESULT: COMMAND2A_POSTRESTART_HOST_READONLY_PASS`.

Checks verified EXACT expected UUIDs and states (`win11_1` running,
original `win11` shut off, trial running), the live and inactive
clone disk/NVRAM/TPM configuration, zero NICs and no host passthrough,
trial has zero NICs, lab libvirt network inactive and non-autostart,
and CAPE-specific nftables guard table present. **No clone snapshot
exists in libvirt metadata yet.** Only ONE Windows disk is attached:
`win11_1.command2.qcow2`, currently 31,538,872,320 bytes logical
QCOW2 file size (~29.37 GiB); clone NVRAM 540,672 bytes. Host root
filesystem: 937 GiB total, 794 GiB used, **97 GiB available (90%
used)**; RAM: 62 GiB total, **46 GiB MemAvailable**. The guard's
presence does not prove ruleset integrity, reboot persistence or
runtime IPv4/IPv6 isolation. The report does NOT inspect actual TPM
state storage nor establish rollback completeness.

**Snapshot safety decision:** Do not immediately create an ordinary
disk-only libvirt snapshot or run qemu-img on the live guest. A
restorable Windows 11 analysis baseline must account for at least the
QCOW2 disk, dedicated UEFI NVRAM, per-clone swtpm state, libvirt VM
identity/configuration, consistency and storage reservation. Disk-only
live snapshots can be crash-consistent; libvirt snapshot metadata
alone is not evidence that TPM state is snapshotted. Relevant official
references:
- https://www.libvirt.org/kbase/snapshots.html
- https://www.libvirt.org/manpages/virsh.html
- https://www.qemu.org/docs/master/specs/tpm

**New DEV-only snapshot feasibility stage:** Three files committed to
development:
- `scripts/command2_snapshot_feasibility_audit.py`: root
  read-only inspection of EXACT clone and protected host state,
  libvirt snapshot metadata, separate clone swtpm permanent state
  FILE METADATA ONLY (no TPM content), firmware/disk metadata,
  versions and conservative 64+30 GiB storage requirement.
- `scripts/test_command2_snapshot_feasibility_audit.py`:
  synthetic offline unit tests, including no-NIC and no-write gates.
- `scripts/command2_snapshot_feasibility_acceptance.sh`:
  one-report operator launcher.

These files are **not yet host-verified**; no snapshot, restoration,
Windows IP, second clone or networking is authorized by the audit.
With 97 GiB free and a 94 GiB conservative copy+reserve model, capacity
is only marginal and will need fresh revalidation before allocation.

## Snapshot audit first attempt blocked by OFFLINE TEST import (2026-10-10)

Operator ran the pinned development acceptance launcher. It confirmed
`PASS: All development files verified`, but the Python 3.12 unit-test
loader stopped before any tests ran:

```
ImportError: cannot import name 'SimpleNamespace' from 'unittest.mock'
```

This is a **test-only bug**: `SimpleNamespace` is in Python's `types`
module, not `unittest.mock`. Corrected
`scripts/test_command2_snapshot_feasibility_audit.py` to import
`from types import SimpleNamespace` and
`from unittest.mock import patch` on development.
The `set -e` launcher stopped before invoking the snapshot feasibility
host audit; **no new host acceptance report, snapshot or network change
was performed**. Re-run after a fresh SHA-pinned file download and
review actual unit-test and host audit results before continuing.
This code edit is NOT a claim that the full test suite passed.

## HOST-VERIFIED read-only swtpm/UEFI feasibility audit (2026-10-10 23:46)

Actual user report:
`CAPE_Command2A_SnapshotFeasibility_20261010_234638_eLxaAMp1.txt`.
Result: `COMMAND2A_SNAPSHOT_FEASIBILITY_READ_ONLY`, no VM changes.
This followed a separately fixed Python 3.12 `types.SimpleNamespace`
offline-test import failure. The host report proves the audit executed,
but does not itself include the unit-test console log.

Exact findings:
- `win11_1` (UUID `732b2256-ee99-41fa-881d-fbf5c476d960`)
  present with **zero NIC** live and inactive XML, independent QCOW2,
  OVMF VARS and emulated TPM 2.0.
- Clone swtpm directory:
  `/var/lib/libvirt/swtpm/732b2256-ee99-41fa-881d-fbf5c476d960/tpm2`.
  `tpm2-00.permall` is 9,234 B, UID/GID 105, mode 0600;
  `.lock` is zero length, UID/GID 105, mode 0640.
  **Contents not read. No restore tested.**
- Clone QCOW2 on-disk allocated blocks ~31,415,902,208 bytes
  (~29.26 GiB), file size 31,538,872,320 bytes; root-owned mode 0600.
  UEFI VARS 540,672 B, root-owned mode 0600.
- QEMU/qemu-img 9.2.2; libvirt 11.1.0; swtpm 0.7.3.
- No libvirt snapshot metadata exists. Analysis network inactive.
- `free_gib_approx = 96.11`; conservative independent 64 GiB cold disk
  copy + 30 GiB reserve = 94 GiB, leaving only **2.11 GiB headroom**.
  This was a PASS on numerical feasibility ONLY and explicitly reported
  `snapshot_or_copy_authorized: false`, `more_clones_authorized: false`.
- Original master UUID/state verified, disk fingerprint not checked;
  guest TPM recovery, copy/restore consistency and atomic memory/TPM
  snapshot all UNVERIFIED.

Engineering decision: **no live disk-only snapshot or direct copy of
active swtpm state**. New development-only design:
`docs/COMMAND2_COLD_CHECKPOINT_DESIGN.md` documents candidate complete
cold clone-only restore points (QCOW2 + NVRAM + swtpm + libvirt XML),
storage trade-offs, explicit operator approval, rollback/restore gates
and future overlay design. It is NOT an executed backup or a completed
implementation. Keep `win11_1` networkless; do not shut it down or
allocate disk yet solely on this read-only evidence.

## Previous guest-verification procedure (historical; do not repeat completed steps)

1. Open the **specific win11_1** console in virt-manager. Verify Windows
   completed its boot and a user session can be opened. Do not start
   original `win11`, re-run clone staging, attach NICs or start a network.
2. In the Windows PowerShell console, manually run a minimal set
   of benign local inspection commands (`hostname`, `python --version`,
   `py --version`, `Invoke-WebRequest -UseBasicParsing
   http://127.0.0.1:8000/status`, `Get-NetAdapter`). Screenshot the
   observed desktop and shell outcomes from the host console. Do NOT
   assume host/guest clipboard works: verified zero-NIC XML also forbids
   guest channels, and SPICE clipboard may require a guest agent channel.
   Never add a NIC, guest shared folder, USB passthrough or extra
   virtio channel just to move this report.
3. For future **approved** secure transfer only, the new read-only
   Windows observation script `scripts/command2_win11_1_guest_observation.ps1`
   can run inside `win11_1` and writes one guest-Desktop TXT.
   Merely storing code in GitHub does not make it accessible to a no-NIC
   guest; script is NOT yet guest-tested. If safe transfer is unavailable,
   screenshots suffice for the immediate guest checks. Return the
   screenshots/TXT for review. Check hostname, Python, local agent,
   adapters/IPs, BitLocker and TPM in stages. A missing agent must
   be repaired on this clone without compromising the original.
   Observation is not authorization for network activation.
4. Only after independent guest evidence, plan targeted clone-only
   hostname/IP personalization, safely contained NIC attachment,
   boot guard persistence and negative IPv4/IPv6 egress acceptance.

**No guest software, hostname, IP, snapshot, firewall or networking
changes are made by the observation script.** Its PowerShell behavior
remains host-unverified until executed inside win11_1.

## Still unfinished before full Command 2
1. **DONE for one guest:** screenshot-verified `WIN11-1`, Python 3.10.11,
   CAPE localhost `status: init` postrestart; TPM had passed *before*
   restart. Recheck host clone isolation/state and design clone-only
   disk/NVRAM/swtpm snapshot and restoration acceptance.
2. Safe full Windows personalization (NIC GUID + hostname/static IP) on
   clone only, proven new NIC adapter binding; approved no-egress bridge.
3. Boot-ordered dedicated guard service and persistence without flush,
   safe libvirt startup gates, genuine benign IPv4/IPv6 negative egress tests
   against campus, Docker, NAT, host management; host-to-guest TCP/8000
   positive test.
4. Create and verify per-guest snapshots including revert/reboot,
   parallel two-guest CAPE agent tests and registration.
5. Build host-portable count-driven `Command 2` from fully proven SSL-55
   stages, not hardcoded host paths, and test resource limits; initial
   staging plan reported **125 GiB host free** versus 94 GiB conservative
   required BEFORE the new copy, so check remaining space before
   requesting more VMs.
6. CAPE (Command 3) and INetSim (Command 4) remain future work.
   No malware samples may run until isolation is independently proven.

**Never modify original master chain/TPM/NVRAM, campus Ethernet
`enp0s31f6`, Wi-Fi, Docker bridges, global forwarding/firewall,
or broad AppArmor protections. All GitHub writes: development ONLY.**
