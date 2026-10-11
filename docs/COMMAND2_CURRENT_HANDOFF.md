# Command 2 — current handoff after first independent clone boot (2026-10-10)

**CANONICAL CODE BRANCH = `development`. NEVER commit to `main`.**

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
