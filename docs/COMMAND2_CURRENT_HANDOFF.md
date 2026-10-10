# Command 2 — current handoff after first independent clone boot (2026-10-10)

**CANONICAL CODE BRANCH = `development`. NEVER commit to `main`.**
This is a state handoff, not a complete deployment approval. User builds
incrementally on shared Ubuntu host SSL-55; user pastes carefully guarded
terminal commands and uploads one report instead of repeated console output.

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

**Current next gate:** design safe Windows-native hostname change for
only the independently verified `win11_1` clone. Current guest name is
`Win`; target `WIN11-1`. Do not apply the existing offline hive IP editor:
it hardcodes an unverified source IP and unknown adapter GUID. A hostname
rename via the guest OS requires explicit operator authorization and a
controlled Windows restart before it takes effect. The no-NIC libvirt
identity and protected original master must be rechecked after any restart.
**There is no need to repeat the agent localhost test**: JSON `status: init`
was already decoded from screenshots. No network or malware is authorized.

The read-only optional PowerShell observation script now decodes
byte-array HTTP content as UTF-8; this code is not yet guest-executed
and its SHA was revised in development. A no-NIC guest has no guaranteed
copy/paste channel; screenshots are sufficient for this milestone.

## Next operator action: inspect the already RUNNING win11_1 Windows session

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
1. Complete inside-guest Windows desktop, TPM, Python and CAPE agent
   validation on already-running `win11_1`; plan clean restoration to a
   verified clone-only baseline if needed.
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
