# Command 2 — current handoff after first independent clone boot (2026-10-10)

## 2026-10-12 — APPROVED ONE-NIC FIRST BOOT REMOVES A TWO-BOOT DEPENDENCY (CI PASS; NOT PRODUCTION)

Operator reiterated: do not declare Commands 1/2 complete or ask for Command 3 until ALL installation, clone/IP/CAPE/snapshot functions really work. The software target is one Command 1 on supported fresh Ubuntu plus one Command 2 for N Windows clones ending in verified CAPE RUNNING-state snapshots, and then the operator supplies Command 3 config edits. Current work remains on `development`. No SSL-55, second host, Windows VM, or malware was changed during this code pass.

Concrete code created/fixed:
- Windows `command2_guest_personalize.ps1`: retain ZERO-NIC Identity route but permit ONE reserved NIC only with explicit `-HostIsolationVerified` after host-approved evidence, exact MAC and no IPv4/IPv6 default routes. The trust is in pre-installed master SYSTEM task plus independently proven host containment; a CD checksum alone is not authentic host attestation.
- Windows `command2_guest_startup_autoconfig.ps1`: with one isolated NIC and valid `network-approved.json` attached, if the hostname differs, call Identity and restart, then on the subsequent SYSTEM startup apply/verify unique static IPv4 without default gateway. This **reduces manual two-boot transitions** but is unproven on a real Windows master.
- `command2_guarded_isolated_nic.py`: retains strict V1 receipt requiring *already witnessed zero-NIC Windows identity*; adds a separate exact-bound V2 **firstboot-pending** receipt for source-master SYSTEM bootstrap with reviewed runner/personalizer SHA-256 pins, recorded actual source-master UUID, mandatory shutoff, and ALL former physical IPv4, IPv6, L2, host-positive path, reboot persistence and firewall preservation witnesses. V2 explicitly refuses a fictitious `windows_zero_nic_identity_verified=true`.
- `command2_portable_approved_firstboot.py`: approved OTHER-host **separate operation** that validates exact V2 private acceptance, matches real source-master libvirt UUID, guarded isolated nft/network readback, independent staged QCOW2/RAW OVMF/swtpm2, exact approved CAPE_CMD2 ISO config/approval hashes and contents, expected single NIC/MAC, no host passthrough, sufficient RAM; starts one guest PAUSED, checks live XML/guard before resume. On failed live checks leaves guest paused; no auto destroy/shutdown/retry. This explicitly does NOT prove Windows rename/IP/Agent.
- `command2_portable_workflow.py`: new `approved-firstboot` and all-N `approved-firstboot-batch` with canonical per-VM receipt paths `win11_N.firstboot-network-receipt.json`, real all-VM preflight and **aggregate** VM RAM capacity gate before any boot; sequential guarded individually approved child operations, stop/preserve on first failure.
- Regression tests added for v1/v2 receipt strictness, one-NIC firstboot reject NAT/hostdev/wrong optical, paused failure no resume, all-N receipt path and memory capacity. Full aggregate Python 3.10 and Windows PowerShell parser CI [run 38259205735](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38259205735) **SUCCESS** at `e56ee2cf71abe9eee4e3cb023cc1c5622da51dcf`; later documentation-only changes are not physical tests. [Operator workflow](COMMAND2_UNIFIED_OPERATOR_WORKFLOW.md) explains exact routes.

**No completion claim:** existing Command1 `command1_pre_vm.sh` remains only a partial pre-VM installer and does NOT install the trusted task inside Windows or the full CAPE/INetSim/golden Windows master. No physical guest executed the new PowerShell path, no firstboot receipts are cryptographically or physically established, no real two-VM network/CAPE run, no full swtpm+OVMF running memory/disk reset proved. SSL-55 `win11_1` remains last measured RUNNING with RAW UEFI NVRAM and NO snapshot. We cannot safely fix that by editing GitHub: converting RAW firmware while RUNNING or blindly calling `virsh snapshot-create` risks preserved state. The last cold backup was checksum-verified but NOT restoration-tested. The snapshot approach requires actual hardware-backed proof or a carefully engineered CAPE full-state machinery. This is the **critical blocker** before saying Command 2 is done.

Upstream technical rationale: [libvirt v10.9 release note](https://libvirt.org/news.html) allows internal UEFI snapshots with QCOW2 NVRAM, but [libvirt developers on swtpm snapshot state](https://lists.libvirt.org/archives/list/users%40lists.libvirt.org/message/QGU2EQQSUC6X6CGK4QPTHH2EIWMOXHOP/) previously reported that TPM state wasn't coordinated with snapshots; feature existence alone cannot establish atomic Windows/TPM revert on SSL-55. Real test on a disposable guest and then carefully approved existing SSL-55 clone change is essential, not a second-host *full three-command test* yet.

## 2026-10-12 13:35 UTC — ACTUAL COMMAND1/COMMAND2 GUEST BOOTSTRAP + COUNTED BOOT PROGRESS, CI GREEN

Operator's locked sequence: finish Command1 + Command2 *software implementations* first, then obtain exact Command3 edits, then run all three together on another host. No other-host inventory requested now. Work remains only on `development`; original SSL55 `win11` and `win11_trial_1` untouched.

Engineering changes since earlier handoff:
- `scripts/command2_guest_startup_autoconfig.ps1` has **new READ-ONLY `-Mode Verify`** plus SHA-pinned source/installed runner and personalization script checks for first-time `Install`. Requires exact source SMBIOS UUID, audits SYSTEM ServiceAccount/Highest startup task, only one exact PowerShell action and boot trigger. No password/credential installation, automatic host/VM mutation or source-master install. Real Windows scheduled-task behavior NOT tested; source master task NOT installed automatically by Command1.
- `scripts/command2_guest_personalize.ps1` now blocks mismatched IP prefix/duplicate reservations, *same IP from DHCP counted as static*, any unexpected IPv4/IPv6 default route on isolated NIC, and rechecks DHCP/IP/routes AFTER changes. New static regression tests; PowerShell syntax tested in CI, not real Windows.
- NEW `scripts/command2_portable_identity_boot.py` other-host-only one-VM benign identity boot: checks canonical private journal, exact shut-off master/clone UUID, standalone QCOW2, dedicated raw OVMF/swtpm2, SHA-matched readonly identity ISO inserted, zero NIC or host passthrough, RAM and no snapshot. Boot uses `virsh start --paused`, verifies LIVE domain isolation before resume, and leaves paused for operator review if live XML differs. Never starts protected SSL55. Does NOT prove Windows hostname, task execution or CAPE agent. Synthetic unit tests.
- `scripts/command2_portable_workflow.py` exposes `identity-boot` and new `identity-boot-batch`, including all-N preflight and ordered guarded individually approved child boots. On failure, preserve state, do not automatically destroy or retry. Together with existing `identity-batch` this removes repeated per-VM CLI invocations for media and first-boot stages. **Still NOT a complete two-command automatic deployment**; Windows identity witness, guest shutdown, NIC/IP, real isolation, cold restore, TPM/UEFI running snapshots and CAPE concurrent analyses remain pending.
- CI complete SUCCESS on [run 38256510201](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38256510201) for count-driven identity-boot batch. Earlier [run 38255931128](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38255931128) passed guarded pause/resume boot helper.
- Latest real SSL55 evidence remains `CAPE_Command2_Win11_1_SnapshotReadiness_20261012_110035.txt`: clone RUNNING with RAW pflash OVMF, independent swtpm, no libvirt running snapshot, saved complete cold backup not yet restore-tested, available 64.74GiB and minimum 40GiB reserve. No SSL55 snapshot fix was applied. No software code commit can certify a real TPM-consistent memory snapshot without physical acceptance.

**Next real coding priorities (do not switch to Command3 or second host):** implement a first-class Command1 host/CAPE+Windows master installer (upstream installer and Windows provisioning remain incomplete); integrate trusted source-master SYSTEM task installation/attestation; add safely accepted Windows hostname and isolated NIC/static-IP transitions to a single counted Command2 run; implement and validate real full-state running-snapshot/TPM reset rather than metadata-only admission. Do not mark Command2 complete prematurely. SSL55 remains reference only until a reviewed existing-clone action can be safely approved. No malware.

## User-directed execution order — three commands, no other-host work yet (2026-10-12)

The operator explicitly corrected our sequence: **finish the actual Command 1 and Command 2 implementations first**, including fresh-supported-Ubuntu prerequisite/bootstrap, CAPE + Windows master, exact N Windows 11 clones, fully automatic unique static IP/hostname/TPM/firmware, actual isolated guest networking/CAPE agent, and a final **RUNNING** snapshot per VM with a defensible revert strategy. The operator will then supply the relatively simple Command 3 configuration edits. Only **after** that integration is coded should we schedule a complete three-command acceptance run on a second machine. DO NOT ask for a second-host inventory now. Do not mistake an orchestration front end or passing mocked CI for fulfilled two-command automation.

The user also specifically wants the reference SSL-55 `win11_1` snapshot issue resolved before considering Command 2 complete. As last **actually observed** on 2026-10-12 11:00 UTC: it is RUNNING with RAW pflash OVMF, swtpm2 and **NO libvirt snapshot**; byte-verified cold backup exists, but restore was not tested. Do not force snapshot, convert active RAW firmware, power off protected `win11`/`win11_trial_1`, or assert it is fixed remotely. No current terminal access. There is no demonstrated safe automatic RAM+disk+OVMF+TPM running revert on SSL-55; real protected-host interventions need appropriate recovery admission and explicit scoped authorization.

**Active engineering, not finished:** `scripts/command2_portable_workflow.py` adds `--phase identity-batch --mode plan|apply` with a single count-driven reserved journal. One all-VM zero-NIC/SHUT-OFF identity ISO preflight precedes any changes; apply invokes existing individual guarded ISO build+attach under per-VM typed approval, preserving partial artifacts on error. No arbitrary vm count regeneration, no guest boots/NICs/IPs/snapshots/CAPE registration. Offline regression tests were added and [run 38253664839](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38253664839) passed both jobs on commit `1b66c4d65c1cd7b3ea1fcfa075eab150e09b0eea`. This **eliminates 2N manual CLI invocations** for the optical identity stage but is not the final one-command setup. Next implement actually missing Command1 full installer and trusted Windows bootstrap integration, then Command2 ordered benign guest boot/network orchestration, persistent isolation proof/recovery, full running snapshot semantics and multiple independent clone acceptance, instead of producing only more inventories and planners.

**Three-command design and INetSim caveat:** Older repository text outlines four components with INetSim split separately. The operator now requests three externally invoked commands: (1) CAPE+master, (2) N-clone full readiness including snapshots, (3) operator-supplied CAPE configuration changes. Preserve INetSim scope and determine its exact placement from the user's verified manual setup when Command 3 is described; do not silently drop or misassign required INetSim work.

## 2026-10-12 12:54 UTC — RESERVED SNAPSHOT INVENTORY FAIL-CLOSED HARDENING, CI GREEN

On `development`, commit `c879309124799d0c9dbc25636759c555df44bbaf` passed both GitHub Actions jobs at [run 38251784009](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38251784009). Updated `scripts/command2_snapshot_path_admission.py` and its synthetic tests: when invoked with the count-driven root-private reservation journal, the planner verifies **reserved exact disk file, original RAW or derived QCOW2 NVRAM file and isolated NIC MAC**, in addition to VM/UUID. Refuses duplicated reserved disk/NVRAM/MAC, detects two guests accidentally pointing to the same live disk or UEFI path, and checks the actual RUNNING XML against the saved XML for critical device drift. Bare `--guest` inventory remains explicitly advisory (`all_guests_bound_to_private_journal=false`) and never signals running-revert acceptance. The inventory is READ ONLY, not a snapshot/TPM restore.

This removes a misleading readiness inference from only name/UUID and is essential before physical multi-clone tests. **SSL-55 snapshot is NOT created**: real `win11_1` still RUNNING with RAW pflash, swtpm2, and zero libvirt snapshots as last measured (2026-10-12 11:00 UTC). Nothing changed on either host. The second disposable Ubuntu/KVM system is available according to the operator but still lacks an actual submitted host profile, canonical tested cloned Windows master, and two-machine benign TPM/UEFI/revert acceptance. Do not touch SSL-55 master/trial or claim Command 2 finished; next execute *read-only* second-host resource and hypervisor inventory, then physically acceptance-test explicit approved phases with complete cold backups and isolation. Command 3 remains LOCKED.


## 2026-10-12 12:35 UTC — COUNT-DRIVEN SNAPSHOT INVENTORY NOW ACCEPTS PRIVATE STAGING JOURNAL

`scripts/command2_snapshot_path_admission.py` now accepts `--journal /absolute/path/command2-identity-reservation.json` for approved other-host root-only 0700 staging journal (matching existing Command2 N-clone reservation schema, fixed ordered guest names/UUIDs). This removes hand-entering every UUID and shows per guest where firmware, NIC, native running snapshot or TPM/UEFI revert evidence still blocks deployment. Host `CSE-SSL-55` still may use only explicit `--reference-ssl55` (read-only) and cannot use journal for other hosts. No host, disk, VM, network, snapshot modifications; not a finished Command2 runner. Tests added for exact journal host/order and protected reference. Initial CI exposed malformed escaped newline in the new argparse section, fixed in commit `92d9f4e48aa399ade378e41c2b2efae80f0bcf94`; **new post-fix CI confirmation required** (last successful pre-journal CI 38249429972). Other-host physical 2-VM test and real running TPM-consistent snapshots still OPEN. Never claim completion from this planner.


## 2026-10-12 12:26+ — COUNT-AWARE SNAPSHOT LIFECYCLE INVENTORY IMPLEMENTED, OFFLINE CI GREEN

User: "chalo chalo complete it" = continue completing all of Command2, especially each clone's final CAPE usable RUNNING snapshot, without redoing SSL55 passed checks. Latest work only on GitHub development:
- `scripts/command2_snapshot_path_admission.py` with `scripts/test_command2_snapshot_path_admission.py`, GitHub Actions run **38249429972 SUCCESS**. Read-only new inventory from explicit count/ordered per-VM `--guest win11_N=UUID` values or exact `--reference-ssl55` on CSE-SSL-55; checks live libvirt guest UUID, state, saved XML one independently backed QCOW2 disk, single swtpm2 and no unauthorized NAT network; classifies RAW OVMF blocker, QCOW2 with no analysis NIC, QCOW2 missing per-VM snapshot, or snapshot metadata needing actual TPM/UEFI and repeated benign revert evidence. Crucially never declares production ready on metadata. Duplicate VM names/UUIDs refused before querying libvirt; no network, disk, snapshot or VM power mutations. This is an engineering phase planner, not the full production runner.
- Prior latest stable RAW→QCOW2 separate-host staging and XML switch tools and CI run 38241761244 SUCCESS, required reviewed immutable cold bundle/real restored witness, still no REAL running snapshot anywhere. Existing `win11_1` on SSL55 RUNNING with RAW OVMF VARS 540672 bytes and swtpm2 state 9234 bytes; no snapshot; 64.74GiB disk free and 40GiB reserve as of 11:00 UTC report. SSL55 master/trial off; do not start/modify originals or force conversion of live clone. User confirmed second Ubuntu/KVM system available but HAS NOT supplied access/runtime evidence. Actual two-VM cold-restore, QCOW2 OVMF/SWTPM compatibility and two-cycle CAPE benign revert remains unverified.
- Current focus must move beyond planners: fully integrated, fail-closed Command2 orchestration and target-host physical two-VM tests, with working guest SYSTEM bootstrap and isolation, distinct per-VM final RUNNING snapshot, CAPE config and parallel benign jobs. Do not claim Command2 complete based on offline CI. Command3 remains gated on physical integration.


## 2026-10-12 12:00+ — COUNT-DRIVEN COMMAND2 UNIFIED OPERATOR WORKFLOW + HOST NFT NETWORK/BOOT INSTALL + BENIGN REVERT CODE GREEN

User insists "chalo chalo complete it". Work delivered to GitHub `development` only (no actual host/VM changes). **Do not equate CI with complete Command 2**. User has offered second Ubuntu/KVM system suitable for two VMs. Must now collect actual other-host inventory and run approved, benign phases there; cannot physically complete the working `win11_1` snapshot on SSL55 through GitHub alone.

Code added/integrated:
- `scripts/command2_portable_workflow.py` + `scripts/test_command2_portable_workflow.py`: a single guarded operator-facing CLI `--phase PHASE --mode plan/apply` (default plan), delegating via Python argv (never shell) to existing and new count-driven stager, network install, nft persistence, per-VM identity ISO build/attach, isolated NIC + host network approval ISO, full cold backup verify/restore, QR OVMF sidecar+activation with full restore witness, per-VM running snapshot capture, single disposable benign snapshot revert, final all-VM witness audit and backed-up CAPE kvm.conf registration. Every phase requires exact other-host and root-private ordered reservation; child handles its own typed approval and live revalidation. No automatic bulk snapshot, forced poweroff, sample execution, untested receipt creation, or reference SSL55 mutation. Examples `docs/COMMAND2_UNIFIED_OPERATOR_WORKFLOW.md`.
- `scripts/command2_portable_network_install.py` + tests: explicit other-host approval; refuses already-present exact libvirt network/bridge or CAPE nft table, subnet conflicts with kernel routes/interfaces/libvirt networks and running VMs. Creates exactly the dedicated `inet cape_analysis_cmd2_guard` table (no global flush, no unrelated firewall modifications) and persistent `cape-analysis-isolated` no-NAT/no-DHCP/`port isolated=yes` network. Leaves network/guest autostart OFF and guest NICs unattached. Real packet path, persistence, L2 and IPv6 negatives unproven; partial state -> STOP, no blind retry.
- `scripts/command2_portable_guard_persistence.py` + tests: after verified dedicated guard/network and with all reserved guests SHUT OFF/autostart DISABLED and no active/enabled base nftables.service, creates exclusively `/etc/cape-command2/nft-cape-cmd2-only.nft`, `/usr/local/libexec/cape-command2/nft-cape-cmd2-replay.py`, and dedicated `/etc/systemd/system/cape-command2-nft-guard.service`. Pinned SHA policy, boot helper refuses altered existing table, writes root-only, enables but DOES NOT START dedicated unit; does not modify `/etc/nftables.conf`, base nftables.service, Docker firewall, libvirt network autostart or boot/reboot system. Need real systemd reboot accept.
- `scripts/command2_disposable_snapshot_revert_probe.py` + tests: separate host only, VM exact SHUT OFF, original master off, no other VM running, pinned SHA-verified complete cold disk+OVMF+swtpm backup, actual dedicated nft/libvirt guard shape, native QCOW2 OVMF active and snapshot metadata `running` with internal RAM + QCOW2 disk. Typed approval `REVERT-BENIGN-DISPOSABLE-WIN11_N` calls ONE `virsh snapshot-revert` without force and verifies VM RUNNING + CAPE Agent HTTP. Does NOT prove guest TPM/UEFI/Secure Boot/BitLocker or IPv4/IPv6/L2 packet negatives, no automatic repeat or shutdown; operator needs off-guest Windows witness and second benign cycle. Final CAPE registration still barred until complete guest acceptance.
- CI consolidated run **38247709103** PASSED both full Python offline (previous count ~603+ tests, new tests integrated) and Windows PowerShell syntax. All new code remains synthetic-tested only. Latest docs `docs/COMMAND2_UNIFIED_OPERATOR_WORKFLOW.md`.

REAL SSL55 baseline unchanged: `win11_1` UUID 732b2256-ee99-41fa-881d-fbf5c476d960 is RUNNING with no running snapshot, 64.74GiB free, standalone disk, RAW OVMF pflash (540672 bytes) and swtpm2 (9234 bytes) and a complete hash-verified cold backup CAPTURED, restore not witnessed. Libvirt daemon 11.1/QEMU9.2 supported experimental QCOW2 NVRAM but no proof swtpm running snapshot/revert consistency; never force live XML/NVRAM conversion, destroy/stop master, or blindly snapshot. Master+trial shutoff immutable. Other-host remains not tested.
REMAINING to mark Command2 complete: (1) trusted SYSTEM bootstrap and offhost Windows identities tested (2) real nft replay reboot persistence & target IPv4/IPv6/L2 actual negatives and CAPE/INetSim positives (3) real cold revert/TPM OVMF migration+multiple harmless full-state running snapshot revert tests for two guests, or custom CAPE full-state adapter if swtpm incompatible (4) two simultaneous benign CAPE samples with proper kvm.conf snapshots and reset (5) second physical host end-to-end fresh-host test including interruption, capacity, rollback. Command3 deployment not yet certified.


## 2026-10-12 11:00+ — REAL SSL55 SNAPSHOT READINESS EVIDENCE + GUARDED OTHER-HOST QCOW2 OVMF MIGRATION IMPLEMENTED

Actual user-uploaded `CAPE_Command2_Win11_1_SnapshotReadiness_20261012_110035.txt`:
- libvirt compiled/used/running daemon 11.1.0, QEMU hypervisor 9.2.2. Standalone flattened QCOW2 64GiB virtual, `win11_1` UUID `732b2256-ee99-41fa-881d-fbf5c476d960` RUNNING; master+trial SHUT OFF. EXACT pflash NVRAM RAW (540672 bytes) in XML and on disk; swtpm2 `tpm2-00.permall` 9234 bytes plus .lock; **zero snapshots**; cold recovery manifest previously present (restore untested); free shared storage **64.74 GiB** with 40GiB reserve. No host/guest modifications. Audit decision `SSL55_CAPE_RUNNING_SNAPSHOT_COMPATIBILITY_READONLY`, `running_snapshot_ready_for_cape=false`.
- Libvirt 10.9 added internal running snapshot of UEFI when varstore QCOW2; 10.10 fixed reversion issues. This host version is sufficient for **experiment** but native RAW pflash **not**. swtpm state is independent; no automatic libvirt TPM snapshot/revert proof. Do not convert LIVE SSL55 NVRAM, force `virsh snapshot-create-as` or touch originals. Real `win11_1` snapshot still NOT CREATED.
- Added OTHER-HOST-ONLY `scripts/command2_disposable_nvram_qcow2_prepare.py` + synthetic tests: exact SHUT-OFF zero-snapshot disposable clone, approved host and pinned SHA-verified cold bundle, sidecar `win11_N.command2_VARS.fd.qcow2` created with qemu-img raw→qcow2, checked/compared, preserves original RAW, XML, disk and TPM. No VM action.
- Added OTHER-HOST-ONLY `scripts/command2_disposable_nvram_qcow2_activate.py` + tests: requires separate operator full disk/OVMF/swtpm cold-restore/boot witness with matching manifest SHA; verifies sidecar compares bitwise with original RAW and that VM is SHUT OFF, isolated NIC and TPM unchanged, no snapshots. Typed approval, persists original saved XML in exclusive durable private backup, `virsh define --validate` XML with QCOW2 OVMF VARS sidecar, re-checks unchanged disk, NIC, TPM and SHUT OFF. This is a **saved-definition transition**, not snapshot, not boot, and not certified firmware restoration; failure preserves artifacts and refuses blind retry.
- Native snapshot guards recognize sidecar filename (provided actual XML uses format qcow2), and `scripts/command2_running_snapshot_batch_gate.py` now hard-refuses capereg if ANY guest has RAW format or is still pointing to the *unused* old .fd. Tests ensure both accepted and refused in simulation. CI aggregate run `38241338729` SUCCESS; later hardening commit CI run `38241612410` pending/completed check. Docs `docs/COMMAND2_SSL55_20261012_SNAPSHOT_DECISION.md` catalogs exact observed host evidence and physical acceptance path.
- CRITICAL: Command2 portable zero-NIC stager still clones original RAW OVMF variables; optional native-QCOW2 staging integration is not done. Trusted Windows bootstrap, two-VM real same-epoch TPM/UEFI running revert, CAPE analyses, count-driven full orchestration and production release are still OPEN. The disposable test machine is the proving ground; no unsafe real SSL55 changes before a second host success. Previous SSL55 independent Windows boot/agent/network and L2 policy checks should NOT be repeated.


## 2026-10-12 ~10:42+ — SNAPSHOT PROGRESS: GUARDED EXPERIMENTAL CAPTURE NOW BINDS FULL COLD BUNDLE, NATIVE FIRMWARE STACK AND WINDOWS WITNESS

Operator asks assistant to finish Command 2 and fix missing running snapshot for REAL SSL55 `win11_1` so it can inform other-machine automation; protected master `win11` and trial remain SHUT OFF and MUST NOT be modified. **win11_1 HAS NOT YET RECEIVED A VERIFIED RUNNING SNAPSHOT**; independent boot+agent+one NIC+Windows benign targeted external IPv4/IPv6 negative probes + Linux bridge isolation policy were accepted, cold bundle byte-verified at capture but its real restore NOT tested. Storage last 64.77GiB, 40GiB reserve. No malware.

Research 2026-10-12: libvirt 10.9 introduced internal QCOW2 OVMF running snapshots but v10.10 fixed UEFI snapshot reversion bugs; RAW OVMF variable store unsupported, current swtpm state consistency independent physical blocker. QEMU swtpm migration supports snapshotting at QEMU layer but libvirt snapshot semantics cannot be assumed to restore TPM without actual repeat tests. Sources: https://libvirt.gitlab.io/libvirt/news.html ; https://www.qemu.org/docs/master/specs/tpm ; https://lists.libvirt.org/archives/list/users%40lists.libvirt.org/message/QGU2EQQSUC6X6CGK4QPTHH2EIWMOXHOP/

New development code (no changes to SSL55 host or second host):
- `scripts/command2_snapshot_recovery_preflight.py` hashes complete previously captured cold bundle disk+UEFI+swtpm files and root/private/UUID/manifest SHA constraints independently while VM is running; not equivalent to restore test.
- `scripts/command2_native_snapshot_stack_guard.py`: checks other host live daemon >=10.10.0 and QEMU >=9, exact QCOW2 OVMF variable store on disk and in VM XML, swtpm2, RAM/storage safety. Only *experimental admission*, not actual TPM/UEFI revert proof.
- `command2_running_cape_snapshot_gate.py` capture now requires `--recovery-bundle` + `--reviewed-manifest-sha`, revalidates recovery bytes and native stack after typed approval, requires running+one internal memory/disk XML; capture remains ONLY on approved other host, not SSL55; restored state unproven.
- `command2_windows_benign_snapshot_witness.ps1`: harmless Baseline/Mark/Verify measurements; Mark is one exclusively created benign file with typed guest approval after running snapshot; Verify after revert checks disappearance, reads Get-Tpm, Secure Boot, BitLocker, route, agent. Human must preserve baseline OFF GUEST before revert; marker removal alone does NOT prove TPM/UEFI rollback.
- CI run **38239479336** PASSED all Python offline (including malicious backup substitutions) and Windows PowerShell parser. New docs section `docs/COMMAND2_RUNNING_SNAPSHOT_RESOLUTION_PLAN.md`.

NEXT DECISIVE SSL55 EVIDENCE: run only pinned `scripts/command2_ssl55_running_snapshot_readonly.py` (currently source blob check from GitHub) with `sudo virsh -c qemu:///system version --daemon` to ONE TXT. It has NO mutation and prints no TPM secrets. Review before proposing any change. Do not generate another 30GiB copy or force snapshot on SSL55. To physically PROVE running snapshot, use user-approved second Ubuntu/KVM system with two disposable Windows VMs, full cold bundle before snapshot, enough disk space, isolated ingress/egress and record repeated benign TPM/OVMF/BitLocker/agent reset. Only after repeated success adapt an appropriate proven strategy back to SSL55 and production-grade count automation. Existing three-command user goal still requires complete orchestrator, per-guest CAPE register and independent end-to-end fresh-host acceptance; no production-ready claim or Command3 handoff yet.


## 2026-10-12 ~10:30 — USER REQUIRES SNAPSHOT FOR WIN11_1 AND ALL COMMAND2 CLONES: ACTIVE ENGINEERING, NOT YET PHYSICALLY COMPLETE

User explicitly confirmed `win11_1` still has NO running snapshot, requests all needed fixes and full Command2 work before proceeding to Command3. **DO NOT CLAIM THIS IS SOLVED**. No current remote host terminal access; assistant has GitHub development connector only and must provide explicit guarded host command for actual evidence/changes. SSL55 master/trial off and immutable, independent clone RUNNING, previous full cold bundle captured but not restore-tested, ~64.77GiB available and 40GiB reserve.

New primary research on official libvirt/QEMU/CAPE docs:
- SSL55 VM RAW OVMF variable store incompatible with new native internal running pflash snapshots requiring QCOW2 NVRAM. An offline QCOW2 conversion by itself does NOT restore swtpm2 state atomically.
- Libvirt TPM snapshot RFE `https://bugzilla.redhat.com/show_bug.cgi?id=1855367` now CLOSED WONTFIX; QEMU supports swtpm state migration, but vanilla libvirt snapshot metadata does not attest TPM restore.
- QEMU `virsh save` alternative saves RUNNING VM RAM but NOT disk, then leaves VM shut off; candidate requires a complete disk+NVRAM+swtpm same-epoch image and custom, separately tested CAPE machinery adapter. Do not mislabel as native libvirt snapshot. Docs `docs/COMMAND2_RUNNING_SNAPSHOT_RESOLUTION_PLAN.md`.
- Upstream current CAPE `LibVirtMachinery.start(label)` REFUSES already running VM; needs VM SHUT OFF at registration/start, with snapshot CAPTURED while running and `domainsnapshot state=running`. Corrected `scripts/command2_running_snapshot_batch_gate.py` to require each VM SHUT OFF at final CAPE registration and running internal memory+disk metadata, separately per-VM TPM/UEFI/witness. Synthetic test modified.
GitHub development-only new code:
- `scripts/command2_ssl55_running_snapshot_readonly.py` + `scripts/test_command2_ssl55_running_snapshot_readonly.py`: exact canonical host running clone + protected master/trial UUID/states, live/saved XML/NIC/QCOW2, raw vs qcow2 NVRAM, swtpm file metadata only, existing snapshot names, known cold bundle existence, free storage; READ ONLY, no snapshot/power/NVRAM change, reports incompatibility instead of force snapshot. CI passed at run 38236409671 (later wording update run pending). Needed single verified host evidence.
- `scripts/register_cape_clones.py` supports distinct per-VM snapshot names; fixed accidental escaped newline, CI successful earlier run 38236888223/88215. `scripts/command2_cape_registration_gate.py` + tests: explicit OTHER-host snapshot witness gate for every VM, propose/approved backup-preserving kvm.conf only after each per-guest snapshot+TPM/UEFI revert cycle; never restart CAPE or execute samples. Original test suite green after fix.
- `docs/COMMAND2_RUNNING_SNAPSHOT_RESOLUTION_PLAN.md` covers candidate standard native QCOW2 NVRAM+TPM physical compatibility and candidate save-state full-state adapter; both require disposable spare KVM machine and real repeat benign acceptance. No unsafe live pflash conversion or TPM removal on SSL55. New tests are offline only and NO real snapshot exists yet.
- Any GitHub Actions latest results should be checked at development HEAD before reporting CI success; several intermediate CI failures due fixtures were corrected.
- Run next only a pinned, verified READ-ONLY SSL55 snapshot compatibility audit and upload report, then prototype actual full-state snapshot on disposable second host, not original SSL55. Keep other-host two-VM testing separate and future Command3 blocked until real Command2 pass.


## 2026-10-12 — SUBSTANTIVE DEVELOPMENT: PER-VM RUNNING SNAPSHOT MANDATORY + APPROVED NETWORK MEDIA

User reiterated: complete all Command2 parts; at the very END of each cloned VM's successful network/CAPE readiness, create a RUNNING analysis snapshot because standard CAPE KVM machinery reverts to it. Command3 follows after Command2 development and acceptance. User confirmed spare second KVM system for two-VM acceptance, but second machine NOT yet physically tested. Do not claim background work/automation or production readiness before accepted witness logs.

Committed on GitHub `development`:
1. `scripts/command2_running_snapshot_batch_gate.py`, `scripts/test_command2_running_snapshot_batch_gate.py`: read-only exact other-host 1..16 guest check of live NIC/UUID+unique IP, internal RUNNING snapshot metadata per `cape_ready_win11_N` (guest state running, internal memory and disk) and root-private VM-specific witnessed actual benign/repeated snapshot reverts with OVMF and swtpm state, agent, network and master-source acceptance. Every VM independently gated, snapshots absent or missing TPM/UEFI proof => batch FAIL. Read-only and does NOT itself create or revert snapshots or authorize production. Private evidence folder check and RFC1918 /24 guard added. Green GitHub CI run **38235535550**.
2. `scripts/command2_portable_sequence_model.py`: now has required `RUNNING_CAPE_SNAPSHOT_REVERT_VERIFIED` stage between separate cold restore and ready; tests prove no skip. `command2_running_cape_snapshot_gate.py` no longer ignores custom target `--subnet` in plan mode. CI PASS.
3. `scripts/command2_portable_network_approval_iso.py` plus `scripts/test_command2_portable_network_approval_iso.py`: after per-VM staging, first identity CD ISO, clean Windows hostname initialization, guarded per-guest NIC attach, and a separately recorded root-private `COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V1` receipt confirming actual host IPv4+IPv6, L2, CAPE positive paths and reboot persistence, constructs second immutable `CAPE_CMD2` ISO containing original guest-config JSON+hash AND network-approved JSON+hash for the Windows SYSTEM startup bootstrap; swaps only EXISTING optical CD-ROM in SAVED config of verified SHUT-OFF clone. No NIC, OS disk, network, firewall, VM power, master, CAPE or sample action. Receipt self-reported operator evidence, not cryptographic independent proof. CI PASS run **38235256974**. Physical guest boot/Windows static IP still NOT tested.
4. Documentation `docs/COMMAND2_20261012_IMPLEMENTATION_AND_RELEASE_GATES.md` now records these phases, exact CAPE snapshot contract and TPM/UEFI risk.

Critical gaps: REAL working per-VM snapshot capture/restoration strategy for RAW OVMF VARS+swtpm; existing generic libvirt running internal snapshots must never be treated as proven atomic TPM/UEFI restore. CAPE `kvm.conf` setup must remain proposal-only until each VM has a proven running reverted snapshot and two-VM benign parallel jobs. There is no complete single-command all stages apply yet; no new machine tests. SSL55 pilot already passed independent disk/cold boot/agent/static IP, targeted external IPv4+IPv6 probes and single-TAP host policy, but full negative packet-path+peer L2 and running snapshot revert NOT done. Host free last 64.77GiB, original win11 & trial immutable shut off. No malware.


## 2026-10-12 — NEW EXPLICIT OPERATOR REQUIREMENT: EVERY VM GETS A VERIFIED RUNNING CAPE SNAPSHOT *LAST*

User explicitly requires running CAPE snapshot on each Command2 analysis guest after identity/network isolation, as standard CAPE KVM machinery reverts running snapshot for each analysis; no Command3 deployment until full Command2 work is sufficiently complete.

Commits on GitHub development (no SSL55 host modifications):
- `scripts/command2_running_snapshot_batch_gate.py` plus offline regression suite `scripts/test_command2_running_snapshot_batch_gate.py`: read-only OTHER-host 1..16 VM audit bound to root-private canonical reservation. For each named `win11_N`, validate exact running libvirt UUID, single isolated NIC/MAC, QCOW2 OS disk, private OVMF VARS, swtpm2, libvirt `cape_ready_win11_N` snapshot XML state RUNNING + internal RAM + internal disk, and separate root-private operator witness recording real repeated benign reverts/TPM/UEFI state/network/agent recovery. Every VM must pass; one pass does not hide another failure. The audit is not a snapshot creator, witness evidence is NOT cryptographically self-authenticating, and runtime production readiness remains false regardless of metadata alone. Windows/original master untouched.
- `scripts/command2_portable_sequence_model.py` requires new `RUNNING_CAPE_SNAPSHOT_REVERT_VERIFIED` stage before simulation readiness, after cold restore; tests verify no bypass. Original `command2_running_cape_snapshot_gate.py` CLI plan now honors nondefault target `--subnet`, regression test.
- Official CAPE guest snapshot guide requires Windows running agent ready when snapshot captured; libvirt virsh revert starts from chosen snapshot and is destructive; libvirt historical swtpm integration limitations documented. RAW OVMF pflash + swtpm2 on SSL55 pilot is NOT an approved coherent snapshot state. Do not try destructive generic `virsh snapshot-create-as/revert` on protected SSL55; plan to evaluate on disposable second machine after verified safe cold restore and operator approval.
- Added final snapshot release policy section `docs/COMMAND2_20261012_IMPLEMENTATION_AND_RELEASE_GATES.md`. CI run `38234513569` PASSED both offline and Windows parser at branch commit `59260036694ea8881ee6331e0c918005a08c800e`. Any later tests CI as branch HEAD advances.
- REAL OTHER HOST NOT YET PROVIDED/TESTED. Need secure master Windows SYSTEM bootstrap actual install, per guest identity ISO, network approval media+NIC, CAPE Agent registration, coherent per VM snapshot/revert, 2 parallel benign jobs, target-host tests. Do not mark Command2 complete merely by code tests. No more SSL55 full clones due to 64.77GiB remaining and 40GiB shared-host reserve.


## 2026-10-12 — USER CONFIRMED SECOND MACHINE FOR TWO-VM COMMAND2 ACCEPTANCE

Operator has access to another Ubuntu/KVM machine for a TWO Windows analysis VM acceptance test. Preference: complete and offline-test all remaining Command 2 implementation, then proceed to Command 3 development, then physically test integrated command sequence. Do NOT say Command 2 production complete until real machine passes; physical validation is not optional and can expose hardware/firmware/CAPE constraints. Do not require the operator to redo already verified SSL55 audit: report `CAPE_Command2_HostBridgeL2_Fixed_20261012_092812.txt` PASSED, 64.77 GiB free.

New `scripts/command2_portable_guest_identity_attach.py` and `scripts/test_command2_portable_guest_identity_attach.py` on `development`: after an approved separate-host zero-NIC N-stage and per-VM identity ISO creation, the attach helper verifies the reserved per-VM UUID, exact canonical config bytes, ISO-embedded JSON and SHA256, that the VM is still shut off and has zero NIC, one master-independent QCOW2 and exactly one **empty** read-only CD-ROM. Requires root, explicit approved host, separate single-VM typed approval, root 0600 lock; copies ISO **exclusively** to existing libvirt disk directory with the disk file's owner/group, preserves original journal ISO, then uses `virsh change-media --insert --config` on that existing CD-ROM ONLY and verifies saved XML. No boot/NIC/network/fw/TPM/snapshot changes. If copy or virsh partially fails, stop/preserve artifacts; no automatic retries. CI run **38233141539** SUCCESS (offline and Windows syntax). This ISO delivery still requires a trusted Windows SYSTEM bootstrap already installed in the source master, and it is not yet physically validated on the second machine. Copies may need libvirt/AppArmor ownership/label consideration during real boot; do not bypass security rules to force it.
The path is **multiple guarded components, NOT one final, production-ready count-driven command**; batch orchestration and recovery reconciliation pending. Further gaps remain full local host network apply/persistence+negative tests, individual Windows bootstrap and network identities, cold restore, TPM/UEFI-consistent CAPE snapshot reset, CAPE N-machinery parallel analysis and second-host end-to-end test. Command 3 is still locked for deployment.


## 2026-10-12 09:28+ — REAL SSL55 HOST L2 CONFIGURATION AUDIT PASS, PORTABILITY CODE ADVANCED

Uploaded `CAPE_Command2_HostBridgeL2_Fixed_20261012_092812.txt` ACTUAL host report returned `SSL55_RUNTIME_ISOLATED_BRIDGE_POLICY_OBSERVED`: win11_1 running, only `vnet1` attached to `cape-lab0`, Linux kernel per-port bridge isolation flag = 1, no other bridge TAP, expected libvirt no-forward/no-DHCP port isolation XML, CAPE guard nft chain shape accepted and service active; IPv6 bridge inventory empty + kernel bridge exists. 64.77 GiB free. `guest_firewall_packet_path_negative_tested=false` and `real_guest_to_guest_l2_negative_probe=false`; `safe_for_malware_execution=false`. This is **valid full read-only host policy-shape acceptance**, not a packet test. DO NOT repeat already passed blockpull, cold-copy, independent boot, CAPE Agent, benign Windows V2 negative egress or L2 bridge check.

The user explicitly requests fully completed portable count-driven Command 2 as quickly as possible. On GitHub `development` implemented:
- `scripts/command2_portable_guest_identity_iso.py`: guarded **OTHER HOST ONLY**, `--mode plan/build`, verifies exact root-private reserved ordered identity journal, generated per-guest config JSON matching `command2_windows_guest_config.make_guest_config`, guest UUID/name, shut-off **zero NIC**, root-owned output and storage reserve, creates new exclusively named `CAPE_CMD2` ISO containing `guest-config.json` and SHA256 file expected by Windows `command2_guest_startup_autoconfig.ps1`. It creates files only; does not attach media, boot, network-approve, or confirm Windows startup-task installation. Tests added and CI passing. Build is currently per-guest operator approval; no batch/auto optical attachment yet.
- `scripts/command2_isolated_network_xml_plan.py`: generated no-NAT/no-DHCP network includes `<port isolated="yes"/>` for intended L2 TAP separation. `scripts/command2_guarded_isolated_nic.py` now **refuses** actual network lacking enabled port isolation before adding a guest NIC. Synthetic tests adjusted. CI run 38231517392 PASS.
- Additional formal overview `docs/COMMAND2_20261012_IMPLEMENTATION_AND_RELEASE_GATES.md` documents completed real pilot versus required tests. The original master and trial remain **protected**. No new SSL55 cloning or additional VM/disk snapshots authorized: free 64.77 GiB and 40GiB host reserve, additional full ~30GiB clone would breach reserve.
- Full Command2 remains INCOMPLETE: trusted SYSTEM startup bootstrap in golden Windows not physically demonstrated, bulk identity media attach+delivery, second approved capable host for 2 concurrently running unique-ID guests, complete host/external/L2 negative packet tests and persistence on that host, live CAPE/INetSim machinery registration and benign parallel analyses, safe disk+UEFI+swtpm **restore** test, and coherent running snapshot revert (RAW OVMF pflash and swtpm unsupported/unproven). Do NOT mark Command 3 ready or run malware.
- Research: libvirt 2024 pflash snapshot support requires QCOW2 NVRAM, and libvirt historic snapshot handling does not atomically restore swtpm; QEMU swtpm migration protocol support alone is not a working CAPE cycle. No unsupported workarounds.


## 2026-10-12 09:24 — HOST BRIDGE AUDIT BLOCKED ONLY ON EMPTY IPV6 INVENTORY (READ-ONLY)

Actual uploaded `CAPE_Command2_HostBridgeL2_20261012_092420.txt`:
`BLOCKED_ISOLATION_RUNTIME_INSPECTION`, `reason: Unexpected CAPE bridge IPv6 interface inventory`, `no_host_guest_mutation_performed: true`. Audit reached `bridge_ipv6()` after `domain_preflight()`, `network_preflight()` and `bridge_config()` did **not** raise. This means the exact protected VM identities/states, single Linux TAP member and per-port isolated flag, libvirt no-forward network checks passed **at that inspection time**, but later nft firewall_shape() did NOT run and final audit did NOT complete. Do not mislabel complete runtime isolation audit as PASS.

Likely cause: `ip -j -6 addr show dev cape-lab0` can return `[]` on an existing bridge with no IPv6 addresses. The original code incorrectly required exactly one IPv6 interface JSON object. Fixed `scripts/command2_ssl55_l2_runtime_readonly.py` to verify bridge identity independently via `ip -j link show dev cape-lab0`, accept either empty IPv6 list or exactly one expected bridge entry, reject malformed/foreign entries and any scope other than link/host. Added 8 regression tests including empty/foreign/global IPv6; GitHub Actions run **38229894575** passed Windows parser+offline. Host code remains strictly read-only; no shell VM start/reboot/network restart/copy/snapshot or malware. NEXT: re-run ONLY the patched pinned host kernel L2 configuration audit once and upload TXT. Full negative packet-path and guest-to-guest test remains unverified even on a PASS; TPM/OVMF restore, running snapshot/revert and second host portability still unverified. Keep original master and trial off; shared free disk after cold backup most recently ~64.8GiB, do not make additional full-size clone copies without capacity checks.


## 2026-10-12 ~09:19 UTC — HOST BRIDGE L2 RUNTIME READ-ONLY ACCEPTANCE IMPLEMENTED

User's latest Windows benign V2 screenshot is a **PASS_TARGETED_PROBES_ONLY**: exact static guest IP, zero guest IPv4/IPv6 default routes, four `SOCKET_FAILED_NetworkUnreachable` on enumerated public endpoints; no guest network changes, but full egress and guest-to-guest L2 NOT proved. V2 ISO installer uploaded report SUCCESS; cold boot and CAPE Agent preexisting PASS.
- Added `scripts/command2_ssl55_l2_runtime_readonly.py` and offline synthetic `scripts/test_command2_ssl55_l2_runtime_readonly.py`; GitHub Actions run **38229380274** PASS both offline and Windows syntax. Host script checks exact CSE-SSL-55/VM UUIDs, master/trial off, live+inactive isolated guest NIC and flattened disk/UEFI/swtpm, active libvirt no-forward/no-DHCP/`port isolated=yes` network, kernel bridge `/sys/class/net/cape-lab0/brif` ports exactly one TAP from the running clone, that TAP master equals cape-lab0, TAP `brport/isolated` flag is actually 1, no bridge global/site IPv6, nft inet cape_analysis_guard chain structure and active dedicated CAPE firewall service, current storage reserve. No VM/network/firewall/disk writes or guest execution. Run only with SHA-pinned GitHub blob and upload TXT; never blindly retry an unexpected kernel bridge mismatch.
- A passing kernel flag test is **configuration evidence**, not an end-to-end negative guest-to-guest lateral packet test; second guest disposable peer and full-state cold restore and running OVMF/TPM memory+disk snapshots remain unverified. Shared free space last reported ~64.8GiB: fail closed on further full-size VM clones without reserve. No malware testing authorization.


## 2026-10-12 ~09:16 local — WINDOWS BENIGN V2 TARGETED EGRESS PASS (REAL EVIDENCE)

User attached screenshot of Windows `CAPE_Command2_GuestEgressProbe_V2.txt` plus HOST report `CAPE_Command2_EgressV2_20261012_091450.txt`. Host report proves the corrected v2 ISO was approved, installed onto CDROM sdb live and saved without guest execution, previous ISO untouched, win11_1 stayed RUNNING: `BENIGN_EGRESS_V2_ISO_INSERTED_NO_GUEST_EXECUTION`.
Windows user-visible screenshot exact verified fields:
- `RESULT_TYPE=BENIGN_GUEST_IPV4_IPV6_EGRESS_PROBES_V2`; `WINDOWS_HOSTNAME=WIN11-1`.
- `PHYSICAL_NIC_COUNT=1`, `CONNECTED_PHYSICAL_NIC_COUNT=1`, `ONE_PHYSICAL_NIC=TRUE`; expected MAC `02-0A-30-6A-3F-50` TRUE; expected static `192.168.240.101/24` TRUE; exactly one nonloopback IPv4.
- `IPv4_ROUTE_QUERY=SUCCESS`, `IPv4_DEFAULT_ROUTE_COUNT=0`, `IPv6_ROUTE_QUERY=SUCCESS`, `IPv6_DEFAULT_ROUTE_COUNT=0`, `GUEST_DEFAULT_ROUTE_GUARD=PASS`.
- 1.1.1.1:443 (IPv4), 8.8.8.8:53 (IPv4), 2606:4700:4700::1111:443 (IPv6), 2001:4860:4860::8888:443 (IPv6) all `SOCKET_FAILED_NetworkUnreachable`; `ALL_FOUR_BENIGN_CONNECTIONS_DENIED=True`; `GUEST_NEGATIVE_PROBE_RESULT=PASS_TARGETED_PROBES_ONLY`.
- `REAL_L2_LATERAL_TEST=NOT_PERFORMED`, `FULL_HOST_EGRESS_GUARANTEE=NOT_PROVEN`, `WINDOWS_NETWORK_CHANGES=NONE`.
DO NOT conflate these four bounded route-based connection denials with any host nft external packet-path negative proof; guest-to-guest lateral L2 still NOT tested; no permission to run malware. Latest free host storage in prior post-coldboot report 64.8 GiB; don't make further ~30GiB copies on shared host before rechecking 40GiB reserve. Independent cold boot and CAPE Agent have passed; cold RESTORE and running memory/disk/UEFI/swtpm snapshot revert are not yet verified. Next recommended low-impact evidence is read-only host nft rules+bridge port runtime inventory, no host or guest writes, then decide L2 negative tests using disposable peer only after separate approval and resource gate. Preserve both V1/V2 ISO and report; DO NOT rerun egress probe unless debugging required.


## 2026-10-12 ~09:05 UTC — V1 EGRESS OPTICAL ISO SUCCESS; GUEST ROUTE QUERY CIM ERROR; V2 FIX CI GREEN

Actual uploaded `CAPE_Command2_EgressISO_Retry_20261012_090358.txt` proves operator-approved installation of `win11_1.command2_benign_egress.iso` onto existing sdb live and saved: result `BENIGN_EGRESS_ISO_INSERTED_NO_GUEST_EXECUTION`, VM still running, previous safe_fix ISO untouched. Windows screenshot of resulting `CAPE_Command2_GuestEgressProbe.txt` shows v1 PS1 executed and collected WIN11-1 hostname, single physical UP NIC MAC 02-0A-30-6A-3F-50, exact static 192.168.240.101/24 true, then `GUEST_NEGATIVE_PROBE_RESULT=FAIL_OR_INCONCLUSIVE`, `PROBE_ERROR_KIND=CimJobException` BEFORE default-route results/TCP probe results. This is guest Windows PowerShell route query failure, not a positive external egress finding, and not proof of denial. No guest networking changes, malware or snapshots.
ROOT CAUSE (likely): v1 PowerShell `Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop` (and IPv6 equivalent) can raise CimJobException when that optional default route does NOT exist, which is expected for an isolated guest without gateway. Never infer a missing gateway means unsafe routing.
- NEW `scripts/command2_guest_benign_egress_probe_v2.ps1`: enumerates ALL IPv4/IPv6 routes independently then filters `DestinationPrefix` in PowerShell; zero defaults=PASS route check, query errors INCONCLUSIVE and probe runs where possible. Four bounded safe TCP dials use family-specific sockets (IPv4 1.1.1.1:443 and 8.8.8.8:53; IPv6 2606:4700:4700::1111:443 and 2001:4860:4860::8888:443). Does not run external samples or mutate NIC/routes. Writes new `C:\\Users\\Public\\Documents\\CAPE_Command2_GuestEgressProbe_V2.txt` rather than overwrite v1 and opens in Notepad. Result `PASS_TARGETED_PROBES_ONLY` vs `FAIL_UNEXPECTED_ROUTE_OR_CONNECTION` vs `INCONCLUSIVE`; never claim comprehensive containment.
- NEW `scripts/command2_ssl55_benign_egress_iso_v2.py` (separate guarded installer): only permitted to change existing sdb CD-ROM FROM `win11_1.command2_benign_egress.iso` TO new immutable `win11_1.command2_benign_egress_v2.iso`, no overwrite of previous ISO; exact running domain identity, live/saved XML, isolated network active, nft guard and protected VM identity, single NIC etc. --mode plan read-only; --mode apply requires local TTY typed `INSERT-CORRECTED-EGRESS-V2-ISO-WIN11_1`. Windows double-click `RUN_EGRESS_CHECK_V2.cmd` on `CAPE_EGR_V2` D: optical media only AFTER operator host result `BENIGN_EGRESS_V2_ISO_INSERTED_NO_GUEST_EXECUTION`.
- New v2 PowerShell + ISO installer regression tests, Windows PowerShell syntax checks, all offline test suite passed at GitHub Actions run **38228292921** (head 4de4db0492f932379ccfe9645ba1a808ac011d65). Continue only with SHA-pinned GitHub read-only preflight and explicit approval if all checks pass. Do not restart, remount disks, rerun old V1 launcher, or touch protected master. No malware authorization; full negative IPv4/IPv6/L2 and running memory+disk+TPM+OVMF snapshot/revert still unverified.


## 2026-10-12 08:22 UTC — BENIGN EGRESS ISO PREFLIGHT FALSE NETWORK INACTIVE; FIXED

Actual user-uploaded `CAPE_Command2_EgressISO_20261012_082242.txt` has only Python syntax pass followed by `BLOCKED_EGRESS_ISO`, reason `Analysis network not active`, `no_guest_execution_performed: true`. The isolated guest media was NOT changed, no guest tests run. Previous live cold boot had `win11_1` running and CAPE agent good. No reason to force power/network cycle.

Root cause in `scripts/command2_ssl55_benign_egress_iso.py`: compared each stripped libvirt output line *literally* against `active: yes`. Real `virsh net-info` has colon then alignment spaces (`Active:         yes`), leading to false refusal. Fixed by strict pure key/value parser normalizing whitespace, with explicit active yes, persistent yes, autostart no and exact cape-lab0 bridge checks. If genuinely inactive, still refuse; never blindly start network or VM. Also now catches installed nft guard structural `AuditBlocked` into operator-safe refusal. Tests include realistic spaced virsh output, valid full offline preflight and actual-inactive refusal; CI Python offline + Windows PowerShell syntax passed in GitHub run 38223707905.

Retry Step 1 ONLY using pinned commit, exact script blob, original benign PS1/CMD blob IDs. It still requires a local TTY exact phrase before optically replacing the **existing** sdb safe_fix ISO and validates running and saved CD-ROM XML after change, retaining previous source. If any other mismatch (unexpected optical media, firewall, etc) fail closed and inspect result. Only if `BENIGN_EGRESS_ISO_INSERTED_NO_GUEST_EXECUTION` returned, use Windows GUI to double-click `RUN_EGRESS_CHECK.cmd` on CAPE_EGRESS CD-ROM, photograph Notepad `C:\\Users\\Public\\Documents\\CAPE_Command2_GuestEgressProbe.txt` and upload host installer report. Windows guest TCP probes are bounded benign IPv4/IPv6; **not** full egress or L2 isolation proof. No malware, snapshots/revert or additional VM clones authorized.


## 2026-10-12 ~08:06 UTC — INDEPENDENT WIN11_1 COLD BOOT VERIFIED; NEXT BENIGN EGRESS PROBES

User uploaded `CAPE_Command2_NetworkColdBoot_20261012_080646.txt`. REAL evidence:
- Operator restarted ONLY existing win11_1 after prior cold backup; analysis network was already ACTIVE, so did not execute net-start or require first approval. `CLONE_START_REQUESTED`, result `COLD_BOOT_AGENT_VERIFIED`: CAPE agent reached via isolated bridge.
- After actual cold boot, `SSL55_POST_BLOCKPULL_READONLY_ACCEPTED`: clone running with new QEMU PID **130846**, v0.23 CAPE Agent administrator-positive HTTP 200, master/trial both SHUT OFF. Both live/inactive disk backing chains EMPTY; source master image FDs not open by active clone QEMU; independent NVRAM and TPM model unchanged.
- Free host storage after cold bundle **64.8GiB** (before ~94.69GiB). Clone allocated 29.87GiB. STOP any further unconstrained full 30GiB disk copies: 40GiB shared-host reserve would be at risk.
- Cold recovery bundle created earlier still preserved (cold-b8c6f2d3b4ba4e948dc476b2a1b35c2d). Actual restore from that bundle NOT tested, running memory+disk+UEFI/swtpm snapshot/revert NOT tested, actual negative external IPv4, IPv6 and inter-guest L2 not verified. Do NOT run malware yet.
- Official libvirt docs: RAW OVMF pflash internal snapshots cannot be assumed safe, and swtpm state is separate. Libvirt 2020 user list explicitly stated its snapshot machinery does not handle swtpm state; QEMU supports TPM migration but that alone does not prove consistent libvirt rollback. Never use generic snapshot-create/revert for this pilot without validated full-state approach. Links: https://www.libvirt.org/manpages/virsh.html ; https://www.qemu.org/docs/master/specs/tpm ; https://lists.libvirt.org/archives/list/users@lists.libvirt.org/message/ONDDG6TMLDDISRAWV7SMADP53FOCAU5L/
- New `scripts/command2_guest_benign_egress_probe.ps1` and `scripts/command2_guest_benign_egress_RUN.cmd`: benign Windows one-click read-only NIC/IPv4/IPv6/default routes and four bounded external TCP-denial probes, writes report to Public Documents and opens Notepad. THIS CANNOT PROVE ALL NETWORK ISOLATION OR L2 lateral denial, and must not be misrepresented as such.
- New `scripts/command2_ssl55_benign_egress_iso.py` --mode plan/apply: staged, operator-approved opt-in existing-guest optical ISO update ONLY, fixed sdb existing safe-fix media, checks exact running clone/master/trial, CAPE no-forward isolated network, structural nft firewall and bridge, one CDROM, existing backup untouched, source PS/CMD pinned by Git SHA-1 blob. No sample execution or guest/host VM disk mutations. On mismatch/failure, STOP and upload TXT; do not force media eject or blindly retry. GUI action if installed: double-click RUN_EGRESS_CHECK.cmd on Windows CD-ROM and send screenshot of C:\\Users\\Public\\Documents\\CAPE_Command2_GuestEgressProbe.txt.
- General portable auto-subnet selection previously implemented on development only; no claim complete three-command production automation or verified second-host run.


## 2026-10-12 07:49 UTC — COLD-BOOT CONTINUATION FOUND INACTIVE NETWORK; NO VM RESTART YET

Actual file `CAPE_Command2_ColdBootContinuation_20261012_074913.txt`:
- Current pilot `win11_1` was **SHUT OFF**.
- Existing cold bundle metadata accepted (`COLD_BUNDLE_METADATA_VALIDATED_NO_COPY_OR_RESTORE`), 3 previously hashed-at-capture files; report did NOT rehash or restore.
- Existing `cape-analysis-isolated` libvirt XML passed no-forward/port-isolated bridge checks.
- Stopped at `STOP: network inactive`. The source did NOT reach VM XML checking, approval or VM start. No network or guest changes in this command. The network has autostart disabled, so no persistent active bridge expected after a manual shutdown.
- Also discovered latent Python quoting bug in the previously generated Bash local `ssl55_cold_boot_continuation.sh`: embedded `d=r.findall("./devices/disk[@device="disk"]")` would be invalid Python. Do NOT reuse that wrapper.
- Added `scripts/command2_ssl55_cold_boot_resume.py` (**SSL55 only**, not portable entrypoint) and `scripts/test_command2_ssl55_cold_boot_resume.py` to development CI: read-only `plan` gate for master/trial VM IDs and shutdown, exact stopped clone XML, 3-file cold bundle metadata and isolated no-forward network, previously installed nft CAPE guard structural verifier, collision-free inactive bridge IP/network; `resume` requires local TTY exact phrases to first `virsh net-start cape-analysis-isolated` (ONLY if network is inactive), validate bridge IP and firewall and no global/site IPv6, then `virsh start win11_1` and wait bounded for benign host-bound CAPE Agent HTTP GET. Exclusive root lock serializes operator session. NO `net-autostart`, default NAT network, VM creation/force shutdown/malware/snapshot/revert or backup modification. After a PASS, run existing SHA-verified `command2_ssl55_post_blockpull_acceptance.py` for QEMU master-FD checks.
- If bridge start or VM start partially succeeds but later check fails, no automatic rollback; preserve state, inspect report, and do NOT retry blindly.
- Other-host automation must use host-dependent collision-free subnet and interface discovery, NOT this hardcoded SSL55 pilot script. Separate second-host full acceptance remains pending.


## 2026-10-12 07:34 UTC — COLD BACKUP ACTUALLY CAPTURED; RESTART STATUS UNKNOWN + PORTABLE AUTO-SUBNET

Actual uploaded `CAPE_Command2_ColdResume_20261012_073419.txt`:
- User shut Windows down manually with `shutdown.exe /s /t 0` after ACPI `virsh shutdown` timed out; host wrapper saw `win11_1` SHUT OFF, exact expected identity, 94.69 GiB pre-copy free, 29.98 GiB apparent source disk.
- `scripts/command2_ssl55_stopped_backup.py --mode capture` separately approved `CAPTURE-STOPPED-WIN11_1`; created NEW cold backup directory `/var/lib/libvirt/images/cape-clones-staging/cape-win11_1-cold-recovery/cold-b8c6f2d3b4ba4e948dc476b2a1b35c2d`. Report: `STOPPED_CLONE_BACKUP_CAPTURED_UNRESTORED` with three source+dest SHA256 verified files: `disk.qcow2`, `uefi-vars.fd`, `tpm-tpm2-00.permall`. Saved domain.xml and manifest.json. Original master untouched by backup code; no restore performed.
- Uploaded report **ENDS** at `========== PRE-BOOT NETWORK SAFETY ==========`. This report does NOT establish that the wrapper passed guard checks or restarted the VM. Current actual VM state is UNKNOWN; **inspect read-only first before any start**. Do not repeat checkpoint capture or blindly restart while wrapper might still be running.
- Backup is a verified cold artifact, not yet a VERIFIED RECOVERABLE RESTORE; CAPE Agent post-restart, guest independent cold-boot, IPv4/IPv6/L2 negative egress and running memory+disk+UEFI+swtpm snapshot/revert still unverified.
- **Other-host portability fix committed only to development**: `command2_target_host_preflight.select_analysis_subnet(profile,"auto")` selects first nonconflicting RFC1918 /24 candidate from target host kernel routes, interface addresses and all libvirt network inventories; default `--subnet auto` on `command2_portable_zero_nic_entrypoint.py`; source of selected subnet carried consistently through identity/IP allocation, guest JSON, network and CAPE configuration drafts and staging. Fail-closed on absent/invalid inventory, no suitable range, or explicitly specified overlapping subnet. Before ANY stage writes, fresh read-only target host preflight enforces unchanged outbound interface, subnet nonoverlap, RAM reserve and no generated UUID/MAC collision. No automatic nft changes; no NIC started. CI regression coverage added for overlapping routes, libvirt networks, invalid inventory and drift.
- Operator requested portability/no errors on another machine. Never promise zero errors. Current GitHub has only offline mock CI, NOT real complete 3-command validation on a second host. Separate validation required for installer dependencies, CAPE/INetSim, safe NIC/IPv6/L2 containment, Windows customization, TPM+UEFI snapshot and revert and count-based parallel analysis before production use.


## 2026-10-12 07:26 UTC — FIRST LIVE COLD BACKUP WRAPPER TIMEOUT; NO BACKUP MADE

User uploaded `CAPE_Command2_ColdBackupAndBoot_20261012_072649.txt` and screenshot. Exact result:
- `scripts/command2_ssl55_stopped_backup.py --mode plan` read-only PASS: clone running, apparent disk 29.98GiB, 94.69GiB free, conservative backup gate 74.98GiB, 3 artifacts including QCOW2/UEFI VARS/swtpm.
- Operator approved `APPROVE-WIN11_1-COLD-BOOT-TEST`. Wrapper invoked **`virsh shutdown win11_1`**, which said `Domain 'win11_1' is being shutdown` (request accepted, not poweroff proof).
- After waiting 60*3sec=180s it printed `STOP: Windows did not shut down gracefully. No forced shutdown or backup copy attempted.` IMPORTANT: no cold copy/checkpoint, no forced poweroff, no restart from wrapper. Exact current VM state AFTER timeout is **not reported**; must check `sudo virsh -c qemu:///system domstate win11_1`.
- Recovery: if still running, operator should open Windows desktop in virt-manager and initiate **normal in-guest shutdown** (`shutdown.exe /s /t 0`, no /f), then check state is `shut off`. If already off, do NOT send extra power signals. Never use `virsh destroy` or force power off.
- Once exact clone is shut off and all QEMU/swtpm PIDs exited, execute already-created stopped-only backup script with pinned SHA + explicit local TTY approval `CAPTURE-STOPPED-WIN11_1`. Only AFTER SUCCESS, verify network/guard and restart existing win11_1; then bounded benign agent GET and post-blockpull read-only acceptance. Preserve protected original master/trial. Do not retry old wrapper because it will demand running VM.
- Guard against user confusing first and second operator approvals. The first approved ACPI shutdown timing out does NOT mean second explicit copy approval occurred. No snapshot/revert/TPM restore/negative guest egress test.


## 2026-10-12 07:15 UTC — COLD CAPACITY PASS AND STOPPED-ONLY BACKUP CODE

User's REAL `CAPE_Command2_RecoveryPlan_20261012_071501.txt`:
- Result `COMMAND2_COLD_RECOVERY_CAPACITY_READONLY`; 94.69 GiB free, clone disk apparent 29.98 GiB/allocated 29.97 GiB.
- Conservative ONE cold file-copy bound: 74.98 GiB total including 40GiB shared-host reserve + 5GiB overhead. Capacity PASS at inspection time, must recheck immediately before capture.
- OVMF VARS 540672 bytes; swtpm 2.0 `tpm2-00.permall` 9234 bytes present. No shutdown/snapshot/copy/restore yet. Raw private repo URL 404 is expected, authenticated `gh api` fallback succeeded and exit status 0.
- Legacy `scripts/command2_cold_checkpoint.py` is unsuitable for current SSL55: asserts trial running, network inactive, ZERO clone NIC, and intentionally refuses capture on SSL55; DO NOT remove its safety refusal.
- NEW `scripts/command2_ssl55_stopped_backup.py` is separately bounded, development-only `--mode plan/capture`, target exact SSL55 clone UID, master and trial both shut off, dedicated isolated CAPE NIC, empty backing chain, OVMF/swtpm. **No VM lifecycle commands in this script.** Capture requires operator to have separately *gracefully shut off win11_1* and it refuses any running libvirt guest or remaining clone QEMU/swtpm PID. It checks peer disk/NVRAM refs, resource reserve, qemu-img check, writes new root-private cold directory with disk+VARS+TPM persistent state/domain XML/manifest, hashes each file on copy. Requires typed phrase and no blind retry. CI synthetic tests added.
- Only after cold bundle actually SAVED and success reported should operator independently restart exact clone after verifying isolated bridge/guard persists, then read-only run the established `command2_ssl55_post_blockpull_acceptance.py` to verify cold-boot disk independence and CAPE agent. Even that does NOT prove backup restoration or running snapshot/revert. No malware execution before containment negative proof.
- Keep original master win11 and win11_trial_1 immutable and off; no external routing, no IP changes. Do not assume snapshot/TPM/UEFI restore.


## 2026-10-12 07:12 UTC — POST-BLOCKPULL STILL PASS; RECOVERY CAPACITY REPORT STILL PENDING

Uploaded `CAPE_Command2_PostBlockpull_20261012_071208.txt` (NOT the requested `CAPE_Command2_RecoveryPlan_*.txt`). Existing post-blockpull read-only acceptance remained `SSL55_POST_BLOCKPULL_READONLY_ACCEPTED`:
- `win11_1` running, CAPE Agent 0.23 admin-positive, isolated NIC unchanged, live AND saved backing chains empty; original master image FDs all closed, original protected win11 and trial shut off.
- Clone allocated 29.97 GiB, free 94.69 GiB, QEMU PID 16439.
- No cold boot, cold backup, swtpm/UEFI restore, running snapshot/revert or negative guest egress test. Original images must remain unchanged, no malware.
- GitHub developer-only read-only `scripts/command2_ssl55_recovery_capacity_plan.py` committed to `development` (source blob 917ea44e435538f35cbd02908f7b073d4a7c7718). Its read-only acceptance report has NOT yet been uploaded. Added basic offline XML fixture tests to CI. The report computes actual apparent QCOW2 bytes plus 40GiB shared-host reserve + 5GiB overhead, and inventories TPM/NVRAM filenames/sizes without reading TPM secret bytes.
- NEXT: Execute exact SHA-pinned recovery capacity plan and upload `CAPE_Command2_RecoveryPlan_*.txt`. Do not repeat blockpull. Until backup and restore validated do not reboot/shutdown/snapshot/revert win11_1.


## 2026-10-12 — LIVE WIN11_1 BLOCKPULL ACTUALLY SUCCEEDED; POST-ACCEPTANCE NEXT

User uploaded `CAPE_Command2_Blockpull_Apply_20261012_064653.txt`. All facts below refer to REAL SSL55 host output.
- Root/operator approved phrase `FLATTEN-WIN11_1-CLONE-ONLY` and `virsh blockpull win11_1 sda --wait --verbose` completed to 100%, `Pull complete`.
- Exact result `CLONE_LIVE_BLOCKPULL_COMPLETED_XML_CHAIN_EMPTY`. Both LIVE and INACTIVE (saved) domain XML backing chains empty; protected original-master disk metadata unchanged; win11_1 remains RUNNING. No reboot, snapshot, revert, negative egress or cold checkpoint tests performed.
- This is credible completion of in-place disk flattening; independent cold boot and running-memory+disk+swtpm+UEFI revert still UNPROVEN, and previous 192.168.240.101 static IP/CAPE agent positive test precedes blockpull.
- Added `scripts/command2_ssl55_post_blockpull_acceptance.py` and synthetic tests, registered offline CI. The new standalone read-only acceptance checks exact saved/live XML emptiness, clone QCOW2 metadata, original-master image FD closure in the exact QEMU PID, clone disk/NVRAM open handles, master/trial untouched, one benign GET to isolated CAPE agent port 8000, and storage/free capacity. This does NOT write or alter any guest, network, host VM definitions or disks. No QMP command or internal snapshot.
- NEXT: Run one SHA-pinned verified read-only post-blockpull acceptance on SSL55, upload TXT. If PASS, design/execute a separately approved safe recovery/checkpoint strategy and benign network negative egress tests. Do not shut down or restart pilot until cold recovery storage and TPM/UEFI plan is verified. Do not revert generic internal RAW pflash snapshots. Do not run malware.
- Note libvirt blockpull without base is intended to flatten entire backing chain; confirmed by virsh official man page. The no-backing original header alone was not enough, so compare live QEMU FDs too.


## 2026-10-12 — BLOCKPULL REPORT: PASS PLAN; APPLY NOT STARTED (STDIN WRAPPER ERROR)

Uploaded `CAPE_Command2_Blockpull_20261012_064231.txt`:
- `--mode plan` **PASS** read-only: free 95.4 GiB, expected maximum growth 38.72 GiB, 40 GiB reserve, target sda, 64 GiB virtual, clone currently 29.28 GiB allocated, live and saved backing chains exactly expected.
- `--mode apply` immediately BLOCKED `Interactive local terminal required`. The preceding command launched `bash <<'BASH'` (Bash reads its stdin from the heredoc) and piped `sudo python3 ... --mode apply | tee`. Thus Python stdin was NOT a TTY. It refused **before blockpull**, no flatten happened. This is operator invocation error, not VM/libvirt test failure; do not reinstall or repeat network setup.
- CORRECTION: explicitly redirect just apply's standard input from `/dev/tty`: `sudo python3 -B "$FILE" --mode apply </dev/tty 2>&1 | tee "$REPORT"`. Preserve exact immutable file/blob SHA and preflight; do not bypass approval or failure guard. Interactive approval phrase remains `FLATTEN-WIN11_1-CLONE-ONLY`.
- If original master backing path stamps, XML, host free-space, or VM identities changed, preflight correctly refuses. If real blockpull begins and fails/interrupts, NO blind retry, blockjob inspection needed. If succeeds, verify post-operation report; TPM/UEFI and running-memory snapshot/restore still unverified. No master changes authorized.


## 2026-10-12 — GUARDED LIVE CLONE-ONLY BLOCKPULL PILOT PREPARED (NOT EXECUTED)

- The live QEMU PID holds open all three protected master image layers and the clone top. Current `win11_1` is **not proven independent**, despite qemu-img -U output without on-disk backing metadata.
- Added `scripts/command2_ssl55_clone_blockpull.py` and `scripts/test_command2_ssl55_clone_blockpull.py`, registered with Command2 offline CI. `--mode plan` ONLY reads exact SSL55 VM IDs (master/trial off, pilot running), live/inactive source XML backing chain, isolated NIC, OVMF VARS, swtpm backend, snapshot absence, all original source file metadata and worst-case clone image growth vs 40GiB shared-host reserve. It refuses unexpected states.
- `--mode apply` is a clone-only **STATE-CHANGING operation** requiring root, an interactive terminal, an exclusive root-owned lock and literal `FLATTEN-WIN11_1-CLONE-ONLY` typed by operator. Repeats preflight then executes ONLY `virsh blockpull win11_1 TARGET --wait --verbose` (no --base, no blockcommit; source image layers are read targets). On completion validates original master file metadata and both live/saved XML backing references are empty. On failure keeps VM/files in place and blocks blind automatic retries.
- This is NOT a checkpoint/backup, running memory snapshot, or proof of cold boot, TPM/UEFI recovery, CAPE restore, or IPv4/IPv6/L2 containment. Running blockpull CAN grow the clone QCOW2 and has nonzero I/O risk. Never run apply without explicit operator authorization. No host operations have yet been run from this script.
- After an actual PASS apply report, independently prove clone still boots without master dependencies (using carefully approved reversible test), CAPE Agent reachable, and design independent TPM/OVMF state recovery before any running memory snapshot/revert. No malware until negative containment accepted. No need to change existing 192.168.240.101 static guest address.


## 2026-10-12 — ACTUAL SSL55 ACTIVE FILE HANDLE AUDIT: MASTER DEPENDENCY CONFIRMED ACTIVE

Report: CAPE_Command2_ActiveDiskHandles_20261012_060328.txt, generated by immutable script at development 7d02415bd4bfd68e4e3eeba2a5496ebd493bf11e, SHA-verified. All operations read-only.

- win11_1 was RUNNING, exact UUID 732b2256-ee99-41fa-881d-fbf5c476d960; master win11 and trial win11_trial_1 SHUT OFF.
- Original-master image files `win11.Afterfull`, `win11.basicinstallwinsnapshot`, AND `win11.qcow2` were **all OPEN file descriptors** in the running win11_1 QEMU PID 16439 (fd 19,18,17 respectively); clone top disk fd 23. Running XML lists entire master chain. This is compelling evidence the running clone currently depends on original master files. Exact block-graph edge ordering was not independently queried. Do NOT claim it is fully independent or portable.
- `qemu-img info -U --backing-chain --output=json` on clone top showed ONLY the 64 GiB clone file (no backing header); this does not overturn live QEMU evidence and may reflect libvirt-supplied explicit XML backingStore.
- RAW OVMF pflash NVRAM clone fd 16; swtpm 2.0 state metadata tpm2-00.permall 9234B. These are NOT validated snapshot/revert preservation.
- Free space 95.39 GiB (shared heavily used root FS); clone allocated about 29.3 GiB. No space approval for flatten, conversion, additional clones or checkpoints. Snapshot created FALSE; restore proven FALSE; guest negative egress tests FALSE. No network/firewall modifications.
- Networking question: the master guest's 192.168.122.125 was on default libvirt NAT / virbr0 subnet 192.168.122.0/24. The deliberately separate existing cape-analysis-isolated network uses bridge cape-lab0 and 192.168.240.0/24; win11_1 192.168.240.101 and CAPE agent previously reached. Correct approach is to retain isolated subnet and never assign both networks to analysis guests. Security depends on bridge/firewall/packet proof, NOT on the numeric choice of .240. On other hosts discover collision-free subnets rather than hard-code 240 blindly.
- NEXT: design explicitly approved, stopped-VM, clone-only flatten/cold recovery strategy with space budget, master protection, TPM/NVRAM identity and independent snapshot compatibility. No live qemu-img convert or blind blockpull. Plan benign IPv4/IPv6/L2 egress negative tests. Do NOT modify original master or take an unproven running snapshot.


## 2026-10-11 — SAFEST NEXT DIAGNOSTIC: ACTIVE QEMU OPEN FILES (NO QMP)

- libvirt 11.1.0, QEMU 9.2.2, swtpm 0.7.3, libtpms 0.9.3 as reported, NO snapshot/revert performed.
- win11_1 uses RAW OVMF pflash VARS, swtpm 2.0, and live XML references old master image paths, but prior qemu-img info -U --backing-chain displayed only clone top. This remains UNRESOLVED.
- Originally a QMP query script was staged, but corrected BEFORE any user host execution: libvirt may mark a VM tainted when qemu-monitor-command is used. To avoid even that diagnostic side effect on shared SSL55, the CURRENT development audit uses NO QMP. It checks exact VM identities, reads libvirt XML, resolves exact QEMU PID using UUID+VM name, inventories /proc/PID/fd inode mappings to original master paths, and compares advisory qemu-img -U metadata plus clone TPM/OVMF file metadata.
- Script: scripts/command2_ssl55_runtime_block_audit.py and synthetic tests test_command2_ssl55_runtime_block_audit.py; CI paths already registered. Do not use older code from commits containing QMP queries.
- QEMU open file handles determine whether master files are held open, but DO NOT independently prove QEMU block-graph edge order; that would require separately authorized monitor inspection on an approved host or alternative evidence.
- NO snapshot, clone, flatten, rebase, revert, guest code or malware. Preserve original master/trial; do not change host firewall. Next: exact read-only QEMU FD report from SSL55, then select restorable disk/memory/TPM/OVMF plan and run separate benign negative IPv4/IPv6/L2 tests.

## 2026-10-11 21:29 UTC — ACTUAL SNAPSHOT READINESS REPORT; CRITICAL TPM/UEFI/BACKING RISKS

User uploaded CAPE_Command2_SnapshotReadiness_20261011_212919.txt:
- win11_1 RUNNING 4 CPUs 4GiB RAM, uuid
  732b2256-ee99-41fa-881d-fbf5c476d960.
- qcow2 active independent path
  /var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2,
  64GiB virtual, 29.3GiB allocated, qemu-img info says corrupt=false.
  Crucially RUNNING dumpxml reveals explicit backingStore chain
  win11_1.command2.qcow2 -> win11.Afterfull ->
  win11.basicinstallwinsnapshot -> win11.qcow2 (protected master
  referenced as backing data, not standalone clone). Do NOT rename,
  move, flatten, rebase or modify original chain on shared SSL55.
  qemu-img info -U --backing-chain printed only top image metadata,
  unlike runtime XML explicit backingStore; need resolve disparity
  before portable clone storage design.
- OVMF secure boot pflash CODE 4M and NVRAM VARS format RAW,
  /var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd.
  swtpm emulator 2.0 model tpm-tis. TPM/NVRAM must be restored
  consistently with VM RAM+disk, not implied by snapshot metadata.
- NO existing snapshots. virsh snapshot-create-as --print-xml
  returned only domainsnapshot name; NOT support/restore test.
- / disk fs available ~96 GiB, 90% used; refrain from clone
  image copies and unbounded snapshot data accumulation.
- CAPE bridge cape-lab0 has one live vnet0 port; host sysctl
  ipv4.ip_forward=1 and ipv6.all.forwarding=0.
- nft table inet cape_analysis_guard forward hook -50 drops
  ingress and egress cape-lab0, input drops new from cape-lab0,
  output allows only host TCP8000; presence is not packet-level
  IPv4/IPv6 external or L2 bridge negative acceptance.
- CAPE libvirt network remains ACTIVE manual, original Windows
  master/trial must remain shut off.
- VM libvirt dominfo: 'tainted: running with undesirable elevated
  privileges' -> analyze cause before production/security claims.

IMPORTANT architecture gate:
Current scripts/command2_running_cape_snapshot_gate.py performs
unspecified INTERNAL memory+disk snapshot via --atomic and
requires internal metadata on separate approved hosts. This is
UNSAFE ASSUMPTION with Windows 11 RAW pflash VARS + swtpm,
especially if basic clone storage chain still references master.
Libvirt internal memory snapshot with pflash has known compatibility
restrictions, raw varstore specifically disallowed in newer
pflash snapshot QMP implementations; external full snapshots may
be capturable but libvirt revert functionality and TPM/UEFI
consistency must be proven on a disposable host. Never run
snapshot-create-as without explicit mode validation and rollback
test for correct libvirt/QEMU/swtpm versions. Do not use
--force or blindly try snapshot-revert on SSL55.

NEXT: single small read-only version and QEMU/libvirt guest
capability check and backing chain inspect on SSL55; no new
guest media/commands, no snapshots, no host writes. Use findings
to select an actually restorable CAPE running snapshot approach,
then separate benign no-internet packet egress proof and
count-driven portable Command2 design. User requests speed,
avoid repeated broad inventory reports.
Source libvirt virsh docs and QEMU TPM docs were consulted.


## 2026-10-11 ~21:25 UTC: LIVE SSL55 WIN11-1 CAPE AGENT 0.23 PASS

User uploaded CAPE_Command2_Win11_1_AgentNetwork_20261011_212518.txt:
exact live win11_1, master/trial shutoff, master NIC preserved,
active CAPE nft guard after boot, libvirt no NAT/DHCP and
isolated network, exact host route to guest
192.168.240.101 via cape-lab0 using src 192.168.240.1.
One genuine read-only HTTP GET returned JSON with
CAPE Agent! version 0.23, is_user_admin=true. VERIFIED.
No need to reinstall agent, change guest IPv4, restart VM,
or repeat host libvirt/firewall configuration.

UNVERIFIED: actual negative guest IPv4/IPv6 egress,
live two-guest L2 isolation, full cold QCOW2+UEFI+swtpm
recovery, running full-system snapshot/revert. Do NOT
execute malware before those acceptance gates.

Relevant upstream CAPE agent /execute POST is available in
agent/agent.py but changes agent state to RUNNING, even for
benign commands, potentially altering analysis-ready baseline.
Avoid blindly invoking /execute for diagnostic probes; stick
to vetted benign guest diagnostic optical media or separately
approved status-preserving test. Host-side pure read-only
snapshot compatibility inventory should be done next;
VM uses OVMF/pflash + swtpm2, so virtual TPM/UEFI state
must be accounted for and snapshot compatibility verified.
Current separate-host running snapshot gate refuses SSL55;
do not bypass directly. No disk copy/snapshot until host
resource audit and specific permitted plan are reviewed.

NEXT: collect ONE read-only host file with libvirt snapshot
--print-xml, VM disk/UEFI/swtpm, free disk, bridge link ports,
IPv4/IPv6 forwarding and nft guards, then decide safe actual
negative guest traffic probes and snapshot method.


## 2026-10-11 21:19 UTC — WIN11-1 STATIC IPv4 CONFIG SUCCESS; next read-only agent/network audit

User screenshot of Windows CAPE_FIX FIX.PS1 apply Notepad:
COMMAND2_WIN11_1_GUEST_OLD_IP_TO_ISOLATED_IP_V1.
- Original win11_1 SMBIOS 732b2256-ee99-41fa-881d-fbf5c476d960,
  MAC 02-0A-30-6A-3F-50, one NIC ifIndex=12.
- Windows hostname already WIN11-1. DHCP disabled.
- Old IPv4 192.168.122.125/24 and exact old default route
  ifIndex 12 nextHop 192.168.122.1 REMOVED by explicit approved
  oneclick script. New 192.168.240.101/24 installed with NO gateway.
- After apply, IPv4 default route count=0, IPv6 default route
  count=0, IPv6 address only link-local fe80. MAC/UUID verified
  again and no Windows firewall/Defender changes. No VM restart needed.
- Ubuntu CAPE_Command2_Win11_1_FixRetry_20261011_211846.txt
  confirmed correct running VM and successful ISO insertion.
- Guest configuration SUCCESS, not yet actual host-to-guest CAPE
  agent success, packet negative IPv4/IPv6 external egress or L2
  lateral isolation. Running snapshot/revert NOT done.

New scripts/command2_ssl55_win11_1_agent_network_audit.py
plus scripts/test_command2_ssl55_win11_1_agent_network_audit.py
(8 synthetic tests). READ-ONLY on SSL55, verifies EXACT
protected running VM MAC/UUID, master/trial state, manual active
isolated network no NAT/DHCP, current enabled/replayed CAPE nft
policy, nftables service disabled, host route to guest dev
cape-lab0 src 192.168.240.1, then ONE harmless HTTP GET bound
to host cape-lab0 IPv4 (192.168.240.1) against guest
192.168.240.101:8000 without proxy or redirects and strict
CAPEv2 agent JSON/admin identity matching. Returns exit 3
with complete JSON report if agent unreachable, not a false
analysis approval. No new guest commands nor ISO needed.
Safety flags always explicitly FALSE for unperformed packet-level
negative IPv4/IPv6 guest egress, L2 and snapshot tests.

NEXT: user runs one SHA-pinned read-only host agent network audit,
uploads TXT, then resolve agent availability and proceed toward
running snapshot after actual containment and cold recovery
acceptance. Continue count-driven multi-VM Command2 build,
then Command3 and 3-command independent host verification.
INetSim service later; never execute malware before isolation.

## 2026-10-11 ~21:14 UTC — BLOCKED Windows CAPE_FIX ISO preflight due assistant parser BUG, not proven inactive network

User ran SHA pinned Windows fix optical ISO launcher from previous turn
(head 837a3c33093c78d63916bf7016e0a6e183f90e8e).
Read-only stage responded:
BLOCKED: Isolated network unexpectedly inactive.
No new ISO, no virsh change-media, no guest modification was done.
Root cause in scripts/command2_ssl55_oneclick_fix_iso_host.py:
- old virsh net-info check searched exact "active:     yes"
  or x.strip() == "active: yes", both reject ordinary padded
  Active:           yes even when bridge is ACTIVE.
- next preflight tried command("systemctl","is-enabled",
  "nftables.service") where disabled returns nonzero exit code
  (correct status but helper would have treated it as fatal).
Fixed both: strict parse_key_values(separator=":") normalizes keys
and whitespace, checks active=yes/autostart=no/persistent=yes/
bridge=cape-lab0; systemctl show (exit 0) instead of is-enabled
to confirm base nftables loaded+disabled+inactive, guard service
loaded+enabled+active+success. Add unit tests including mocked
complete preflight with padded columns and disabled base unit.
GitHub Actions run 38175722660 PASSED both Python and Windows.
Actual host network state NOT changed; do not call virsh net-start,
reboot or disable any checks. Rerun updated SHA-pinned optical
host script plan and optional oneclick CD media replacement.
Then doubleclick CAPE_FIX SETUP.CMD in Windows to guarded replace
old .122.125 IP with .240.101 if old route is expected.
No new VM/snapshot/malware, preserve master/trial.


## 2026-10-11 ~21:03 UTC — WIN11-1 diagnostic screenshot identifies exact stale NAT address

Windows Notepad output from CAPE_DIAG CD:
- Hostname WIN11-1 already CORRECT; do NOT rename.
- SMBIOS UUID 732B2256-EE99-41FA-881D-FBF5C476D960 correct.
- One Intel 82574L e1000e NIC InterfaceIndex=12 MAC 02-0A-30-6A-3F-50, Up.
- Current IPv4 192.168.122.125/24 (Manual, DHCP Disabled), inherited
  from original NAT/default VM; target guest IP 192.168.240.101/24.
- IPv6 guest interface link-local fe80 only; IPv6 default route no matching.
- Old diagnostic attempted nonexistent CIM route object 'PolicyStore' property;
  that error PREVENTED exact IPv4 default route readback, so gateway
  NextHop is NOT known from report. Do not assume it was .122.1.
- Original diagnostic ISO host report CAPE_Command2_DiagnosticISO_20261011_210225.txt
  confirmed new diag ISO mounted live+saved sdb; host/Windows IP unchanged.

User finds typing/copying text in offline Windows very difficult.
Added develop-only guarded Windows one-click converter:
- scripts/command2_ssl55_win11_1_oneclick_guest_fix.ps1 accepts
  Plan/Apply/Verify; checks exact WIN11-1 hostname, SMBIOS UUID,
  one UP e1000e MAC, old 192.168.122.125/24 with DHCP Disabled
  or already-desired 192.168.240.101/24, no extra NIC or other
  non-APIPA IPv4. Reads/default route NextHop/Index directly
  WITHOUT PolicyStore object property; refuses ANY IPv6 default
  or non-link-local global guest IPv6. Permits either ZERO IPv4
  default routes or exact old 192.168.122.1 on reserved adapter;
  blocks unknown default routes BEFORE mutation. Requires admin
  and user YES; removes ONLY exact old default route if found,
  removes ONLY old .122.125, sets .240.101/24 with NO gateway/DNS,
  revalidates absence of default IPv4/IPv6 routes. Reports to
  Windows Public Documents and opens Notepad. Never changes
  guest Windows Defender/firewall or runs malware.
- scripts/command2_ssl55_win11_1_oneclick_SETUP.cmd automatically
  checks exact script SHA256 and requests Windows UAC administrator
  approval via PowerShell Start-Process, no copied Windows commands.
- scripts/command2_ssl55_oneclick_fix_iso_host.py verifies
  SSL55 protected master/trial, exact running win11_1, live/saved
  isolated e1000e MAC/sdb CD, active CAPE nft guard, no NAT/DHCP
  libvirt bridge, root sentinel and Git blob-pinned source scripts;
  after interactive phrase creates small CAPE_FIX ISO via
  genisoimage (without recursive inclusion) and changes ONLY
  existing VM sdb from diag ISO to new ISO, --live --config.
  Preserves old diag ISO; no VM boot, other host networking change
  or file transfer dependency. On error do not rerun blindly.
- 6+7 offline tests, plus actual Windows PowerShell AST passed
  GitHub Actions run 38175451590; NOT live guest acceptance.

NEXT user command: immutable commit pinned downloader for 3 scripts,
  sudo Python host ISO staging plan + apply one TXT report; Windows
  Explorer -> CAPE_FIX -> double click SETUP.CMD -> accept UAC
  then type short YES ONLY if guarded exact old route matches.
  Upload resulting Notepad report/screenshot. If blocked report
  unknown route NextHop and no Windows modification.

Final goal unchanged: complete win11_1 static IP and safe packet
containment, CAPE agent, RUNNING snapshot benign revert, then
count-driven 1..16 multi VM automation (Command 2), Command 3,
final 3-command end-to-end other-host validation. INetSim after
core commands; no extra VMs or qcow2 copies on shared SSL55.

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
