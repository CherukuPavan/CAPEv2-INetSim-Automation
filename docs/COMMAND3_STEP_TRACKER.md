# Command 3 operator-verified step tracker (development)

**Source of truth:** operator's manual changes on reference host SSL-55, recorded
one by one. Screenshots can document the *guide's intended* change, but do not
prove the running SSL-55 config unless the operator confirms or a masked
read-only host audit is inspected. No assistant execution on SSL-55 occurred.

## Step 1 — reported completed on SSL-55 (2026-10-13)

- Guide: Section 13, "Tell CAPE About the Virtual Machine"; 13.2.1 API configuration.
- File: `/opt/CAPEv2/conf/api.conf`.
- Section: `[api]`.
- Operator reports changing **`ratelimit = yes` -> `ratelimit = no`** on SSL-55.
- This is a *configuration-file edit*, not evidence that any CAPE service was
  restarted or that the change has taken effect in a live API process.
- Do not infer network exposure, API authentication, actual contents of the
  file on disk, or any completed multi-VM CAPE registration from the picture.
- **Security:** `ratelimit = no` disables an abuse-prevention control.
  Apply only in a trusted, access-controlled lab and never expose the API to
  arbitrary Internet users. If an API endpoint is broadly reachable,
  retain/restore `ratelimit = yes` until access restrictions are verified.

### Development automation

- `scripts/command3_cape_api_ratelimit.py` supports a read-only `plan`
  and explicitly approved root-only `apply`. Its parser requires one `[api]`
  section and one live `ratelimit` key, changes no other setting, writes
  a root-private `0600` backup before replacing the config atomically,
  preserves original owner/mode, checks the source hash again before writing,
  blocks ambiguous/missing/insecure files, and is idempotent when value is
  already `no`. It does **not** restart any service.
- `scripts/test_command3_cape_api_ratelimit.py` is a synthetic regression
  suite that touches only temporary files. GitHub Actions offline tests run on
  supported Python versions; success does not establish SSL-55 configuration
  or service-level behavior.
- Operator should **not run this apply script again on SSL-55** simply to
  "match automation"; the manual change is already reported complete.
- The script is a **component** of a future all-configuration Command 3
  orchestration, not the finished one-command Command 3 installer.

## Step 2 — reported completed on SSL-55 (2026-10-13)

- Guide: Section 13.2.2, auxiliary module configuration.
- File: `/opt/CAPEv2/conf/auxiliary.conf`.
- Section: `[auxiliary_modules]`.
- **Operator's important correction:** The actual SSL-55 file had **no
  `amsi` option at all**. The automation must **INSERT** `amsi = yes`
  directly beneath the section header, not assume it exists as `amsi = no`.
- Other **14 existing** options and their operator-confirmed target values:

| Existing key | Expected value |
|---|---|
| `curtain` | `yes` |
| `evtx` | `yes` |
| `human_linux` | `yes` |
| `procmon` | `yes` |
| `recentfiles` | `yes` |
| `screenshots_windows` | `no` |
| `screenshots_linux` | `no` |
| `sysmon_windows` | `yes` |
| `usage` | `yes` |
| `file_pickup` | `yes` |
| `permissions` | `yes` |
| `pre_script` | `yes` |
| `during_script` | `yes` |
| `browsermonitor` | `yes` |

All other settings (such as `browser`, `digisig`, `disguise`,
`human_windows`, `sysmon_linux`, `tlsdump`, `filecollector`,
`windows_static_route`, `tracee_linux`, and `sslkeylogfile`) remain
as found. **Do not** overwrite auxiliary.conf with a small example file,
which would erase the operator's actual settings.

### Development automation

- `scripts/command3_cape_auxiliary.py` provides root-guarded read-only plan
  and typed-approval apply. It inserts the absent AMSI line, updates only
  the 14 reviewed boolean keys, preserves other sections/comments/format,
  and rejects duplicate/missing mandatory settings or unexpected values.
- SHA-recheck, root-private 0600 backup, file owner/mode preservation,
  atomic replacement and readback; repeated application is a no-op.
- `scripts/test_command3_cape_auxiliary.py` includes the **real operator's
  missing-AMSI scenario**, preexisting AMSI=no, already-correct settings,
  CRLF, duplicates/missing keys, hash-race, private backup and no restart.
- No assistant-run host operation or service restart; the operator reports
  manual changes already made on SSL-55. Do not reapply there.

### Dependencies and possible functional impact (not yet accepted)

- `browsermonitor = yes` requires the browser extension / supporting
  CAPE components; config enablement alone is not installation proof.
- `sysmon_windows = yes`, `procmon = yes`, and `amsi = yes` require
  guest tools, CAPE package compatibility, and appropriate Windows
  privileges/features; test on a **benign isolated** guest.
- `pre_script`, `during_script`, `file_pickup`, `permissions`,
  `recentfiles`, and `usage` may change analysis behavior, artifacts
  and storage usage. Validate their dependencies and operator intent
  before machine acceptance.
- Turning off both screenshot options reduces analysis screenshots;
  confirm the expected observability trade-off during acceptance.
- `human_linux = yes` is recorded exactly as requested even though the
  current reference analysis VM is Windows 11; do not infer a Linux
  analysis VM exists.

## Step 3 — reported completed on SSL-55 (2026-10-13)

- Guide: Section **13.2.3**, CAPE core `cuckoo.conf`.
- File: `/opt/CAPEv2/conf/cuckoo.conf`.
- Operator confirms the manual edit was completed. **Their corrections override
  the AFTER figure**: `[resultserver] ip = 0.0.0.0` (not
  `192.168.122.1`), and the **existing cleaner keys are exactly**
  `binaries`, `tmp`, and `analysis` (NOT `binaries_days`,
  `tmp_days`, `analysis_days`). Keep existing section/key spelling
  verbatim. An actual terminal screenshot confirms the cleaner spellings.

### Exact operator target

| Section | Existing keys and final values |
|---|---|
| `[cuckoo]` | `machinery_screenshots = on`, `memory_dump = on`, `reschedule = on`, `freespace = 0`, `freespace_processing = 0` |
| `[resultserver]` | **`ip = 0.0.0.0`**, `store_csvs = on`, `upload_max_size = 1000000000` |
| `[processing]` | `analysis_size_limit = 1000000000` |
| `[database]` | `connection = postgresql://cape:<PRIVATE_PASSWORD>@localhost:5432/cape`, `timeout = 150` |
| `[timeouts]` | `default = 300`, `critical = 300`, `vm_state = 150` |
| `[tmpfs]` | `enabled = on`, `freespace = 4096` |
| `[cleaner]` | `enabled = yes`, **`binaries = 0`, `tmp = 0`, `analysis = 0`**, `mongo = yes`, `unused_files_in_mongodb = yes` |

**Total: 22 existing options**, including private database connection; the
script changes only those whose values are different. No invented cleaner
aliases, unwanted sections, or unrelated settings.

### Development automation

- `scripts/command3_cape_cuckoo.py` offers read-only `--mode plan` and
  typed-confirmed root `--mode apply`. It uses the existing `cuckoo.conf`,
  never rewrites the whole file from PDF, and requires all 22 keys exactly
  once in their correct sections. Invalid booleans/numbers/IPv4 or PDF
  `*_days` cleaner aliases fail closed, instead of being changed blindly.
- A valid, existing local PostgreSQL CAPE URL stays unchanged. If the
  database connection is missing/blank/placeholder on a **new host**,
  the deployer needs `--db-dsn-file` referring to a **preexisting root
  owned 0600 file**, containing the locally provisioned
  `postgresql://cape:<encoded-password>@localhost:5432/cape` URL.
  No password is hardcoded in source, reports, CI logs, or Git commits.
  No evidence that the database was actually reachable is claimed.
- Explicit approval, before/after SHA256, private original-config backup,
  ownership/mode preservation, atomic replace, readback and no-op repeat.
  It never restarts CAPE, alters guest VMs, changes services or exposes
  DB credentials. No need to rerun manually finished steps on SSL-55.
- Regression tests include the **operator's two corrections**, correct
  multi-section options, a blank initial DB connection, the root-only
  private-DSN pathway, secret redaction, backup, malformed values,
  repeat-run idempotence and non-restart behavior.

### Safety/acceptance gates before ANY CAPE service restart

1. **`0.0.0.0` listens on all IPv4 interfaces**, including potentially
   campus/public-facing ones. Result-server port exposure, API access,
   firewall allowlist and host route/isolation must be verified; a
   wildcard bind is **not** proof of sandbox containment.
2. `memory_dump = on` creates potentially large files while the two
   free-space thresholds are **disabled (0)**. Check host capacity and
   capacity alarm/recovery, rather than accepting zero as "safe".
3. `[tmpfs] enabled = on` requires an actual configured tmpfs mount and
   enough reserved RAM/disk for guest analysis on the target host.
4. The cleaner's zero-valued `binaries/tmp/analysis` settings and
   `mongo = yes` could trigger aggressive retention/deletion policies.
   **Protect needed samples and analysis results; review effective CAPE
   cleaner semantics before enabling the service.**
5. PostgreSQL role/password/DB must exist, be reachable, and remain
   private; connection-string syntax alone is insufficient.
6. `store_csvs`, `upload_max_size`, `analysis_size_limit` change
   storage and upload limits; verify storage quotas/permissions and
   CAPE version-specific units on the new machine.

No restarts, samples, tests on reference snapshots, nor network edits
were performed by this development-only GitHub work.

## Step 4 — `kvm.conf` master and all additional Windows analysis VMs

**Manual reference completed (operator confirmation, 2026-10-13):**
`/opt/CAPEv2/conf/kvm.conf`. The screenshot of the guide shows a
`win10` example; **DO NOT use that machine**, `snapshot1`, or the
guide's `192.168.122.100`. User's actual master on SSL-55:

```ini
[kvm]
machines = win11
interface = virbr0
dsn = qemu:///system

[win11]
label = win11
platform = windows
ip = 192.168.122.125
tags = win11
snapshot = Afterfull
interface = virbr0
resultserver_ip = 192.168.122.1
arch = x64
reserved = no
```

- `tags = win11` is the automation's default. If the operator
  explicitly selects the alternative `22H2`, use **only one** of
  `win11` or `22H2`, not both in the tag field.
- The master `Afterfull` is the **user-reported exact snapshot name on
  SSL-55**, not a portable assumption that the new-machine imported
  master already has it. Before accepting the target config, match the
  named libvirt running-state RAM **and disk** snapshot metadata.
  A snapshot's existence still **does not certify swtpm2 consistency or
  CAPE-safe restore**.
- The documented `192.168.122.125` belongs to the **existing SSL-55**
  Windows master. A new machine must supply the actual guest master IP,
  and the script checks it is a private address on the verified NAT
  subnet but cannot inspect the shut-off guest OS to independently prove
  its effective static IP. That is an acceptance blocker until tested.
- The `192.168.122.1` `resultserver_ip` is the **address each NAT
  analysis guest uses to reach the host**, not the `[resultserver]`
  **bind** value `0.0.0.0` in `cuckoo.conf`. The host resultserver
  wildcard bind is subject to strong firewall/network isolation.

### Count-driven Command 3 behavior

After Commands 1 and 2 have produced a correctly imported master,
unique guest VM identities, permanent DHCP reservations and candidate
running-state snapshot metadata, Command 3 must produce:

```ini
[kvm]
machines = win11,win11_1,win11_2,win11_3
interface = virbr0
dsn = qemu:///system

[win11]
# ... original master fields above ...

[win11_1]
label = win11_1
platform = windows
ip = <actual verified unique clone 1 IPv4>
tags = win11
snapshot = cape_one_nat_win11_1
interface = virbr0
resultserver_ip = <verified NAT host gateway IPv4>
arch = x64
reserved = no

# ... matching [win11_2], [win11_3] sections, one for each requested VM
```

The independent clone IPs are **derived from Command 2's actual,
persistently registered `default`/virbr0 NAT DHCP MAC reservations**,
not from the sample documentation, and not from the old isolated-network
placeholder or presumed +1 IPs. Current candidate clone snapshot names
are `cape_one_nat_win11_N`. Older repo helpers also contain
`cape_ready_win11_N` and `snapshot1` speculative examples: these
**must not** be used for the current master-NAT flow without an actual
matching snapshot and validated new design.

### Development automation (completed offline, not host accepted)

- `scripts/command3_cape_kvm.py` is read-only in `--mode plan` and
  supports an explicitly approved root-only, **other-host-only**
  `--mode apply`. Inputs include `--approved-host`, canonical
  `--journal`, `--master-ip`, `--master-snapshot` and optional
  `--tag win11|22H2`. The script checks the canonical count-driven
  private journal, libvirt domain identity, saved DHCP assignments,
  guest OS/UEFI QCOW2 snapshot metadata, and the master RAM + disk
  snapshot metadata. It refuses missing/misnamed/misordered VMs and
  ambiguous configuration sections.
- It **replaces** a recognized inactive legacy `[cuckoo1]` example
  when `[kvm] machines = cuckoo1`; alternatively it updates the
  already configured `[win11]` master without duplicates. Other
  sections, comments and unrelated attributes remain intact.
- It lists `win11,win11_1,...,win11_N` in `[kvm] machines`, creates
  one machine stanza per VM, sets `interface = virbr0`, host gateway
  resultserver address, one selected tag, real IP, per-VM named
  checkpoint, `arch = x64` and `reserved = no`.
- File apply requires direct typed consent and makes a new root-private
  `0600` backup before a hash-rechecked atomic replacement. Repeating
  a completed configuration is a no-op. It never executes a service
  restart, VM boot/revert, storage deletion or analysis job, and refuses
  automatic apply to reference SSL-55.
- `scripts/test_command3_cape_kvm.py` exercises the old
  `cuckoo1` fixture, operator's existing `[win11]` scenario,
  `1..16` independently rendered clone sections, alternative
  single tags, unexpected names, duplicate keys, CRLF, missing
  master snapshot RAM/disk, unchanged plan, explicit approval,
  backup/readback/repeat and SSL-55 refusal.

### Acceptance still required

A **CAPE KVM config write does not prove a working CAPE VM**. The
hardware-independent offline tests cannot prove live Agent TCP access,
guest IP uniqueness after start, swtpm2/UEFI/disk+RAM coherent snapshot
restore, CAPE task cycle or malware egress isolation. Keep the
documented deferred new-machine benign tests as hard release gates.
As an additional consequence, the script does **not** declare CAPE_READY
and must not be mistaken for the full single-command Command 3
orchestrator/service restart.

## Step 5 — `mitmdump.conf` host for approved libvirt NAT

**Operator-specified next edit (2026-10-13):** In
`/opt/CAPEv2/conf/mitmdump.conf`, change exactly the existing active:

```ini
host = 192.168.122.1
```

The `192.168.122.1` address is SSL-55's known **host-side
`virbr0`/default libvirt NAT gateway**. This is NOT the wildcard
`0.0.0.0` value specified in Step 3 for
`cuckoo.conf [resultserver] ip`. Do **not** use `0.0.0.0` for
this `mitmdump.conf host` option.

User specified the edit but has **not explicitly confirmed** in this
turn whether it is already saved on SSL-55; do not mark the manual
reference as independently verified. No assistant operation on SSL-55.

### Portable guarded development automation

- `scripts/command3_cape_mitmdump.py` checks exactly one active
  `host =` key in `mitmdump.conf`, keeps original comments and every
  other setting intact, and refuses duplicate, absent, malformed or
  symlinked config entries.
- Default target IP is **discovered from the actual active AND saved**
  libvirt `default` NAT gateway/bridge/subnet on the new machine. Thus
  the established SSL-55 setting resolves to `192.168.122.1`,
  but a supported target with an approved DIFFERENT verified
  private NAT /24 uses its own actual gateway. An explicit `--gateway`
  is an additional ASSERTION that must match what is discovered, never
  an override for an arbitrary/public IP.
- Read-only `--mode plan`; typed-approved root-only
  `--mode apply` on **approved other hosts, never reference SSL-55**.
  Idempotent already-correct settings require no write.
  Change includes a private root-owned 0600 original backup, ownership
  and mode preservation, same-directory atomic replace and SHA256
  revalidation. Never restart CAPE, start/revert a VM, change libvirt
  NAT, or run samples.
- `scripts/test_command3_cape_mitmdump.py` runs synthetic-only tests
  for exact one-key preservation, CRLF/comments, different new-host NAT,
  mismatch/duplicate/invalid/unsafe IP, no-write plan, host rejection,
  private backup, and idempotent re-apply.
- Network access to MITM/INetSim and firewall isolation remain
  separate future acceptance gates. A successful config edit alone
  does not prove traffic routing or public egress containment.

## Pending operator steps

Await the next supplied configuration-file edit. For each step, document
exact file/section/key, operator's desired value, project-specific reason,
the old value if known, dependency/security impact, and idempotent regression.
Do not invent unspecified `kvm.conf`, `routing.conf` or other future values. The operator-confirmed `cuckoo.conf` fields are recorded above.

Restart CAPE/related services **only after** the complete reviewed change
set and its service dependency order have been validated. Do not assume a
service restart is sufficient proof of correct CAPE machinery, snapshot
revert, all-N analysis guest visibility, or network/malware containment.

## Global status

Commands 1 and 2 still have blockers documented in
`docs/COMMAND12_PRE_COMMAND3_ENGINEERING_AUDIT_20261013.md`. Protected
original Windows master `win11`, reference clone `win11_1`, existing
snapshot records, SSL-55 host state and GitHub `main` branch are not
changed by this development-only Command 3 code.
