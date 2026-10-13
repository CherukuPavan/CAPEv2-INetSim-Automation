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
