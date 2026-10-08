# Step 10 — CAPEv2 base installer post-run audit

**Observed 2026-10-08/09 on reference SSL-55.** User-uploaded read-only follow-up: `SSL55_Step10_BaseAudit_20261008_223455_7bKUBQyO.txt` (160 physical lines, 161 indexed). The screenshot previously showed the install command `sudo ./cape2.sh base 2>&1 | tee ~/cape2-base.log` running. **Current outcome: installer reached final "Done", but service readiness and dependency health are not yet proven.**

## Confirmed from user report

- Captured `cape2-base.exitcode` contains `0`. This was manually captured separately after a pipeline using `tee`; if `PIPESTATUS[0]` was not captured immediately, its meaning may be stale. **Do not take the zero alone as success for every internal stage**, especially because the installer continued after at least one service failure.
- `~/cape2-base.log` exists, **286097 bytes, 4550 lines**, ending `[+] cape2.sh - Done`; the report's keyword scan found 15 error-like lines. Those include harmless code-path names such as `exception_execution.py`, so a keyword count is **not** a count of distinct failures.
- `/opt/CAPEv2` exists and was owned by `cape:cape`, with `pyproject.toml` present. Active timezone `UTC` (note the upstream dependency routine sets this globally). Local edited installer SHA-256 `6f557625516feb6f23a8b5339e8b7483c6833073137942299f0d204330f30f9a`; it is **not** verified identical to upstream.
- The `~/CAPEv2` source repository produced Git's `dubious ownership` safety error under the user account, consistent with the previously recorded root-owned clone. **Do not casually disable Git safe-directory checking system-wide**; inspect permissions/ownership first or use a bounded read-only `git -c safe.directory=<exact path>` query after review.
- Snapshot of services: `cape-rooter.service` **active/enabled**; `cape.service`, `cape-processor.service`, `cape-web.service` **activating/enabled** (not confirmed healthy); `suricata.service` **failed/enabled** (a definite failure); `mongod.service` **not-found** (not proof that MongoDB is missing).
- Logged issues: `suricata.service` control-process failure, a `dnspython 2.6.1` pip uninstall/RECORD metadata error, `cp: cannot stat './conf/default/*.env'` (possibly absent optional file glob, check destination files), `update-alternatives` missing `upx`, a `doc-base` merge error and failed attempt to stop missing `tor@default.service`. YARA compiler warnings were also reported; no claim that all YARA or Suricata functionality is proven.
- Last 60 lines show jemalloc packages setup continuing after the Suricata failure. Therefore `[+] cape2.sh - Done` is **not sufficient evidence of operational CAPEv2**.
- The output's `No configuration changes performed` statement applies to the later **read-only verification script**, NOT to `cape2.sh base`: the base installer itself installed software and modified service/host configuration.

## Upstream source investigation (not confirmation of local copy)

Inspected `kevoreilly/CAPEv2/installer/cape2.sh` master blob `1bb76ccb84b5f67ca877ad863550b63687f51e37`:
- `base` calls dependencies, MongoDB, CAPEv2, YARA, Suricata, systemd, jemalloc and cron changes.
- `install_mongo()` **removes `mongod.service` if present and builds/starts `mongodb.service`** (around lines 985–1045). Therefore the previously audited `mongod.service=not-found` may be **expected upstream behavior**; check `mongodb.service`, MongoDB package/binary and journal before concluding success or failure.
- `install_CAPE()` copies a shell glob `conf/default/*.conf.default conf/default/*.env` (around line 1360); if zero .env files match, `cp` reports the literal glob as missing while the loop continues. Whether this matters depends on actual configuration requirements.
- `install_systemd()` enables/restarts CAPE, processor, web, rooter and Suricata and can leave errors to be diagnosed by journal; dependency function also changes timezone. **Do not rerun the full installer** as a generic repair.

## Gate and next step

**Step 10 installer execution completed, post-install validation: NEEDS_REVIEW (unresolved Suricata service failure, CAPE services only activating, MongoDB `mongodb.service` not yet checked, Python dependency and source-owner warning).** Do not proceed to live samples, Windows VM network setup with `default` NAT, or claim a fully operational CAPEv2. Continue with user-executed **read-only** multi-service inspection: `systemctl show` and bounded redacted `journalctl` for Suricata, CAPE and `mongodb.service`; database package and CAPE file checks, and a narrow installer log snippet. Then propose only evidence-based, reversible, separately approved corrections.

See [STEP_LOG.md](STEP_LOG.md), [ROADMAP.md](ROADMAP.md), [PORTABILITY.md](PORTABILITY.md) and [LIVE_MALWARE_CONTAINMENT_POLICY.md](LIVE_MALWARE_CONTAINMENT_POLICY.md). Do not commit raw installer logs, credentials or sensitive campus network details.

## Step 10B — Actual service root causes and disposition (user evidence 2026-10-08/09)

User executed the prior proposed **read-only** Step 10B diagnostic and uploaded `SSL55_Step10B_ServiceReview_20261008_223952_vDl4Vc9K.txt` (280 physical lines / 281 indexed). The report contains no installer, restart, reboot or configuration change.

**Corrections to Step 10A uncertainty:**

- `mongodb.service`: **loaded/active/running/enabled**, `mongodb-org` and `mongodb-org-server` **8.0.32**, `mongod` found under `/usr/bin`. **MongoDB is functioning as a service**; missing `mongod.service` is the upstream custom unit replacement, not proof of MongoDB installation failure.
- `postgresql.service`: active, umbrella unit `SubState=exited`; `pg_isready` **accepting connections**. `cape-rooter.service` and `cape-web.service`: active/running/enabled.
- `cape.service` and `cape-processor.service`: restart/exit-code. **Their journal explicitly identifies the blocker**: `CuckooStartupError` for **`cuckoo1` VM snapshot lookup**, because libvirt cannot find that domain. No Windows guest existed in Step 9. This is an **expected incomplete-deployment dependency**, not proof that the base installer failed. Creating a correctly named guest and snapshot, and aligning CAPE machinery settings, should resolve this specific error; verify after provisioning rather than claiming guaranteed end-to-end success.
- `suricata.service`: **failed**, installed `suricata` Ubuntu package `7.0.17` and executable present. Bounded journal proves unsuccessful startup but does **not show the detailed root cause**. This needs an independent targeted diagnosis/repair; creating `cuckoo1` is not a demonstrated remedy.
- `cape-web.service` currently runs but bounded historical journal reported `psycopg.errors.UniqueViolation` in PostgreSQL type metadata initialization. Do not diagnose an ongoing crash from historical errors; check stable web/database functionality after later stages.
- Existing `/opt/CAPEv2/conf/{cuckoo,reporting,routing,auxiliary}.conf` files present. `/opt/CAPEv2/conf/default` contains **0 `*.env` files**, explaining unmatched copy glob. `dnspython` 2.6.1 uninstall RECORD error remains a separate installation-hygiene concern, though active MongoDB is independently confirmed.
- Source directory ownership: `~/CAPEv2` root:root; `/opt/CAPEv2` cape:cape. Scoped read-only `git -c safe.directory=<exact location> rev-parse HEAD` succeeded without changing global Git settings; SHA output was redacted in user report.

**Disposition:** **Step 10B diagnostic complete**. Do **not** rerun the full base installer and do **not** force an immediate service fix before first Windows VM/snapshot setup. Continue reviewing the user's next installation-document command, but **do not attach the VM to `default` NAT**, let it reach institutional networks, or run real samples before independent isolation testing. Suricata remains a separate unresolved failed service and full system readiness is **not** claimed.
