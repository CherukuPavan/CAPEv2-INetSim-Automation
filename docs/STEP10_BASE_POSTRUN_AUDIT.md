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
