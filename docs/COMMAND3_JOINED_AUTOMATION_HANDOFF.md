# Command 3 — Joined, exact-operator workflow handoff (development)

**Status:** Joined five-config editor PLUS separately approved five-service
restart mode coded and offline-tested, not a full release.
**Master/reference:** SSL-55 operator manually completed all seven
configuration/restart steps. On 2026-10-13 the user supplied actual runtime
proof that `cape.service` and the other four services were **active** after
mounting `/mnt/tmpfs` as a cape-owned 15,995 MiB tmpfs. No assistant-side
modification or rerun on SSL-55.

## What the joined entrypoint actually does

Entry: `scripts/command3_from_operator_reference.py`

`--mode plan` performs READ-ONLY checks for:
1. `api.conf [api] ratelimit = no`.
2. `auxiliary.conf [auxiliary_modules]`: **insert** absent `amsi = yes`;
   reconcile exactly fourteen other operator-reviewed existing settings.
3. `cuckoo.conf`: the operator's exact 22 existing settings, including
   local private PostgreSQL connection, resultserver IP `0.0.0.0`,
   `[tmpfs] enabled = on` and `freespace = 4096`, and unmodified cleaner
   key names **`binaries`, `tmp`, `analysis`** (never `*_days`).
4. `kvm.conf`: the imported actual `win11` master plus the verified
   Command 2 `win11_1..win11_N` clones. Names/IPs and snapshot references
   MUST match root-private Command2 journal, live/persistent NAT DHCP
   reservations, inactive libvirt VM definitions and named RUNNING RAM +
   disk + QCOW2 UEFI checkpoint metadata. The reference `win11`
   master IP `192.168.122.125` and snapshot `Afterfull` are only
   correct where verified; they are not portable constants.
5. `mitmdump.conf host`: current **verified new-host** permanent
   `default`/virbr0 NAT gateway (SSL-55's observed gateway
   `192.168.122.1` is an example, not a cross-machine constant).

The plan additionally reviews routing.conf, tmpfs and, when using
`--mode verify`, the five installed systemd unit states. The routing
reference is currently READ ONLY; no firewall or CAPE/INetSim route rules,
VMs, samples or service restarts are changed by the entrypoint.

`--mode configure` is an interactive, root-only **one-entrypoint batch**:
preflight all five config plans before any edits; verify that tmpfs will
actually work with the target enabled=on profile even if the existing
cuckoo.conf still says off; demand a batch authorization, recheck sources;
write a private per-batch witness; sequentially call the original helpers
with EACH helper's own approval, protected original backup, SHA recheck,
atomic edit and readback. On failure, persist a PARTIAL_OR_UNKNOWN witness
and STOP, with no automatic retry or destructive rollback.

`--mode restart` uses the SAME joined Command3 entrypoint, but only
AFTER all five configuration files exactly match the planned targets
and the target `/mnt/tmpfs` passes admission. It additionally checks the
existing `routing.conf` against the operator's six settings (the tool
DOES NOT automatically write that disputed route). With root, a direct
terminal and separately typed consent, it invokes only the approved
`cape.service`, `cape-processor.service`, `cape-rooter.service`,
`cape-web.service`, `suricata.service` in the supplied operator order.
Each completed stage is persisted in a root-private progress witness;
a failure or unexpected state halts without automatic retry. Verification
requires all five loaded units active in consecutive status samples.
This proves service status only, NOT guest boot, actual snapshot restore
or any malware-analysis acceptance.

`--mode verify` re-runs read-only checks, including systemd unit health,
and reports outstanding independent acceptance blockers. It does not
assert CAPE_READY or automatically restart anything.

## Expected host prerequisites for plan / configure

- A separately approved new Ubuntu host with finished Command1 host
  software and an imported exact golden `win11` (the current Command1
  installation is not yet end-to-end complete).
- Finished Command2 guest provisioning and independently named running
  snapshots. ALL analysis VMs must be **SHUT OFF** for Command3 libvirt
  registration. No running snapshots may be assumed safely restorable
  without TPM-consistent benign acceptance on that target.
- CAPE config files exist with the exact operator-reviewed sections and
  option spellings. No helper invents missing application settings.
- The PostgreSQL CAPE local DSN already exists in the config or is
  provided through `--db-dsn-file`, a **pre-existing root-owned 0600**
  file containing the actual local `postgresql://cape:<password>@localhost:5432/cape`
  URL. NEVER commit, upload or print database passwords.
- Root-owned CAPE configuration backup folder parent is available;
  root witness folder will be created under `/var/lib` if missing.
- `/mnt/tmpfs` must be an **actual tmpfs mount**, cape UID/GID owned,
  owner-writable/traversable with at least 4096 MiB available **before
  the configuration batch starts**. This avoids the exact CAPE startup
  failure observed on SSL-55. A separate reviewed Command1 new-host
  component is `command1_cape_tmpfs_mount.py` (plan then approved apply),
  which writes a persistent systemd mount and dependency, not a CAPE
  service restart. Reboot acceptance is still pending.

## Invocation format — template, NOT an SSL-55 command

Replace every angle-bracket parameter with actually verified new-host
values. **Do not run these on SSL-55.** They are for the final target-host
acceptance phase, not needed from the operator now.

```bash
sudo python3 scripts/command3_from_operator_reference.py \
  --mode plan \
  --approved-host <TARGET_HOSTNAME> \
  --journal /root/<COUNT_JOURNAL_FOLDER>/command2-identity-reservation.json \
  --master-ip <ACTUAL_MASTER_WINDOWS_IPV4> \
  --master-snapshot <ACTUAL_RUNNING_MASTER_SNAPSHOT> \
  --tag win11
```

After every plan/gate passes and approved changes are required, change
`--mode plan` to `--mode configure`. Additional optional arguments:
`--conf-dir`, `--backup-dir`, `--db-dsn-file`, `--witness-dir`.
Then run the same command using `--mode verify` to read service states.

**Command 3 is NOT yet a fully unattended one-command installation:**
The plan, configure, restart and verify *modes* are separate invocations
of the same entrypoint with bounded per-stage approvals.
- `routing.conf` in the operator's guide set `route = internet` and
  `internet = virbr0`; this is still review-only, NOT applied by batch.
- The approved five-service restart stage now has a guarded
  `--mode restart` executor; it will not run until routing.conf has
  been separately and explicitly set to a reviewed target profile.
  It does not declare samples/VM snapshots ready.
- A full fresh-host CAPE installation, complete unattended firstboot of
  N clone guests, TPM-consistent running-snapshot restoration and
  target-host integration checks remain separate blockers.
- Each config write still requires explicit approval; this is intentional
  at the development stage and should not be called fully unattended.
- Offline test success proves deterministic code behavior, **not**
  Windows boot, libvirt running checkpoint reset, service health on
  another machine, or all required software in a fresh OS.

## Authoritative operator steps and evidence

- `docs/COMMAND3_STEP_TRACKER.md` — steps 1–7, original exceptions and
  screenshots/user confirmations.
- `docs/COMMAND3_TMPFS_STARTUP_FAILURE_AND_REPAIR.md` — actual SSL-55
  crash and successfully repaired current boot.
- `docs/COMMAND12_PRE_COMMAND3_ENGINEERING_AUDIT_20261013.md` —
  code completeness and remaining Command1/2 gates.
