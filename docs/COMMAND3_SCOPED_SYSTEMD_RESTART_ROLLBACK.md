# CAPE Command 3: journaled service restart and deployment-only reversal

**Scope:** five exact existing units only: `cape.service`, `cape-processor.service`, `cape-rooter.service`, `cape-web.service`, `suricata.service`.

Command3's guarded restarter now captures a **root-private before/after inventory** of each unit's systemd `Id`, `LoadState`, `ActiveState`, `UnitFileState`, `FragmentPath`, and `InvocationID`. It writes the pre-state *before* invoking the first restart, and records each successful restart and its invocation identity before moving to the next unit. After verification, the final journal includes all five post-state identities.

The separate scoped reversal, `scripts/command3_service_owned_rollback.py`, supports `--mode plan` (read-only) and `--mode rollback` (explicit interactive root approval). It accepts only an attested, complete, root-owned restart receipt matching the current host. A rollback plan stops **only** units that were inactive immediately before this deployment restart, are recorded active afterward, and still have the exact same invocation and unit-file identity. It preserves any unit that was already active, even if this deployment restarted it; restoring the original process memory is not technically possible through systemd. Units with state drift or unknown receipts prevent unattended reversal.

The reversal also refuses operation if any libvirt domain is running. It journals each requested stop *before* calling `systemctl stop`, verifies the unit becomes inactive, and records partial or uncertain results without automatic retry. It never enables/disables units, alters a systemd unit definition, changes firewalls, shuts down a Windows VM, touches swtpm, or deletes packages or images.

## Important acceptance boundaries

- Existing service restart remains guarded by independently established guest containment, valid CAPE tmpfs, exact configurations and a TPM-safe running snapshot. The current read-only inspection intentionally does **not** invent these witnesses.
- This service reversal is **not** whole-deployment rollback. Pre-existing active units are left running, even when deployment restarted them; their prior process state cannot be restored. Complete recovery also needs the separately owned CAPE config, packages, VM disk, OVMF, swtpm, host network and nftables transactions.
- A partially completed five-unit restart receipt is not silently treated as a successful sealed restore point. Manually review any partial failure.
- Neither helper operates on SSL-55 or SSL-46. Only a separately approved host is eligible for host mutation.
- Synthetic Python 3.10/3.12 tests exercise allowed and blocked service identities, rollback planning, preserved preexisting active units, failure journaling, approved stop order, and refusal to act on drift.

Do not use this subsystem as evidence that the final three-command fresh-host CAPEv2 automation, Windows TPM restore, or malware containment have been validated.
