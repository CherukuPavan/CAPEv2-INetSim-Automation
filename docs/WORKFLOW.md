# Verified-manual-build to automation workflow

> **Current stage (2026-10-09):** The user has completed the reference `win11` master, its tested host reachability and both final snapshots. A cold snapshot with a four-layer QCOW2 chain is the current Command 2 clone candidate. Four-command architecture is authoritative: [FOUR_COMMAND_ARCHITECTURE.md](FOUR_COMMAND_ARCHITECTURE.md). Command 1 still lacks safe, complete unattended Windows/CAPE-base installation; Command 2 is offline-tested code, not accepted on SSL-55. CAPE finalization belongs to Command 3 and INetSim belongs to Command 4.


## Source of truth
SSL-55 is the reference machine for the **user-led manual** CAPEv2 + Windows analysis VM installation. The user has completed the first Windows master and the cloning-code development is underway. **Do not start recording Command 3 CAPE UI/service changes or Command 4 INetSim setup until Commands 1 and 2 are ready for host acceptance testing.** The user supplies exact manual commands, configuration changes, GUI actions, results, and evidence at each later stage. Do **not** assume prior experiments or rolled-back changes form part of the canonical build.

## Per-step evidence record
For each manual step, record:
- Step number, date, objective, exact command or GUI sequence, and who performed it
- OS/package/version prerequisites; input files; paths; permissions
- Configuration before/after; expected outputs; actual outputs and evidence
- Validation, troubleshooting, rollback/recovery, and portability notes
- Automation implementation status: **not started / draft / reviewed / tested**

Distinguish **user reported**, **log verified**, **inferred**, and **not verified**. Never treat a draft automation module as proven by manual testing alone.

## Development rhythm
1. User manually performs a step on SSL-55.
2. Review and capture the step faithfully.
3. After a coherent group of verified steps, implement an idempotent automation module on the `development` branch.
4. Review code and checks; validate separately on a supported clean test host.
5. Promote changes to `main` only after user approval and evidence-based testing.

## Project constraints
- Do not alter SSL-55 unless explicitly requested by the user.
- Do not include credentials, private keys, malware samples, snapshots containing sensitive content, or confidential environment details in Git.
- Secure guest networking: no accidental routable internet or corporate LAN path. Validate isolation, not merely configuration.
- Keep all diagnostic output in consolidated report files when practical.
- Prior rolled-back QEMU/libvirt installation steps are **historical, not an approved manual build**.

## Fresh-host portability contract
Every automation module must follow [PORTABILITY.md](PORTABILITY.md): discover required dependencies and versions, reuse compatible existing installations, provision missing supported components **during the authorized installer stage**, then test the actual result. A read-only preflight must **not** install or change anything. Do not assume a package exists because it was present on SSL-55. Stop safely when prerequisites cannot be met; preserve unrelated services and network isolation. Cross-machine deployment success requires tests on independent fresh supported Ubuntu hosts.
