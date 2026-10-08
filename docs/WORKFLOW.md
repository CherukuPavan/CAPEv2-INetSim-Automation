# Verified-manual-build to automation workflow

## Source of truth
SSL-55 is the reference machine for a **fresh, user-led manual** CAPEv2 + Windows analysis VM + INetSim VM installation. The user performs every manual operation and supplies the exact commands, configuration changes, GUI actions, results, and evidence. Do **not** assume prior experiments or rolled-back changes form part of the canonical build.

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
