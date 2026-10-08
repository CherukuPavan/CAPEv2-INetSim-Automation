# Automation roadmap (provisional)

The final target is a portable **three-command** workflow, derived from user-verified manual installation rather than guessed from an existing host.

1. **Command 1:** Bootstrap necessary dependencies and deploy CAPEv2 with the first Windows analysis VM.
2. **Command 2:** Ask for the number of additional Windows analysis VMs and provision parallel CAPE analysis.
3. **Command 3:** Deploy a separate Ubuntu INetSim VM and integrate all Windows guests using a tested isolated analysis network.

Cross-cutting requirements: Ubuntu compatibility checks; resources and CPU virtualization; permissions; reproducible configuration; safe re-runs; error detection; progress logs; secrets management; network isolation; validation tests; rollback and recovery.

## Current implementation status — 2026-10-08

- Canonical manual **Steps 1–3 recorded** in `docs/STEP_LOG.md`: host/interface baseline, installation of `cpu-checker`, and evidence that KVM acceleration is available on SSL-55.
- `scripts/check_host_virtualization.sh` is an **initial read-only draft**, not one of the three deployment commands. It does not install packages, modify networking or configure KVM.
- Draft underwent Bash syntax validation and a negative-path smoke test in a separate restricted environment; it has **not** been run or validated on SSL-55. The restricted environment lacks a usable KVM device, so it cannot establish host readiness.
- APT duplicate VirtualBox repository entry warnings were observed on SSL-55. **No source changes** have been authorized or made as part of our workflow.
- **No deployment command is implemented or validated yet.** CAPEv2, Windows guests, INetSim VM, parallel analysis and network isolation remain to be manually verified and automated.

## Cross-machine release gate

Follow [PORTABILITY.md](PORTABILITY.md) for the dependency-by-dependency bootstrap contract and the fresh-machine test matrix. Completion requires supported-OS/hardware declarations, independent clean-host testing with dependencies absent, idempotent reruns, recovery from failures, protection of existing services, and verified network isolation. **Do not claim compatibility with every arbitrary machine.**

The initial `scripts/check_host_virtualization.sh` is deliberately **read-only**. Missing packages will be provisioned by future installer/bootstrap modules **after** sufficient manual evidence and design review; absence of an optional diagnostic tool does not automatically authorize installation during preflight.
