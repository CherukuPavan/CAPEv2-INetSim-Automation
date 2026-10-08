# Automation roadmap (provisional)

The final target is a portable **three-command** workflow, derived from user-verified manual installation rather than guessed from an existing host.

1. **Command 1:** Bootstrap necessary dependencies and deploy CAPEv2 with the first Windows analysis VM.
2. **Command 2:** Ask for the number of additional Windows analysis VMs and provision parallel CAPE analysis.
3. **Command 3:** Deploy a separate Ubuntu INetSim VM and integrate all Windows guests using a tested isolated analysis network.

Cross-cutting requirements: Ubuntu compatibility checks; resources and CPU virtualization; permissions; reproducible configuration; safe re-runs; error detection; progress logs; secrets management; network isolation; validation tests; rollback and recovery.

**No deployment command is implemented or validated yet.** Manual evidence is required first.
