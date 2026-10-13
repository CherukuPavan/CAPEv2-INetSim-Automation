# Deployment-scoped repair and rollback contract — mandatory release behavior

## Operator clarification, 2026-10-13

The operator does **NOT** ask for reinstalling Ubuntu, formatting the OS
drive, restoring a whole-system image, or resetting unrelated applications.
They require a **deployment-specific rollback**:

**Undo precisely what the CAPEv2 three-command deployment installed,
created or changed, returning the machine to its *before-deployment*
condition as far as CAPE deployment effects are concerned. Keep everything
that existed beforehand.** If deployment fails at Command 1, 2 or 3, the
rollback must also handle its recorded *partial* completed stages.

A separate **repair** operation should discover missing or damaged
deployment components, safely restore only resources with proven ownership,
and recheck their health. Repair must never destructively reset a user's
unrelated environment just to satisfy a check.

INetSim is deferred by operator request and must not silently be installed
or removed as part of this release profile.

## Required transaction ownership (no inferred deletion)

Every mutating subcommand MUST first register its planned change under an
exclusive, root-private, per-deployment transaction ID, including the exact
new-host hostname and initially observed resources. Before changing each
resource, capture its pre-state and a durable before-hash/receipt. After a
successful mutation, record an atomically durable completed-state proof;
partial/interrupted operations retain uncertainty rather than deleting.

- **Packages:** record which packages and versions were present before
  deployment and which exact packages the deployment installed. Only consider
  removing a newly installed, exclusively owned package if neither a user nor
  another package/service now requires it. Never auto-autoremove/upgrade or
  purge pre-existing packages. APT may install transitive dependencies; these
  need separate exact attribution. If attribution is uncertain, STOP.
- **CAPE code/apps and owned files:** only remove files created under a
  specific approved deployment root if the same paths were absent at baseline
  and their content/identity has not changed unexpectedly. Restore before
  versions of modified files byte-for-byte, including mode/uid/gid. Leave
  user changes untouched.
- **libvirt domains, disks and snapshots:** bind each created clone/master
  to recorded VM **name, UUID, disks, NVRAM/TPM sidecar**, paths and hashes.
  Require it to be shut off and separately validate all references; only
  remove an exclusively created, unchanged VM. VMs/disks/snapshots existing
  before deployment must never be removed. TPM or disk drift demands manual
  review; do not destroy data silently.
- **Network:** record exact dedicated created network/table/firewall
  identities, their baseline nonexistence, their deployment receipts, and
  final match. Only remove a verified exclusively owned isolated network or
  nftables table after there are no attached/running guests or foreign
  references. Restore only our own config edits and preserve existing host
  interfaces, routes, libvirt `default` NAT, and external connectivity.
- **System services and accounts:** capture existing unit files, enabled and
  running states and ownership before deployment. Stop/disable/remove only
  newly installed units, with exact after-state checks. Restore preexisting
  service settings and user/group configurations; never blanket-mask or
  delete an existing account because its name resembles CAPE.
- **Downloaded golden master and credentials:** the operator's encrypted
  Drive source and SSL55/SSL46 originals are NEVER rollback targets.
  A newly downloaded local golden bundle, root-only reader key/config and
  imported image may be quarantined ONLY if transaction-owned, unchanged,
  not referenced, separately authorized and not needed for recovery.
  The original cloud copy and crypt credentials in the operator's custody
  must remain available.

A missing journal, mismatched receipt, unknown in-flight operation,
new foreign reference, running guest, untracked user modification or missing
pre-image must cause **STOP with a clear partial-state report**. A wrong
precondition must never result in a best-effort delete.

## Interface expected from the eventual deployment release

The finalized tool may expose one `--mode plan-repair`, `repair`,
`plan-rollback`, `rollback` interface across all three commands;
the operator will provide the **deployment transaction ID**. Plans default
to READ-ONLY; mutation requires direct root interactive consent and exact
object/host verification. Rollback executes in dependency-safe reverse
deployment order and writes a durable step-by-step receipt so interrupted
execution is diagnosable, without blind replay.

Desired postconditions:
- CAPE-created guests, files, isolated networks, service units and owned
  package additions from THAT deployment are absent or restored;
- any preexisting files and service states touched by the deployment
  match their original pre-deployment state, or are explicitly flagged
  unresolved;
- unrelated libvirt/host resources and personal files are unchanged;
- the operator gets a single redacted JSON/TXT report of completed, skipped,
  manually blocked and unverified resources;
- a failure or uncertain state is **not** reported as a successful rollback.

## CURRENT IMPLEMENTATION — NOT YET THE CONTRACT ABOVE

At present, `scripts/command123_repair_rollback.py` is a guarded reversible
**six CAPE-configuration-files-only** tool. It can capture a root-private
before-state, seal after-state, create missing sealed config files and undo
those six changes under strict conditions. It does **not** implement the
whole-deployment transaction ledger or remove cloned guests, VM disks, TPM
sidecars, dedicated networks, nftables rules, systemd units or APT packages.

`scripts/command123_repair_doctor.py` observes host prerequisites and
runtime metadata but does not autonomously remediate package/VM/service/
network failures.

The current Command1 host-installer, Command2 multi-VM and Command3 routing
integration also lack end-to-end real-target release qualification; the
three-command deploy and corresponding comprehensive undo cannot be called
ready for a production environment yet. A full-system image remains an
*optional defense-in-depth safety backup*, NOT the user's requested
rollback feature and NOT a substitute for implementing this contract.

**Before tomorrow's test:** collect the initial read-only host inventory and
capture the six-config baseline; execute only controlled, reversible test
stages, and do not treat existing limited `rollback` as full deployment undo.
Never execute destructive resource removal simply because a resource was
absent from a preflight report; true ownership requires authenticated
step-level creation receipts, not mere before/after difference.
