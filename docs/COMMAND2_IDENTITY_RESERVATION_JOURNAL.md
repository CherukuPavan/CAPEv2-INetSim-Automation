# Command 2 — locked identity reservation component (development)

**Component only. NOT a deployer or guest-creation command.**
**Never execute writes on SSL-55, including reservations.** The
reference machine remains protected.

`scripts/command2_identity_reservation_journal.py` implements
`reserve(blueprint, directory, expected_host=...)` as a controlled
storage primitive for a future **separate approved target host**.

Design:
- Reject SSL-55 before any filesystem access or creation.
- Require exact approved target hostname, existing private mode-0700
  destination directory and owner matching current user.
- Require entirely unapplied candidate IDs with unique canonical
  UUIDs, locally administered unicast MACs, IPv4 addresses, Windows
  hostname targets and independent disk/NVRAM paths.
- Serialize a minimal, non-secret manifest (does not contain passwords
  or Windows/TPM state).
- Acquire `flock` on a nofollow user-owned mode-0600 lock file.
- Create a random exclusively named private pending file and fsync.
  Publish by exclusive hardlink, fsync directory, unlink pending,
  fsync again. Never replace an existing manifest.
- Exact replay of the same source identities is idempotent. A changed
  blueprint is a conflict, not an invitation to regenerate or overwrite.
- An orphan pending file stops the operation for manual review;
  the component does not silently clean crash evidence or roll back.
- No shell, libvirt, cloning, guest actions, NIC attachment, firewall
  changes or automatic restore calls.

IMPORTANT limits:
- This records proposed IDs. It does **not** authenticate the
  external libvirt UUID/MAC inventory, reserve names globally, attest
  host resource adequacy, or authorize any VM definition.
- Hostname is only a defense-in-depth check, **not** strong host
  authentication; a future deployment entrypoint must separately
  enforce operator approval, verified non-SSL-55 host identity,
  storage ownership and authoritative concurrent libvirt inventory.
- The journal must be joined with validated host-side discovery,
  persisted transaction state, no-NIC libvirt XML and safe failure
  recovery before it becomes a real provisioning stage.
- If a crash happened after hardlink publication but before pending
  deletion, the pending marker causes a manual-review refusal even
  if the canonical manifest is intact. Never destroy partial artifacts
  to make the test appear green.
- Future operators must choose a dedicated pre-existing private
  reservation directory on a separately approved machine.

Tests: `scripts/test_command2_identity_reservation_journal.py`
covers new publication, exact replay, conflicts, dangling pending,
symlinked paths, insecure permissions, malformed blueprint and
reference-host refusal. GitHub Actions Python 3.10/3.12 acceptance
is required for every change. Offline success is not evidence of
actual target-host provisioning.
