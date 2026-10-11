# Command 2 — portable VM identity blueprint (development only)

**No VM is created; no NIC, Windows hostname, static IP or UEFI/TPM
state is changed. SSL-55 remains a protected reference host.**

## Implementation

- `scripts/command2_guest_identity_blueprint.py` accepts a **validated
  read-only preflight result** for a separate target machine and an
  inventory of existing UUIDs/MAC addresses. It produces candidate
  values for the requested TOTAL count of resource/subnet-bounded Windows VMs (model safety cap: 4096).
- For each `win11_1..win11_N`, a locally-administered, unicast
  randomly generated MAC is proposed together with fresh candidate
  libvirt UUID and SMBIOS generation ID values. It excludes supplied
  known UUIDs/MACs and retries collisions with a bounded fail-closed
  budget. Candidates are unique within the same generated plan.
- It validates that the name `win11_i`, hostname `WIN11-i`, isolated
  guest IPv4 `(network base + 100 + i)`, disk path and UEFI NVRAM path
  match the exact 1..N plan and selected CIDR. The selected analysis
  subnet must match the target host's preflight output.
- These identities are **ephemeral proposals**, not persistent
  reservations. Generating another plan returns new candidates.
  An apply-stage implementation must acquire an exclusive lock,
  durably record/verify reservations, re-read libvirt inventories,
  check canonical disk/NVRAM paths and MAC/UUID collisions, and
  handle interruption/resume without accidentally overwriting VM data.

## Strict non-claims

- Windows hostnames are not changed by the blueprint.
- Static IPs are not assigned, and no host or guest NIC is attached.
- Isolation, runtime IPv4/IPv6 egress, CAPE agent communication and
  full disk/UEFI/swtpm checkpoint/restore remain unverified.
- No physical multi-VM test is performed on SSL-55 (which has only
  roughly 96 GiB available). Future physical acceptance requires
  a different supported, adequately provisioned machine.
- Preflight is still a metadata-only assessment, not a certificate
  that the Windows source template is safe or unencrypted.
- Candidate Ubuntu support, 4 GiB/VM planning assumption and model-safety cap 4096 and subnet limits are preliminary and must be validated on actual hosts.

## Offline regression tests

`scripts/test_command2_guest_identity_blueprint.py` covers:
multi-guest uniqueness and naming, MAC locally-administered/unicast
bits, collisions with occupied UUIDs/MACs, malformed inventory,
entropy-provider errors, exhausted retry budget, malformed subnet
or guest IP, SSL-55 refusal and strict no-deployment output.
Development CI is configured to run Python 3.10 and 3.12.
Until an actual CI or local run log is available, do **not**
assert that these new tests have passed.

**Next:** implement a separate checked and reversible reservation
stage with crash-consistent journaling, then complete the portable
no-NIC cloning engine and Windows personalization, subject to
subsequent isolation and checkpoint acceptance on another host.
