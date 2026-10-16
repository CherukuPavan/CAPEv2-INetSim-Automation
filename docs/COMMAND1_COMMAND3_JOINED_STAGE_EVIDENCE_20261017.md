# Executable Command 1/3 orchestration improvements (2026-10-17)

Only `development` changed. Never tested against SSL-55/SSL-46 or real
Windows guest storage in these tests.

## Command 1: real Python runtime phase between two existing phases

`scripts/command1_integrated_cold_sequence.py` now **executes** the
existing receipt-backed `command1_cape_runtime_rootless_stage.apply()`
if the operator supplies all eight required pinned runtime inputs:
approved 170-wheel manifest, strict wheel lock, root-immutable wheelhouse,
reviewed uv binary SHA256, and isolated Python 3.12 binary SHA256.
The effective sequence is:

1. Create host-bound transaction, install signed host prerequisites and
   check out exact approved upstream CAPE revision.
2. Execute unprivileged, strictly offline pinned CAPE Python runtime
   installation, requiring and sealing the same transaction ID. A
   new root-private integrated receipt records installed wheel count and
   owned venv path.
3. Only if step 2 returns a **verified sealed runtime receipt**, proceed
   to the already implemented authorized read-only encrypted master
   handoff and stage the master **shut off**.

The old two-phase cold path still exists when no runtime profile is
supplied. A partially specified runtime profile is refused before host
mutation. Root-only, existing non-login runtime user plus independently
approved root-protected wheel artifacts remain required. A synthetic
runtime installation failure leaves the source transaction and a partial
receipt, and **never invokes master import**.

There is still no full CAPE systemd/database install, authorized
distribution of the encrypted exact master, synchronized Windows TPM/UEFI
running snapshot replay acceptance, nor complete VM/network rollback.

## Command 3: one invocation, two existing guarded stages

`scripts/command3_from_operator_reference.py --mode run` joins the
already guarded `configure` and `restart` operations without bypassing
their independent typed approvals, route-safety checks or strict
systemd-active revalidation. The outer root-private receipt is recorded
before configurations change and tracks two stages:
`five_configuration_files` then `five_service_restarts`. Its
successful result includes separate config and service journal paths.

If configurations fail, service restarts are **not** invoked. If
service restart fails, the partial receipt preserves evidence that
configuration had completed and that the service state may be unknown;
there is no blind retry or stop. Both SSL-55 **and SSL-46** are protected
from this mutating path.

This is a real same-invocation Command 3 substage but cannot constitute
the promised fresh-host three-command acceptance until routing,
guest isolation, full Windows snapshot state and installed CAPE service
provenance are independently verified on a physical target.

## Evidence

GitHub Actions repository-wide offline regression runs on both
Python 3.10 and 3.12, including mocked success and failure boundaries.
Earlier separate Ubuntu 26.04 QEMU/libvirt, offline Python wheelhouse
and two-revert tests remain described in their original evidence
documents. None substitute for physical authorized Windows and
production firewall/TPM validation.

The repository retains strict `development`-only change scope.
