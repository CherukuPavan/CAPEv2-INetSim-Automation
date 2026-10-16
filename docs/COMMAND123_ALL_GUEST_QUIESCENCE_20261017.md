# Read-only full-libvirt quiescence for CAPE recovery

**Scope:** recovery checks only, on an approved non-reference host.
No malware execution, VM start/stop/undefine, network mutation or snapshot
revert is part of this change.

## Corrected 2026-10-17

Several existing rollback paths formerly relied on
`virsh list --state-running` or `virsh list --name`. Those commands
omit **paused** and **pmsuspended** domains, which may retain open disks,
guest RAM, interfaces, pending I/O, or TPM state and therefore cannot be
safely treated as stopped.

A shared read-only guard
[`scripts/command123_libvirt_quiescence.py`](
../scripts/command123_libvirt_quiescence.py)
now queries `virsh list --all --name`, verifies each `virsh domstate`
is exactly `shut off`, and re-queries the full inventory to reject
concurrent domain additions/removals. It fails closed on unexpected,
duplicate or excessive inventory, unavailable libvirt or unexpected state.

The guard is used by the main transaction repair/rollback and the
five-service restart reversal. Command 3 configuration recovery uses the
same strict transaction service-state inspection, preventing recovery
when `systemctl is-active` would otherwise ambiguously report exit 3.
The isolated-network rollback and zero-NIC clone rollback also verify
every defined domain's shutoff state and recheck domain membership.

## Tested safety cases

Offline Python 3.10 and 3.12 regression tests explicitly verify
that paused, pmsuspended, running, crashed, unknown and concurrently
changing domains block the relevant recovery paths, including unrelated
foreign VMs. Failed CAPE/Suricata systemd units also block config
recovery. The source-level contract test rejects new running-only
libvirt state filters in these five core recovery paths.

The checks deliberately **do not** assert a transaction-level libvirt
lifecycle lock. The two inventory readings reduce exposure to obvious
races but cannot prevent another privileged process from starting a VM
immediately afterward. Physical acceptance requires externally
coordinated lifecycle ownership and protected resource journals.

This change is not proof of the finished portable three-command
installation, Windows TPM state restoration or full package/network/
VM/swtpm rollback.
