#!/usr/bin/env bash
# Safe read-only summary of one installed Windows libvirt domain.
# Prints no MAC, UUID, host account name, absolute disk/ISO path or TPM EK.
set -u
umask 077
REPORT=$(mktemp "${HOME:?}/SSL55_Step13A_Win11Definition_XXXXXXXX.txt") || exit 1
python3 - <<'PY' > "$REPORT" 2>&1
import os
import subprocess
import xml.etree.ElementTree as ET

URI = "qemu:///system"
VM = "win11"
def virsh(*args):
    return subprocess.run(["virsh", "-c", URI, *args], text=True, capture_output=True, timeout=15)

print("========== STEP 13A: READ-ONLY WINDOWS GUEST SUMMARY ==========")
print("No settings, accounts, disks, snapshots, services or networks changed.")
state = virsh("domstate", VM)
print("VM state:", state.stdout.strip() if state.returncode == 0 else ("ERROR: " + state.stderr.strip()[:180]))
result = virsh("dumpxml", "--inactive", VM)
if result.returncode:
    print("VM XML unavailable:", result.stderr.strip()[:180])
    raise SystemExit(1)
root = ET.fromstring(result.stdout)
def val(path, default="not specified"):
    x = root.find(path)
    return (x.text or "").strip() if x is not None and x.text else default

ostype = root.find("os/type")
print("OS architecture:", ostype.get("arch", "unknown") if ostype is not None else "unknown")
print("Machine type:", ostype.get("machine", "unknown") if ostype is not None else "unknown")
print("UEFI loader configured:", "YES" if root.find("os/loader") is not None else "NO/UNKNOWN")
print("vCPUs configured:", val("vcpu"))
memory = root.find("memory")
if memory is not None:
    amount = int(memory.text or "0")
    unit = memory.get("unit", "KiB")
    mul = {"KiB":1/1024,"MiB":1,"GiB":1024}.get(unit)
    print("Memory configured (MiB):", int(amount*mul) if mul is not None else f"{amount} {unit}")
devices = root.find("devices")
if devices is None:
    raise SystemExit("VM XML missing devices section")
print("----- STORAGE -----")
for disk in devices.findall("disk"):
    device = disk.get("device", "unknown")
    target = disk.find("target")
    source = disk.find("source")
    driver = disk.find("driver")
    source_kind = "present" if source is not None and source.attrib else "none"
    print("device=",device,
          "target=",target.get("dev","unknown") if target is not None else "?",
          "bus=",target.get("bus","unknown") if target is not None else "?",
          "driver=",driver.get("type","unknown") if driver is not None else "?",
          "source=",source_kind)
print("----- INTERFACES -----")
for iface in devices.findall("interface"):
    source = iface.find("source")
    model = iface.find("model")
    print("type=",iface.get("type","unknown"),
          "network=",source.get("network", "not-network-backed") if source is not None else "?",
          "model=",model.get("type","unknown") if model is not None else "?")
print("----- SECURITY AND ACCESS -----")
tpm = devices.find("tpm")
backend = tpm.find("backend") if tpm is not None else None
print("TPM:", "present" if tpm is not None else "absent",
      "model=",tpm.get("model", "unknown") if tpm is not None else "?",
      "backend=",backend.get("type", "unknown") if backend is not None else "?",
      "version=",backend.get("version", "unknown") if backend is not None else "?")
print("Guest agent channel:", "YES" if any(ch.find("target") is not None and
    "org.qemu.guest_agent.0" in str(ch.find("target").attrib)
    for ch in devices.findall("channel")) else "NO")
print("Graphics:", ", ".join(x.get("type", "unknown") for x in devices.findall("graphics")) or "none")
snap = virsh("snapshot-list", "--name", VM)
if snap.returncode:
    print("Snapshots: unable to list:", snap.stderr.strip()[:180])
else:
    print("Snapshots (libvirt-managed):", len([x for x in snap.stdout.splitlines() if x.strip()]))
print("========== COMPLETE ==========")
PY
RC=$?
echo "Private report: $REPORT"
echo "Exit status: $RC"
echo "Review for sensitive details and upload the TXT report."
exit "$RC"
