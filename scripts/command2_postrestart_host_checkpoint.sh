#!/usr/bin/env bash
# SSL-55 Command 2A: post-Windows-restart host checkpoint for exact win11_1.
# READ ONLY (except one root-private user's own TXT report).
# Does NOT start/stop guests, attach interfaces, change firewalls,
# alter libvirt definitions, create snapshots, or access live QCOW2 contents.
set -Eeuo pipefail
umask 077
UUID='732b2256-ee99-41fa-881d-fbf5c476d960'
MASTER_UUID='289d89be-68ec-4c62-90e1-ea930849266f'
TRIAL_UUID='e75f6fef-347d-462f-9738-4de3df6bfa74'
DISK='/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2'
NVRAM='/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd'
NET='cape-analysis-isolated'
[[ -t 0 ]] || { echo 'BLOCKED: interactive SSL-55 terminal required' >&2; exit 2; }
command -v virsh >/dev/null || { echo 'BLOCKED: virsh missing' >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "${HOME}/CAPE_Command2A_PostRestartHost_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
exec 3>&1
printf 'Private report: %s\n' "$REPORT" >&3
exec >"$REPORT" 2>&1
trap 'rc=$?; printf "\nREPORT: %s (exit %s)\n" "$REPORT" "$rc" >&3; tail -n 45 "$REPORT" >&3; exit "$rc"' EXIT
block(){ printf 'BLOCKED: %s\n' "$*" >&2; exit 2; }
v(){ sudo -n virsh -c qemu:///system "$@"; }

echo 'COMMAND2A POSTRESTART SSL55 READ-ONLY HOST CHECKPOINT'
date -Is
printf 'Expected clone UUID: %s\n' "$UUID"
[[ "$(v domuuid win11_1)" == "$UUID" ]] || block 'Wrong new clone UUID'
[[ "$(v domstate win11_1)" == 'running' ]] || block 'win11_1 is no longer running'
[[ "$(v domuuid win11)" == "$MASTER_UUID" ]] || block 'Original Windows master UUID changed'
[[ "$(v domstate win11)" == 'shut off' ]] || block 'Original Windows master is not shut off'
[[ "$(v domuuid win11_trial_1)" == "$TRIAL_UUID" ]] || block 'Trial VM identity changed'
[[ "$(v domstate win11_trial_1)" == 'running' ]] || block 'Trial VM state changed'

echo 'IDENTITY/STATES: PASS'
for mode in live inactive; do
  if [[ "$mode" == 'live' ]]; then xml="$(v dumpxml win11_1)"; else xml="$(v dumpxml --inactive win11_1)"; fi
  printf '%s' "$xml" | /usr/bin/python3 -c '
import sys,xml.etree.ElementTree as ET
r=ET.fromstring(sys.stdin.read())
need=lambda ok,msg: ok or sys.exit("BLOCKED: "+msg)
need(r.findtext("name")=="win11_1","unexpected name")
need(r.findtext("uuid")=="732b2256-ee99-41fa-881d-fbf5c476d960","unexpected UUID")
disks=r.findall("./devices/disk[@device=\"disk\"]")
need(len(disks)==1 and disks[0].find("source") is not None and
     disks[0].find("source").get("file")=="/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2","wrong clone disk")
need(r.findtext("./os/nvram")=="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd","unexpected clone NVRAM")
tpm=r.findall("./devices/tpm")
need(len(tpm)==1 and tpm[0].find("backend") is not None and
     tpm[0].find("backend").get("type")=="emulator","unexpected TPM backend")
for tag in ("interface","hostdev","filesystem","channel","redirdev","smartcard","shmem","vsock"):
    need(not r.findall("./devices/"+tag),"forbidden device: "+tag)
print("EXACT_CLONE_XML_PASS: name UUID independent disk NVRAM TPM zero NIC/passthrough")
' || block "Unexpected $mode guest device/identity configuration"
  echo "$mode XML: PASS"
done

echo '--- Original master/trial NIC checks ---'
for name in win11_trial_1; do
  v domiflist "$name"
done
echo '--- Clone NIC inventory ---'
v domiflist win11_1
echo '--- Clone block device summary (read only) ---'
v domblklist win11_1 --details
echo '--- Clone libvirt snapshot metadata (read only) ---'
v snapshot-list win11_1
echo '--- Analysis network (must be inactive and nonautostart) ---'
info="$(v net-info "$NET")"
printf '%s\n' "$info"
printf '%s\n' "$info" | grep -Eq '^Active:[[:space:]]+no[[:space:]]*$' || block 'Analysis network active'
printf '%s\n' "$info" | grep -Eq '^Autostart:[[:space:]]+no[[:space:]]*$' || block 'Analysis network autostart enabled'
echo '--- CAPE-only nftables guard presence (NOT runtime containment proof) ---'
sudo -n nft list table inet cape_analysis_guard >/dev/null || block 'Guard table missing'
echo 'GUARD_TABLE_PRESENT: true (reboot persistence / runtime egress NOT proven)'
echo '--- Artifact metadata only; no live QCOW2 content reads ---'
sudo -n stat -c '%n size=%s bytes owner=%U:%G mode=%a' "$DISK" "$NVRAM" || block 'Clone artifact missing'
echo '--- Available resources ---'
df -h /var/lib/libvirt/images
free -h
echo 'RESULT: COMMAND2A_POSTRESTART_HOST_READONLY_PASS'
echo 'PENDING: Snapshots incl. NVRAM/swtpm, static IPv4, firewall persistence, safe NIC, IPv4/IPv6 egress and parallel guests'
