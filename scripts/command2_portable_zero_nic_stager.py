#!/usr/bin/env python3
"""Portable Command 2: guarded, one-way zero-NIC clone staging on OTHER hosts.

This component can write large QCOW2 files and define libvirt guests in
--mode stage. It NEVER runs on SSL-55, starts a guest, attaches a NIC,
changes host networks, mutates the master, or runs malware.

NOT a finished Command 2: Windows hostname/IP personalization, proven lab
isolation, TPM/UEFI restore and full multi-guest CAPE acceptance still needed.
Partial artifacts and intents are intentionally NOT auto-deleted/retried.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_identity_reservation_journal as reservation
import command2_portable_zero_nic_xml as renderer
import probe_cold_windows_volume_crypto as crypto
import command2_target_host_preflight as hostaudit

GIB = 1024 ** 3
VIRTUAL_BYTES = 64 * GIB
RESERVE_BYTES = 40 * GIB  # 30 GiB reserve plus 10 GiB shared-host margin
SSL55_PRESERVATION_SENTINEL = Path(
    "/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK_NAME = ".command2-stager.lock"
INTENT_PREFIX = "command2-stage-intent-"
COMPLETE_PREFIX = "command2-stage-complete-"
MAX_FILE_BYTES = 4 * 1024 * 1024


class StageBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise StageBlocked(why)


def run(*argv, timeout=120):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StageBlocked("Host command unavailable or timed out: " + argv[0]) from exc
    need(proc.returncode == 0, "Host command failed: " + argv[0] +
         " (exit " + str(proc.returncode) + ")")
    return proc.stdout.strip()


def virsh(*argv):
    return run("virsh", "-c", "qemu:///system", *argv)


def host_guard(approved_host, *, for_stage):
    real = socket.gethostname().split(".", 1)[0].lower()
    need(real not in ("cse-ssl-55", "ssl-55",
                      "cse-ssl-46", "ssl-46"),
         "SSL55_REFERENCE_ONLY: staging prohibited; SSL46 backup also protected")
    # Defense-in-depth if SSL-55 was renamed; never mutate any host that
    # still carries its canonical protected Windows preservation backup.
    need(not SSL55_PRESERVATION_SENTINEL.exists() and
         not SSL55_PRESERVATION_SENTINEL.is_symlink(),
         "SSL55_REFERENCE_ONLY: preservation sentinel present")
    need(isinstance(approved_host, str) and re.fullmatch(r"[a-z0-9_.-]{1,64}", approved_host),
         "Explicit safe target hostname required")
    need(real == approved_host, "Approval host differs from actual host")
    if for_stage:
        need(os.geteuid() == 0, "Production staging requires root")


def exact_file(path, *, root=True, max_bytes=None):
    p = Path(path)
    need(p.is_absolute() and not p.is_symlink() and p.is_file(),
         "Missing/nonregular source or symlink: " + p.name)
    s = p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
         (not root or (s.st_uid == 0 and s.st_mode & 0o077 == 0)),
         "Unsafe source file mode/owner/link: " + p.name)
    if max_bytes is not None:
        need(s.st_size <= max_bytes, "File unexpectedly large: " + p.name)
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def exact_dir(path, *, root=True, mode=None):
    p = Path(path)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Expected existing safe directory: " + str(p))
    st = p.stat()
    need((not root or st.st_uid == 0) and not st.st_mode & 0o022,
         "Directory not protected: " + str(p))
    if mode is not None:
        need(stat.S_IMODE(st.st_mode) == mode, "Unexpected directory mode")
    for part in (p, *p.parents):
        need(not part.is_symlink(), "Directory ancestor is a symlink")
    return p


def digest_file(path):
    result = hashlib.sha256()
    with open(path, "rb") as inp:
        for chunk in iter(lambda: inp.read(4 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def free_bytes(path):
    fs = os.statvfs(path)
    return fs.f_bavail * fs.f_frsize


def reservation_entries(root, approved_host):
    directory = exact_dir(root, mode=0o700)
    identity = directory / reservation.RECORD_NAME
    exact_file(identity, max_bytes=MAX_FILE_BYTES)
    data = json.loads(identity.read_text(encoding="utf-8"))
    need(data.get("format") == "CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION"
         and data.get("version") == 1 and data.get("host") == approved_host
         and data.get("state") == "CANDIDATES_RECORDED_NOT_APPLIED"
         and data.get("provisioning_started") is False
         and data.get("libvirt_domains_created") is False
         and data.get("host_network_modified") is False,
         "Untrusted candidate reservation journal")
    entries = data.get("entries")
    need(type(entries) is list and type(data.get("guest_count")) is int
         and 1 <= len(entries) <= 16 and len(entries) == data["guest_count"],
         "Reservation count malformed")
    ids, macs, ips, paths = set(), set(), set(), set()
    for index, row in enumerate(entries, 1):
        need(type(row) is dict and set(row) == set(reservation.KEYS) and
             row["libvirt_name"] == f"win11_{index}" and
             row["windows_hostname_target"] == f"WIN11-{index}",
             "Malformed ordered reservation entry")
        for key in ("libvirt_uuid_candidate", "smbios_generation_id_candidate"):
            import uuid
            try:
                identifier = str(uuid.UUID(row[key]))
            except (TypeError, ValueError, KeyError) as exc:
                raise StageBlocked("Invalid UUID in reservation") from exc
            need(row[key] == identifier and identifier not in ids,
                 "Duplicate/noncanonical reserved guest UUID")
            ids.add(identifier)
        need(re.fullmatch(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}", row["mac_candidate"]) is not None
             and row["mac_candidate"] not in macs, "Duplicate/unsafe reserved MAC")
        macs.add(row["mac_candidate"])
        import ipaddress
        try:
            ip = str(ipaddress.IPv4Address(row["guest_static_ipv4_target"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise StageBlocked("Invalid reserved guest IPv4") from exc
        need(ip == row["guest_static_ipv4_target"] and ip not in ips,
             "Duplicate or malformed reserved IP")
        ips.add(ip)
        for pathkey in ("disk_target", "uefi_nvram_target"):
            value = row[pathkey]
            need(type(value) is str and value.startswith("/") and "\x00" not in value
                 and ".." not in Path(value).parts and value not in paths,
                 "Reservation artifact path unsafe or duplicated")
            paths.add(value)
    return entries


def assert_no_collision(entries):
    domains = set(virsh("list", "--all", "--name").splitlines())
    reserved = set()
    for row in entries:
        reserved.add(row["libvirt_uuid_candidate"])
        reserved.add(row["smbios_generation_id_candidate"])
        need(row["libvirt_name"] not in domains,
             "Target VM name already defined: " + row["libvirt_name"])
        for filename in (row["disk_target"], row["uefi_nvram_target"]):
            f = Path(filename)
            need(not f.exists() and not f.is_symlink(),
                 "Target disk/UEFI artifact already exists")
    for existing in domains:
        if not existing:
            continue
        existing_uuid = virsh("domuuid", existing)
        need(existing_uuid not in reserved,
             "Reserved UUID conflicts with existing libvirt domain")
        # XML read-only to check source disk and UEFI reuse; refuse the
        # same target path even if a future path is not yet present.
        root = ET.fromstring(virsh("dumpxml", "--inactive", existing))
        occupied = {s.get("file") for s in root.findall("./devices/disk/source")}
        occupied.add(root.findtext("./os/nvram"))
        need(not occupied.intersection({x for row in entries for x in
             (row["disk_target"], row["uefi_nvram_target"])}),
             "Another domain points to planned disk or NVRAM")
        for nic in root.findall("./devices/interface/mac"):
            mac = nic.get("address", "").lower()
            need(all(mac != row["mac_candidate"] for row in entries),
                 "Reserved MAC conflicts with existing VM")


def assert_cold_source_unshared(template, master_nvram):
    """Refuse cloning a template/UEFI source referenced by another guest."""
    expected = {os.path.realpath(str(template)), os.path.realpath(str(master_nvram))}
    other_names = set(virsh("list", "--all", "--name").splitlines()) - {"win11", ""}
    for other in sorted(other_names):
        views = [virsh("dumpxml", "--inactive", other)]
        if virsh("domstate", other).strip() == "running":
            views.append(virsh("dumpxml", other))
        for xml_text in views:
            root = ET.fromstring(xml_text)
            for disk in root.findall("./devices/disk/source"):
                path = disk.get("file")
                if path and os.path.realpath(path) in expected:
                    raise StageBlocked("Clone source storage is assigned to another libvirt guest")
            firmware = root.findtext("./os/nvram")
            if firmware and os.path.realpath(firmware) in expected:
                raise StageBlocked("Source UEFI variables are shared with another guest")


def validate_inputs(entries, master_uuid, source_template, master_nvram,
                    master_xml, template_sha256, audit_source):
    need(virsh("domuuid", "win11").lower() == master_uuid.lower() and
         virsh("domstate", "win11").strip() == "shut off",
         "Protected master changed or is active")
    source = Path(source_template)
    orig_vars = Path(master_nvram)
    diskstamp = exact_file(source)
    vars_stamp = exact_file(orig_vars)
    assert_cold_source_unshared(source, orig_vars)
    need(diskstamp[2] > 0 and vars_stamp[2] in
         (540672, 131072, 262144, 1048576),
         "Unexpected OS template / firmware size")
    meta = json.loads(run("qemu-img", "info", "--output=json", str(source)))
    need(meta.get("format") == "qcow2" and
         meta.get("virtual-size") == VIRTUAL_BYTES and
         not meta.get("backing-filename") and
         not meta.get("full-backing-filename"),
         "Clone source must be independent flat 64GiB QCOW2")
    need(re.fullmatch(r"[0-9a-f]{64}", template_sha256) is not None,
         "Explicit SHA-256 of reviewed source template required")
    if audit_source:
        need(digest_file(source) == template_sha256,
             "Windows template SHA-256 mismatch; do not stage")
        try:
            crypto.require_cleartext_candidate(source)
        except crypto.VolumeProbeError as exc:
            raise StageBlocked("Template plaintext Windows volume not verified") from exc
    root = ET.fromstring(master_xml)
    expected_master_disk = root.find("./devices/disk[@device='disk']/source")
    need(expected_master_disk is not None and expected_master_disk.get("file"),
         "Protected master missing exact OS disk path")
    master_disk = expected_master_disk.get("file")
    # A source template MUST be independent of the protected master.
    # Refuse both an identical path and an underlying hardlink alias.
    need(str(source) != master_disk and str(source) != str(orig_vars),
         "Clone template aliases protected master storage")
    if Path(master_disk).exists():
        need(not os.path.samefile(source, master_disk),
             "Standalone template is the master's disk")
    for row in entries:
        expected_disk = Path(row["disk_target"])
        expected_vars = Path(row["uefi_nvram_target"])
        exact_dir(expected_disk.parent)
        exact_dir(expected_vars.parent)
        need(source != expected_disk and orig_vars != expected_vars and
             expected_disk != Path(master_disk) and
             expected_vars != Path(master_nvram), "Clone path aliases a master artifact")
        candidate = dict(row,
                         nic_attached=False,
                         static_ipv4_applied=False,
                         per_vm_tpm_state_must_be_fresh=True)
        renderer.render_no_nic(
            master_xml, candidate, expected_master_disk=master_disk,
            expected_master_nvram=master_nvram)
    return diskstamp, vars_stamp, master_disk


def target_host_preflight(entries, template, subnet):
    """Require actual fresh-host inventory, not a fabricated planning profile."""
    import ipaddress
    need(len(entries) > 0, "No reserved Windows guests")
    first = entries[0]
    disk_base = str(Path(first["disk_target"]).parent)
    nvram_base = str(Path(first["uefi_nvram_target"]).parent)
    need(all(Path(row["disk_target"]).parent == Path(disk_base) and
             Path(row["uefi_nvram_target"]).parent == Path(nvram_base)
             for row in entries), "Clone artifacts span unapproved directories")
    facts = hostaudit.collect(disk_base, nvram_base, str(template), len(entries))
    report = hostaudit.evaluate(facts, len(entries), disk_base, nvram_base, subnet)
    need(report.get("preflight_pass") is True,
         "Real target-host preflight blocked: " +
         ",".join(report.get("errors") or ["unknown"]))
    expected_rows = report["planned_vms"]
    need(len(expected_rows) == len(entries), "Preflight count changed")
    for candidate, inspected in zip(entries, expected_rows):
        need(candidate["libvirt_name"] == inspected["libvirt_name"] and
             candidate["windows_hostname_target"] == inspected["hostname"] and
             candidate["guest_static_ipv4_target"] == inspected["planned_ipv4"] and
             candidate["disk_target"] == inspected["disk"] and
             candidate["uefi_nvram_target"] == inspected["nvram"],
             "Reserved VM identity differs from independently checked host plan")
    return {"preflight_pass":True,
            "ipv4_overlap_checked":report["ipv4_overlap_checked"],
            "verified_storage_free_gib":report["storage_reported_free_gib"],
            "deployment_authorized":False,
            "network_isolation_verified":False}


def atomic_note(root, name, data):
    content = (json.dumps(data, sort_keys=True, separators=(",", ":"))+"\n").encode("utf-8")
    need(len(content) < MAX_FILE_BYTES, "Journal note too large")
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    dfd = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dfd)
    finally: os.close(dfd)


def validate_after_definition(row):
    name = row["libvirt_name"]
    need(virsh("domstate", name).strip() == "shut off",
         "Staged VM unexpectedly booted")
    xml = ET.fromstring(virsh("dumpxml", "--inactive", name))
    sources = xml.findall("./devices/disk[@device='disk']/source")
    backend = xml.find("./devices/tpm/backend")
    need(xml.findtext("name") == name and
         xml.findtext("uuid") == row["libvirt_uuid_candidate"] and
         xml.findtext("genid") == row["smbios_generation_id_candidate"] and
         len(sources) == 1 and sources[0].get("file") == row["disk_target"] and
         xml.findtext("./os/nvram") == row["uefi_nvram_target"] and
         backend is not None and backend.get("type") == "emulator" and
         backend.get("version") == "2.0" and
         not xml.findall("./devices/interface") and
         not xml.findall("./devices/hostdev") and
         not xml.findall("./devices/filesystem"),
         "Staged VM identity, storage, TPM or zero-NIC invariant differs")


def make_one(row, *, master_xml, master_disk, master_nvram,
             template, source_stamp, vars_stamp, logdir):
    need(virsh("domstate", "win11").strip() == "shut off",
         "Original Windows master started before clone")
    assert_cold_source_unshared(template,master_nvram)
    need(exact_file(template) == source_stamp and
         exact_file(master_nvram) == vars_stamp,
         "Original template or NVRAM changed before clone")
    name = row["libvirt_name"]
    disk = Path(row["disk_target"])
    nvram = Path(row["uefi_nvram_target"])
    need(free_bytes(str(disk.parent)) >= VIRTUAL_BYTES+RESERVE_BYTES,
         "Insufficient conservative capacity for next clone")
    xml = renderer.render_no_nic(
        master_xml,
        dict(row,nic_attached=False,static_ipv4_applied=False,
             per_vm_tpm_state_must_be_fresh=True),
        expected_master_disk=master_disk, expected_master_nvram=str(master_nvram))
    # An exclusively written, fsynced intent permanently blocks blind retry.
    atomic_note(logdir, INTENT_PREFIX+name+".json",
                {"name":name, "stage":"BEFORE_ANY_CLONE_FILES",
                 "disk":str(disk),"nvram":str(nvram),
                 "uuid":row["libvirt_uuid_candidate"],"zero_nics":True})
    temp_file = None
    try:
        fd, temp_file = tempfile.mkstemp(prefix=".command2-incomplete-"+name+"-",
                                        suffix=".qcow2",dir=str(disk.parent))
        os.close(fd)
        os.unlink(temp_file)
        run("qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-o", "compat=1.1",
            str(template), temp_file, timeout=7200)
        os.chmod(temp_file,0o600)
        run("qemu-img","check","-q","-f","qcow2",temp_file,timeout=3600)
        info=json.loads(run("qemu-img","info","--output=json",temp_file))
        need(info.get("format") == "qcow2" and
             info.get("virtual-size") == VIRTUAL_BYTES and
             not info.get("backing-filename") and
             not info.get("full-backing-filename"),
             "Copied QCOW2 has invalid format, size or backing chain")
        try:
            crypto.require_cleartext_candidate(Path(temp_file))
        except crypto.VolumeProbeError as exc:
            raise StageBlocked("Clone Windows plaintext validation failed") from exc
        need(exact_file(template) == source_stamp and
             exact_file(master_nvram) == vars_stamp and
             virsh("domstate", "win11").strip() == "shut off",
             "Protected Windows source changed during staging")
        need(free_bytes(str(disk.parent)) >= RESERVE_BYTES,
             "Storage safety reserve crossed during clone")
        need(not disk.exists() and not disk.is_symlink() and
             not nvram.exists() and not nvram.is_symlink(),
             "Clone destination collision after copy")
        # Distinct UEFI vars; never copy the master TPM state.
        source_st = Path(master_nvram).stat()
        fd=os.open(nvram, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as target, open(master_nvram,"rb") as src:
            os.fchown(target.fileno(), source_st.st_uid, source_st.st_gid)
            shutil.copyfileobj(src,target)
            target.flush()
            os.fsync(target.fileno())
        need(digest_file(nvram) == digest_file(master_nvram),
             "Independent guest UEFI firmware copy mismatch")
        need(exact_file(master_nvram) == vars_stamp,
             "Master UEFI variables changed during copy")
        os.link(temp_file,disk)
        os.unlink(temp_file)
        temp_file=None
        # Sync both independent artifact directories BEFORE libvirt define.
        for parent in {disk.parent, nvram.parent}:
            dfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        with tempfile.TemporaryDirectory(prefix="command2-define-",dir="/run") as folder:
            path=Path(folder)/"vm.xml"
            path.write_text(xml,encoding="utf-8")
            path.chmod(0o600)
            virsh("define",str(path),"--validate")
        validate_after_definition(row)
        need(virsh("dumpxml","--inactive","win11")==master_xml,
             "Original master XML changed during clone staging")
        need(exact_file(template) == source_stamp and
             exact_file(master_nvram) == vars_stamp and
             virsh("domstate","win11").strip() == "shut off",
             "Master source changed following staging")
        atomic_note(logdir, COMPLETE_PREFIX+name+".json",
                    {"name":name,"status":"SHUT_OFF_ZERO_NICS_STAGED",
                     "uuid":row["libvirt_uuid_candidate"],
                     "tpm_persistent_state_created":False,
                     "guest_personalized":False,"network_attached":False,
                     "clean_restore_verified":False})
        return {"name":name,"status":"SHUT_OFF_ZERO_NICS_STAGED",
                "uuid":row["libvirt_uuid_candidate"],"nic_count":0,
                "windows_personalized":False,"network_attached":False}
    except Exception as exc:
        # Never auto-unlink incomplete files, UEFI/NVRAM, or new domains.
        raise StageBlocked(name + ": incomplete stage, preserve disk/NVRAM/XML "
             "and journal for manual review; reason: " + str(exc)) from exc
    finally:
        if temp_file and Path(temp_file).exists():
            print("INCOMPLETE_QCOW2_RETAINED: "+Path(temp_file).name, file=sys.stderr)


def execute(*, mode, approved_host, journal_dir, template, template_sha256,
            master_nvram, master_uuid, subnet="192.168.240.0/24"):
    need(mode in ("plan","stage"), "Unknown stage mode")
    host_guard(approved_host, for_stage=mode=="stage")
    logdir=exact_dir(journal_dir, root=mode=="stage", mode=0o700)
    entries=reservation_entries(logdir, approved_host)
    host_summary=target_host_preflight(entries, template, subnet)
    source=Path(template)
    master_xml=virsh("dumpxml","--inactive","win11")
    # No action ever occurs when the master is running or identity differs.
    _, _, master_disk = validate_inputs(
        entries, master_uuid, source, master_nvram,
        master_xml, template_sha256, audit_source=mode=="stage")
    assert_no_collision(entries)
    need(not any((logdir/(INTENT_PREFIX+row["libvirt_name"]+".json")).exists()
                 for row in entries), "Previous staging intent: no blind retry")
    need(not any((logdir/(COMPLETE_PREFIX+row["libvirt_name"]+".json")).exists()
                 for row in entries), "Existing completed stage marker")
    require_bytes=len(entries)*VIRTUAL_BYTES + RESERVE_BYTES
    need(free_bytes(str(Path(entries[0]["disk_target"]).parent)) >= require_bytes,
         "Insufficient conservative capacity for whole requested group")
    report={"result":"PORTABLE_COMMAND2_ZERO_NIC_STAGE_PLAN_ONLY",
            "host":approved_host,
            "count":len(entries),
            "names":[row["libvirt_name"] for row in entries],
            "booted":False,"attached_nics":0,"network_modified":False,
            "windows_ip_assigned":False, "master_modified":False,
            "restore_verified":False,"created":[],
            "host_preflight":host_summary}
    if mode=="plan":
        return report
    need(sys.stdin.isatty(), "Interactive terminal required for stage")
    phrase="STAGE-COLD-ZERO-NIC-"+approved_host.upper()
    need(input("Type "+phrase+" to authorize large clone writes: ")==phrase,
         "User did not approve staging")
    # One shared root-private lock; re-check after locking.
    need(not (logdir/LOCK_NAME).is_symlink(),"Unsafe staging lock")
    lockfd=os.open(logdir/LOCK_NAME,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(lockfd)
        need(meta.st_uid==0 and stat.S_IMODE(meta.st_mode)==0o600 and
             stat.S_ISREG(meta.st_mode) and meta.st_nlink==1,
             "Unsafe staging lock metadata")
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        host_guard(approved_host,for_stage=True)
        target_host_preflight(entries,template,subnet)
        assert_cold_source_unshared(source,master_nvram)
        need(virsh("dumpxml","--inactive","win11")==master_xml,
             "Master XML changed during staging authorization")
        need(not any((logdir/(INTENT_PREFIX+row["libvirt_name"]+".json")).exists()
                     for row in entries), "Prior incomplete stage requires manual review")
        assert_no_collision(entries)
        stamp=exact_file(source)
        nvstamp=exact_file(master_nvram)
        need(digest_file(source)==template_sha256,"Template changed after authorization")
        for row in entries:
            report["created"].append(make_one(
                row,master_xml=master_xml,master_disk=master_disk,
                master_nvram=master_nvram,template=source,
                source_stamp=stamp,vars_stamp=nvstamp,logdir=logdir))
        report["result"]="PORTABLE_COMMAND2_ZERO_NIC_STAGED_NOT_PERSONALIZED"
        return report
    finally:
        os.close(lockfd)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--mode",choices=("plan","stage"),default="plan")
    cli.add_argument("--approved-host",required=True)
    cli.add_argument("--journal-dir",required=True,type=Path)
    cli.add_argument("--template",required=True,type=Path)
    cli.add_argument("--template-sha256",required=True)
    cli.add_argument("--master-nvram",required=True,type=Path)
    cli.add_argument("--master-uuid",required=True)
    cli.add_argument("--subnet",default="192.168.240.0/24")
    opt=cli.parse_args()
    try:
        data=execute(mode=opt.mode,approved_host=opt.approved_host,
                     journal_dir=opt.journal_dir,
                     template=opt.template,template_sha256=opt.template_sha256,
                     master_nvram=opt.master_nvram,master_uuid=opt.master_uuid,
                     subnet=opt.subnet)
        print(json.dumps(data,indent=2,sort_keys=True))
        return 0
    except (StageBlocked, reservation.ReservationBlocked, renderer.XMLBlocked,
            OSError,ValueError,ET.ParseError,json.JSONDecodeError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
