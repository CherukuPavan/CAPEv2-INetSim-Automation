# SSL-55 canonical manual installation log

> **LATEST CHECKPOINT — Steps 1–11D reviewed; first Windows VM not yet created.** Verified manual installation output and errors are recorded below. New [coverage ledger](AUTOMATION_COVERAGE_STEPS_1_11.md) lists which steps have executable **audit**, **controlled install**, or **not-yet-implemented** automation. The existing introductory historical status paragraphs were written earlier in the installation and do not override this later checkpoint. No end-to-end unattended installation or malware-safe guest network has been validated.


**Status:** Steps 1–7 reported with terminal evidence. The user ran the custom `kvm-qemu.sh all` hypervisor build in Step 7, which showed successful component stages **and serious unresolved errors**; overall hypervisor runtime is NOT verified. CAPEv2 runtime, Windows VMs, INetSim, and guest isolation remain unverified/not reported.

**Evidence provenance:** The user supplied a terminal transcription on 2026-10-08. Commands were **not** independently executed by the assistant on SSL-55, and exact execution timestamps were not supplied. "Terminal-evidenced" below means supported by the supplied output, not separately re-tested. Exact site-specific private IP addresses are intentionally **redacted from this GitHub record**; the original user-provided transcript remains in the conversation.

Previous assistant-guided QEMU/libvirt installation and rollback were exploratory work and are **not** counted as the manual installation procedure to automate.

## Step 1 — Host identity, interfaces, CPU virtualization flags

- **Reported date:** 2026-10-08 (actual execution date/time not independently established).
- **Performed by:** User on SSL-55.
- **Objective:** Establish the canonical reference machine's hostname, kernel, network-interface baseline, and CPU virtualization feature exposure.
- **Exact manual commands, in order:**
  ```bash
  hostname
  uname -a
  ip -br addr
  egrep -c '(vmx|svm)' /proc/cpuinfo
  ```
- **GUI actions:** None reported.
- **Dependencies/permissions:** Linux hostname/uname, iproute2 `ip`, grep, readable `/proc/cpuinfo`; no root required for the reported queries.
- **Software version/OS evidence:** `Linux CSE-SSL-55 7.0.0-34-generic #34~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 4 15:38:29 UTC 2 x86_64`. This is a kernel build string; the installed OS release has **not** been independently established by `/etc/os-release` or `lsb_release`.
- **Observed output:**
  - Hostname `CSE-SSL-55`.
  - `lo`: loopback up at OS level, displayed `UNKNOWN` by `ip -br addr`.
  - `enp3s0`: `DOWN`, no address shown.
  - `enp0s31f6`: `UP`, private IPv4 address with `/22` prefix (address redacted).
  - `wlp0s20f3`: `UP`, private IPv4 address with `/19` prefix and link-local IPv6 (addresses redacted).
  - `docker0`: `DOWN`, `172.17.0.1/16`.
  - Two `br-*` Docker bridge interfaces: `DOWN`, `172.18.0.1/16` and `172.19.0.1/16`.
  - `egrep -c '(vmx|svm)' /proc/cpuinfo` returned **64**. This counts matching `/proc/cpuinfo` lines; **it does not prove 64 physical cores**.
- **Expected result:** Identify host/network state and determine whether Intel VMX or AMD SVM flags are exposed.
- **Files/settings changed:** None by these commands.
- **Warnings/errors in output:** None reported for these commands.
- **Verification:** **Terminal-evidenced (user-supplied)**; the output supports identifying the reference host and exposed virtualization flags, not a complete virtualization or OS compatibility assessment.
- **Portability/safety notes:** Use `/etc/os-release` for supported Ubuntu version; check VMX/SVM without hardcoding the observed count; enumerate active host, wireless, wired and Docker interfaces without modifying them. Never assume Docker bridge CIDRs or lab network values are free on another host. Ensure that future analysis guest traffic cannot reach these existing host/private networks.
- **Related automation:** `scripts/check_host_virtualization.sh` (initial **draft**, read-only; not yet validated on SSL-55).

## Step 2 — Install `cpu-checker`

- **Reported date:** 2026-10-08 (actual execution date/time not independently established).
- **Performed by:** User on SSL-55.
- **Objective:** Install the utility used to check KVM acceleration availability.
- **Exact manual command:**
  ```bash
  sudo apt install cpu-checker -y
  ```
- **GUI actions:** None reported.
- **Dependencies/permissions:** Ubuntu/Debian APT package manager; sudo privileges; suitable configured package sources; `msr-tools` added as a dependency.
- **Installed package versions as shown:** `cpu-checker_0.7-1.3build2_amd64.deb`; `msr-tools_1.3-5ubuntu0.1_amd64.deb`. These are observed on SSL-55, **not** portable version pins.
- **Expected result:** `cpu-checker` and its dependency become installed, making `kvm-ok` available.
- **Actual result:** APT reported **2 newly installed**, **0 upgraded**, **0 removed**, **192 not upgraded**. It unpacked and configured `msr-tools` and `cpu-checker`; `man-db` triggers ran. Reported download required 0 B of 16.0 kB archives (already locally available); ~65.5 kB additional disk space.
- **Files/settings changed:** APT installed `cpu-checker` and `msr-tools` and updated package-management state. No other configuration changes were reported.
- **Warnings/errors:**
  - **Repeated APT target warnings**: VirtualBox `contrib` package, translation, DEP-11 and CNF targets configured in both `/etc/apt/sources.list.d/archive_uri-https_download_virtualbox_org_virtualbox_debian-noble.list:1` and `/etc/apt/sources.list.d/virtualbox.list:1`.
  - **192 packages not upgraded**; informational, not evidence that an upgrade is necessary.
  - APT listed automatically installed packages as no longer required, but **no `apt autoremove` was performed** in this step.
- **Troubleshooting:** None performed or requested; do **not** autonomously edit APT sources, upgrade packages, or autoremove packages.
- **Verification:** **Terminal-evidenced (user-supplied)** successful package setup; later `kvm-ok` output in Step 3 supports availability of the tool. No independent `dpkg-query` test recorded.
- **Portability notes:** Check whether `cpu-checker` and `msr-tools` already exist before installing; respect package versions available on the supported Ubuntu host and avoid unnecessary upgrades. Existing third-party repository warnings should be diagnosed separately and not silently "fixed".
- **Related automation:** Deployment dependency bootstrap **not implemented** yet. Read-only draft preflight detects whether `kvm-ok` exists; it **never installs** packages.

## Step 3 — Verify KVM kernel modules and acceleration

- **Reported date:** 2026-10-08 (actual execution date/time not independently established).
- **Performed by:** User on SSL-55.
- **Objective:** Confirm loaded KVM kernel modules and whether `/dev/kvm` enables acceleration.
- **Exact manual commands, in order:**
  ```bash
  lsmod | grep kvm
  kvm-ok
  ```
- **GUI actions:** None reported.
- **Dependencies/permissions:** `lsmod`, grep, installed `kvm-ok` from Step 2; KVM kernel/device support; no sudo used.
- **Expected result:** Intel/AMD KVM and general KVM modules, `/dev/kvm` and positive `kvm-ok` check.
- **Actual user-supplied output:**
  ```text
  kvm_intel             540672  0
  kvm                  1507328  1 kvm_intel
  irqbypass              16384  1 kvm
  INFO: /dev/kvm exists
  KVM acceleration can be used
  ```
- **Files/settings changed:** None by these commands.
- **Warnings/errors:** None in the supplied Step 3 output.
- **Verification:** **Terminal-evidenced (user-supplied): PASS for KVM availability on SSL-55 at the time of this test**. This **does not** demonstrate VM creation, QEMU/libvirt installation, guest isolation, analysis tooling, or network containment.
- **Portability notes:** Handle both `kvm_intel` and `kvm_amd`, and possible built-in kernel support; check `/dev/kvm` existence and user access; do not assume loaded modules always indicate guest readiness; do not assume `kvm-ok` is preinstalled on fresh machines.
- **Related automation:** `scripts/check_host_virtualization.sh` (**draft**, no SSL-55 runtime test).

## Step 4 — Ensure Git availability and clone CAPEv2 upstream source

- **Reported date:** 2026-10-08 (exact execution date/time not independently established).
- **Performed by:** User on SSL-55, terminal identity `charan@CSE-SSL-55`.
- **Objective:** Ensure Git is available and obtain the upstream CAPEv2 source repository.
- **Exact manual commands, in chronological order:**
  ```bash
  sudo apt-get install git -y
  cd ~
  sudo git clone https://github.com/kevoreilly/CAPEv2.git
  ```
- **GUI actions:** None reported.
- **Dependencies and permissions:** APT package manager, sudo privilege, Git binary, DNS/network access to `github.com`, free disk space and working GitHub HTTPS transport. The final clone was run **using sudo** from the user's home working directory.
- **Package evidence:** APT reported `git is already the newest version (1:2.43.0-1ubuntu7.3)` and `git set to manually installed`. **No newly installed Git package** is evidenced; the APT auto/manual installation state was changed to *manual*.
- **APT result:** `0 upgraded, 0 newly installed, 0 to remove and 192 not upgraded`. APT displayed an `autoremove` suggestion but the user **did not execute** it. This step's APT output did not contain new repository warnings; that does **not** establish the duplicate VirtualBox repository configuration from Step 2 has been resolved.
- **Source URL:** `https://github.com/kevoreilly/CAPEv2.git` (original exact upstream URL, preserve in canonical step history).
- **Observed clone output:**
  ```text
  Cloning into 'CAPEv2'...
  remote: Enumerating objects: 67910, done.
  remote: Counting objects: 100% (1031/1031), done.
  remote: Compressing objects: 100% (384/384), done.
  remote: Total 67910 (delta 861), reused 647 (delta 647), pack-reused 66879 (from 4)
  Receiving objects: 100% (67910/67910), 255.04 MiB | 4.66 MiB/s, done.
  Resolving deltas: 100% (45776/45776), done.
  ```
  Shell prompt returned after the command.
- **Expected result:** Git available, repository cloned into the working directory as `CAPEv2`.
- **Actual result:** **Terminal-evidenced successful source transfer and delta resolution**. Because `cd ~` was run in the `charan` shell, the intended checkout path is `~/CAPEv2`; an absolute path was not displayed. The source commit SHA, branch, on-disk file ownership and repository integrity have **not** been independently verified.
- **Files/settings changed:** APT marked the pre-existing Git package as manually installed; a new `CAPEv2` checkout directory and contents were created (per Git output). Git clone was launched via sudo, so its files may be **root-owned**. This is a portability and maintainability concern, not proof of a failure on SSL-55.
- **Warnings/errors:** No fatal error in the supplied clone output. No fix has been attempted for potentially root-owned checkout contents.
- **Verification status:** **Terminal-evidenced source clone: PASS**. **Full Git checkout identity/ownership/commit: NOT YET VERIFIED.** CAPEv2 has **not** been installed or tested merely by cloning the source.
- **Troubleshooting:** None reported.
- **Portability requirements:** On fresh supported Ubuntu machines, detect whether a functioning supported Git is installed; only install it when missing. Detect APT and privilege/repository errors instead of assuming availability. Clone as the intended user where safe (unlike the original `sudo git clone`), use a configurable path, refuse to overwrite arbitrary existing directories or repositories, validate the upstream origin and resulting Git commit. Record a **verified immutable commit SHA** for reproducible deployment; the manual clone did not report the commit, so the current default branch remains unpinned. Avoid hardcoded usernames, shared network CIDRs, and repeated network downloads on rerun.
- **Related automation:** `scripts/bootstrap_cape_source.sh` **draft**. It has an optional full-commit `--revision` pin, checks Git availability, installs missing Git with APT under explicit execution, clones as an unprivileged user, validates origin/HEAD on existing checkouts and refuses mismatches. This differs intentionally from the historical `sudo git clone` for safe fresh-host behavior.
- **Automation testing evidence:** Bash syntax validation passed; local sandbox tests of cloning from a **synthetic repository** with a **simulated Ubuntu OS identity** passed for initial clone, second-run no-op, and safe refusal of origin/revision mismatches. **No SSL-55 test, actual upstream clone test or Git-missing installation test was performed**. Draft is not production-ready.

## Step 5 — ACPI firmware analysis and replace nine installer placeholders

- **Reported date:** 2026-10-08 (exact execution time not independently established).
- **Performed by:** User on SSL-55, terminal `charan@CSE-SSL-55`.
- **Objective:** Extract DSDT firmware information and replace CAPEv2 installer QEMU/SeaBIOS identification placeholders using the selected host identifier.
- **Exact manual commands as supported by terminal evidence:**
  ```bash
  cd ~/CAPEv2/installer
  ls -lh
  sudo apt install acpica-tools -y
  sudo sh -c 'acpidump > acpidump.out'
  sudo acpixtract -a acpidump.out
  sudo iasl -d dsdt.dat
  cat dsdt.dsl | grep "Hardware ID"
  grep -n "OEM Table ID" dsdt.dsl
  grep -n "DSDT" dsdt.dsl | head
  sudo sed -i 's/<WOOT>/DELL/g' kvm-qemu.sh
  grep -n "<WOOT>\\|DELL" kvm-qemu.sh
  ```
  The `sudo sed -i 's/<WOOT>/895C/g' kvm-qemu.sh` command supplied in the surrounding explanatory text is from an **older reference/example**, **not an observed SSL-55 terminal command**.
- **GUI actions:** None reported.
- **Packages:** APT newly installed `acpica-tools` version `20230628-1`. `0 upgraded, 1 newly installed, 0 removed, 192 not upgraded`; no `apt autoremove`.
- **Existing local source evidence:** `installer/kvm-qemu.sh` was listed as ~57K and root-owned, consistent with Step 4 using `sudo git clone`.
- **ACPI evidence:** `acpixtract` reported writing numerous ACPI tables, including `dsdt.dat` (652906 bytes). `iasl` produced `dsdt.dsl` (~4.7 MB), reported `DefinitionBlock ("", "DSDT", 2, "DELL  ", "Dell Inc", 0x00000002)`. This means **OEM ID = `DELL  `** and **OEM Table ID = `Dell Inc`**. The user's selected `DELL` was derived from the padded OEM ID, **not** the OEM Table ID. The many `_HID` entries (e.g. `PNP*`) are device IDs, not the DSDT OEM ID.
- **Warnings:** iASL warned about unresolved external control methods, possible need for additional ACPI/SSDT files, and potential inability to recompile the resulting DSL. Disassembly still completed; do not report warning-free firmware compilation. APT reported 192 not upgraded, without a mandate for system-wide upgrade.
- **Files/settings changed:** `acpica-tools` was installed; firmware dump `acpidump.out`, extracted `*.dat` and `dsdt.dsl` were generated inside the CAPEv2 installer directory; `kvm-qemu.sh` was changed in place by `sudo sed -i`. These dumps may contain sensitive firmware information. **No backup was shown before the manual sed**.
- **Observed post-edit check:** Exactly the **nine named replacement assignments** appeared set to `DELL` at lines 116, 127, 130, 133, 136–138, 141 and 144, and the grep result showed **no remaining `<WOOT>`**. A `DELL` comment on line 140 was also returned. No original-file diff, exact source SHA, QEMU/SeaBIOS compilation, or guest behavior verification was supplied.
- **Verification status:** **Terminal-evidenced PASS** for package installation, DSDT disassembly output, and nine-variable text modification; **with iASL warning and unverified runtime compatibility**. No evidence of QEMU/SeaBIOS installed or running merely from these commands.
- **Technical caveat discovered via upstream source inspection:** The nine variables affect different QEMU/SeaBIOS identification surfaces. **Eight are disk/tablet/BIOS-related and cannot safely be inferred from an ACPI header alone**; the `BXPC` identifier is four characters and may accept an appropriate OEM candidate. A generic one-value-for-all shortcut (as in the historical PDF) is not a verified universal solution.
- **Automation:** [`scripts/prepare_acpi_replacements.py`](../scripts/prepare_acpi_replacements.py), a **draft** with read-only default, raw binary DSDT header checks, fail-closed OEM selection, reviewed per-field profile requirement for non-ACPI variables, source hash pin, guarded diff, secure backup, idempotence checks, and atomic changes only with explicit `--apply`. Python must be provisioned separately by the eventual bootstrap; this module does not install packages. See [`docs/ACPI_REPLACEMENTS.md`](ACPI_REPLACEMENTS.md).
- **Tests:** 13 synthetic local unit tests passed. The exact tested files were committed to `development` and their Git blob SHA values verified. **No test performed on SSL-55**, no real firmware binary provided to the assistant, and no actual Ubuntu fresh-host integration or QEMU/SeaBIOS compilation run.
- **Portability:** Do not hardcode DELL/895C/PNP0 or copy a host ACPI ID into unrelated device branding; reject missing/invalid/ambiguous ACPI input, unknown source structure or profile and unsupported runtime. Build/test on each claimed supported host class before certification. No automatic host modifications without explicit user authorization.

## Step 6 — Install libvirt clients/daemon, inspect default network and edit CAPE settings

- **Reported date:** 2026-10-09 (exact execution time not supplied). Performed by user on SSL-55.
- **Objective:** Make `virsh` available, install system libvirt/QEMU dependencies, identify `virbr0`, and update four values in upstream CAPEv2 `cape2.sh`.
- **Commands evidenced in user's terminal transcript:**
  ```bash
  sudo apt update
  sudo apt install -y libvirt-clients libvirt-daemon-system
  sudo virsh net-list --all
  ifconfig
  cd ~/CAPEv2/installer
  sudo sed -i 's/^NETWORK_IFACE=.*/NETWORK_IFACE=virbr0/' cape2.sh
  sudo sed -i 's/^IFACE_IP=.*/IFACE_IP="192.168.122.1"/' cape2.sh
  sudo sed -i 's/^INTERNET_IFACE=.*/INTERNET_IFACE=eno1/' cape2.sh
  # A further sudo sed command changed PASSWD to a literal secret; intentionally redacted.
  # Subsequent user correction, after inspecting outbound route:
  ip -4 route get 1.1.1.1
  sudo sed -i 's/^INTERNET_IFACE=.*/INTERNET_IFACE=enp0s31f6/' cape2.sh
  grep -E '^(NETWORK_IFACE|IFACE_IP|INTERNET_IFACE|PASSWD)=' cape2.sh
  grep -E '^(NETWORK_IFACE|IFACE_IP|INTERNET_IFACE|PASSWD)=' cape2.sh
  ```
- **Reference versus actual commands:** User-provided screenshot described `sudo virsh net-start default` and `sudo virsh net-autostart default`, but these **were not executed in the uploaded terminal transcript**. `virsh net-list --all` already showed `default active / autostart yes / persistent yes` after APT setup.
- **Package evidence:** `libvirt-clients` and `libvirt-daemon-system` installed; transaction added **51 packages**, upgraded **2** (`libxml2` for amd64/i386), removed **0**, and left **195 not upgraded**. `libvirt0` **10.0.0-2ubuntu8.19**, Ubuntu `qemu-system-x86` **1:8.2.2+ds-0ubuntu1.18**, `seabios` **1.16.3-2**, `ovmf` **2024.02-2ubuntu0.10** are visible in output. Package triggers regenerated initramfs. No `apt autoremove` performed.
- **Network evidence:** `default` network active, persistent, autostart enabled. Host `virbr0` assigned `192.168.122.1/24`; existing Ethernet, Wi-Fi, Docker bridges still shown. Specific institutional host addresses, MACs and upload-only secrets are not included here.
- **Original configuration evidence (superseded):** First `cape2.sh` grep showed `NETWORK_IFACE=virbr0`, `IFACE_IP="192.168.122.1"`, `INTERNET_IFACE=eno1` and `PASSWD=[REDACTED]`. This was corrected in the next user report.
- **Correction (latest user terminal evidence, 2026-10-09):** `ip -4 route get 1.1.1.1` selected **`enp0s31f6`** with the host Ethernet source and gateway. The user then executed `sudo sed -i 's/^INTERNET_IFACE=.*/INTERNET_IFACE=enp0s31f6/' cape2.sh` and the next `grep` confirmed `NETWORK_IFACE=virbr0`, `IFACE_IP="192.168.122.1"`, `INTERNET_IFACE=enp0s31f6` and `PASSWD=[REDACTED]`. The route lookup is evidence for this destination, **not proof of Internet reachability, all-destination routing, or malware isolation**. The user-provided campus/source addresses are redacted from GitHub.
- **Important warnings / blockers:**
  - **Resolved configuration error:** `eno1` was absent from host inventory; the user changed it to `enp0s31f6`. A destination-specific route lookup supports the correction. Actual Internet connectivity and stability across destinations/routes **remain unverified**.
  - The standard libvirt `default` network uses **NAT** by design, not isolated malware networking. The actual SSL-55 XML/forwarding rules have **not** been supplied: **do not attach live malware analysis guests to it without verified containment**.
  - The uploaded log includes an apparent live plaintext DB secret. Secret was removed from the documentation. User should rotate it wherever reused.
  - APT metadata combined `noble` and `focal` Ubuntu release suites (and third-party `jammy` feeds), repeatedly warned about duplicated VirtualBox sources. Do not rewrite repos or blindly upgrade.
  - Kernel module configuration repeatedly logged `/etc/modprobe.d/blacklist-kvm.conf line 1: ignoring bad line starting with '-e'`. Requires separate read-only verification and approved correction before relying on module behavior.
  - Ubuntu-packaged QEMU/SeaBIOS now coexist in the intended workflow with planned source-built versions; version/path conflicts must be reviewed.
- **Verification status:** **Terminal-evidenced PASS** for package configuration, current libvirt network status and setting assignments. **NOT VERIFIED:** default network XML, actual NAT/firewall/forwarding state, guest isolation, Internet reachability or routing behavior across all destinations, QEMU/CAPEv2 source build compatibility, database auth, runtime functionality or Windows/INetSim deployment.
- **Automation design:** [`docs/LIBVIRT_NETWORK_STEP6.md`](LIBVIRT_NETWORK_STEP6.md) gives complete analysis; new read-only [`scripts/audit_libvirt_cape_network.py`](../scripts/audit_libvirt_cape_network.py) detects NAT, mismatched bridge/IP/interface and redacts `PASSWD` without evaluating installer source. Its **11 synthetic tests passed**; matched GitHub blob SHA after upload. No SSL-55 audit or live malware-isolation tests have run.
- **Additional portability implementation (2026-10-09):** [`scripts/discover_host_uplink.py`](../scripts/discover_host_uplink.py) checks the per-destination route, actual link state, source IPv4 assignment, default route ambiguity, policy routing, VPN and container interfaces and explicit override, **without changing networks**. The 19 synthetic tests in [`scripts/test_discover_host_uplink.py`](../scripts/test_discover_host_uplink.py) passed; a separate-environment read-only smoke test passed. Not tested on SSL-55. See [`docs/DYNAMIC_NETWORK_DISCOVERY.md`](DYNAMIC_NETWORK_DISCOVERY.md).
- **Portability:** Missing system packages should be installed only in the authorized deployment stage after checking OS/repo health, package versions and conflicts; preserve existing workloads. Derive actual interface names/routes, use dedicated isolated guest networking with negative-connectivity checks, store credentials securely, and refuse to proceed with malware operations until safety gates pass.
- **Full evidence:** Original uploaded transcript is retained in the conversation with its confidential information, not copied into GitHub.

## Step 7 — Run custom KVM/QEMU/SeaBIOS/libvirt installer (partial / unverified)

- **Reported date:** 2026-10-09. **Performed by:** user on SSL-55 (`charan`), not by assistant.
- **Manual procedure, as reported:**
  ```bash
  cd ~/CAPEv2/installer
  sudo chmod a+x kvm-qemu.sh
  sudo ./kvm-qemu.sh --help
  sudo ./kvm-qemu.sh all charan 2>&1 | tee kvm-qemu-all.log
  ```
- **Objective:** Build customized QEMU, SeaBIOS, libvirt/KVM and optional desktop virtualization manager. On a fresh machine the Ubuntu login name may vary; never hardcode `charan`.
- **Actual command argument semantics:** Inspected upstream `kvm-qemu.sh` initializes `username=$SUDO_USER` and comments out the branch that would set username from `$2`. `all charan` therefore does **not** independently guarantee the intended user is `charan`; under ordinary `sudo` from `charan`, `SUDO_USER` supplies that identity. Validate account existence/non-root UID/permissions and current revision. There is a top-level `systemctl mask` before help/command dispatch; `--help` is **not** harmless. See [KVM_QEMU_STEP7.md](KVM_QEMU_STEP7.md).
- **Evidence:** Uploaded `Pasted text(4).txt` had **9,154 lines**. It **begins mid-build** with `[1683/3252]` and ends at a returned shell prompt; the original `all` shell exit status and initial log prefix were **not captured**. A pipeline without `set -o pipefail` normally reports `tee` status; even zero installer exit status would require functional checks.
- **Positive stage indicators (from the supplied excerpt):** QEMU **9.2.2** package created/installed, SeaBIOS **1.16.3** `bios.bin` generated/copied, libvirt-python **11.1.0** wheel installed, KVM acceleration reported usable, `virt-host-validate qemu` produced multiple PASS results, libvirt sockets were enabled and virt-manager installation activity reached the end of output. These are **not** proof that runtime/guest isolation is working.
- **Errors and warnings requiring review:**
  - The script purged previously installed Ubuntu libvirt-client/daemon/config packages (9 packages) and set APT holds; existing default bridge/network may have been disrupted.
  - `libkmod` repeatedly found invalid `/etc/modprobe.d/blacklist-kvm.conf` line beginning with `-e`.
  - `fatal: The group 'kvm' already exists`; group membership still needs verification and creation must be idempotent.
  - SeaBIOS first patch attempt encountered missing `.config`, followed by compiler and linker warnings (including string overread).
  - Forced OVMF install overwrote files owned by the custom QEMU package.
  - Python package installer failed attempting to remove distro `cryptography 41.0.7` (missing RECORD), and attempts to satisfy Python 2 era dependencies (e.g. `python-enum34`) exposed conflicts. Mixed `focal`/`noble` APT sources add risk.
  - Global system sysctl, GRUB/IOMMU and sleep-target masks were modified; script emitted `[+] Please reboot`. Reboot not verified or authorized by assistant.
- **Safety:** Do not rerun `all` blindly, purge additional libvirt packages, force-overwrite firmware, fix grub/sysctl or reboot as automatic remedies. Protect Docker/networking and unrelated workloads. Use isolated malware-analysis network only after validated negative guest connectivity checks.
- **Verification status:** **PARTIAL BUILD WITH ERRORS — not fully successful or production-ready.** No post-run `virsh version`, binary provenance, running service validation, guest VM or INetSim checks were supplied.
- **Automation:** [`scripts/audit_kvm_build_step7.py`](../scripts/audit_kvm_build_step7.py) read-only audit: **10 synthetic tests passed**, and real excerpt classified `UNVERIFIED_WITH_ERRORS` with nine distinct findings. Inspects source `SUDO_USER` semantics and validates non-root target usernames when invoked with a real local account. GitHub committed sources matched tested blob SHAs. Future install will use gated modular steps and actual exit codes; not automatic execution of upstream `all`.
- **Detailed evidence and acceptance requirements:** [KVM_QEMU_STEP7.md](KVM_QEMU_STEP7.md). Raw user log is **not committed**.

### Step 7 follow-up — Post-build validation (2026-10-09)

- **Input:** user-supplied `SSL55_Step7_PostBuild_20261009_025646.txt`; read-only checks performed **by user** on SSL-55. Full findings: [STEP7_POSTBUILD_AUDIT.md](STEP7_POSTBUILD_AUDIT.md).
- **Verified functioning:** `qemu-system-x86_64` **9.2.2**; `virsh` **11.1.0**; `virsh -c qemu:///system version` successfully shows libvirt **11.1.0** with running QEMU **9.2.2**; `kvm-ok` confirms acceleration; `libvirtd.service` active. No VMs defined yet.
- **Network regression from Step 6:** `default` is now **active, autostart no, persistent no**. It is **transient**, so do not rely on it surviving a restart. The actual libvirt XML/bridge isolation was **not inspected in this report**; never assume default NAT is safe for malware guests.
- **Account permissions:** `getent group kvm` and `libvirt` list `charan`, but the current `id` session lists only the primary `charan` group and `sudo`. Login-session group membership needs refresh/verification, not blind `usermod`.
- **Host configuration issues:** `/etc/modprobe.d/blacklist-kvm.conf` contains malformed `-e blacklist kvm_intel` and a real `blacklist kvm`; `net.ipv4.tcp_syncookies=0`; sleep/suspend/hibernate targets masked; `qemu` held by APT. These require reviewed host-safe remediation, **not unattended repair**.
- **Additional observations:** `libvirt-clients`, `libvirt-daemon-system`, `seabios` not installed *as Ubuntu packages*, which does **not** contradict working source-built QEMU/libvirt or copied firmware. `libvirtd` active and modular `virtqemud` / `virtnetworkd` inactive does **not** alone mean broken virtualization. The expected `kvm-qemu-all.log` path was not found. Reboot-required marker present. **Do not reboot until module and network issues are assessed.**
- **Verification:** **QEMU/libvirt/KVM basic runtime verification PASS; overall Step 7 still BLOCKED/REVIEW REQUIRED** for stable configuration and guest isolation. No Windows VM booted, no post-reboot check and no INetSim tests.
- **Automation:** [`scripts/audit_step7_postbuild.py`](../scripts/audit_step7_postbuild.py), a secret-safe read-only parser with **14 passed synthetic tests**; run on this exact report, it returned `REVIEW_REQUIRED` and 11 diagnostic categories. Committed source/test Git hashes match local tested versions. This is a diagnostic draft, **not** an installer.
- **No modifications performed to SSL-55 by assistant.**

### Step 7 second follow-up — Final topology and policy diagnostics (2026-10-09)

- **User-run read-only report:** `SSL55_Step7_FinalDiagnostics_20261009_030314.txt`. Detailed interpretation: [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md). The raw report was not committed due to institution-specific IP/MAC/UUID data.
- **Conclusive guest-network fact:** `virsh net-dumpxml default` showed **`<forward mode='nat'>`** and DHCP on `virbr0` with gateway `192.168.122.1/24`. This is **not** an isolated malware analysis network. No guest/host firewall or negative connectivity test has been done. **Never run live samples on this network.**
- **Persistence:** `net-info default` reports **active yes, persistent no, autostart no**. The source-installer's network definition is therefore currently transient; do not force autostart or persist the existing NAT just to satisfy a check. `ip -br addr show virbr0` showed **DOWN**; with no guest attached, this does not independently prove bridge failure.
- **Host uplink:** Two main-table IPv4 default routes exist, Ethernet `enp0s31f6` metric **100**, Wi-Fi `wlp0s20f3` metric **600**. Prior `ip route get 1.1.1.1` chose Ethernet; do not assume a single route or hardcode interfaces across hosts. Preserve Docker bridges and institutional network paths.
- **User groups:** A separate `id charan` confirms account group membership in `kvm` and `libvirt`; the current session's `id` shows neither. A new login may be required before non-root libvirt usage.
- **Modprobe:** File `/etc/modprobe.d/blacklist-kvm.conf` contains an invalid `-e blacklist kvm_intel` line plus the valid `blacklist kvm` directive. Current KVM works, but the post-reboot module-loading policy is not verified. No file edits authorized or performed.
- **Sysctl and power management:** `net.ipv4.tcp_syncookies=0` actively and in both `/etc/sysctl.conf` and `/etc/sysctl.d/99-sysctl.conf` views. These paths may alias/symlink; do not blindly edit both. Four power-management targets are masked. Security settings require a deliberate policy-reviewed change, not unattended automation.
- **Current decision:** **Basic QEMU/libvirt/KVM runtime PASS**, **Step 7 host readiness and guest containment NOT PASSED**. No restart, reboot, service change, system configuration edit, or VM creation by assistant. Keep status pending until approved fixes and negative isolation tests. See [STEP7_FINAL_DIAGNOSTICS.md](STEP7_FINAL_DIAGNOSTICS.md).

### Step 7A — Backup of KVM modprobe configuration completed (2026-10-09)

- **User-performed manual procedure:** Previously supplied backup/diagnostics block inspected `/etc/modprobe.d/blacklist-kvm.conf`, created a restricted backup under `/root`, verified the backup byte-for-byte, and recorded module state. Input: `SSL55_Step7_KVM_Backup_20261009_030850.txt` (not committed).
- **Backup verified:** `/root/SSL55_KVM_Backup_yTIScjEU/blacklist-kvm.conf`, `Backup verification: PASSED`, original owner/mode `root:root 0644`, 37 bytes; source and backup **both SHA-256 `d172d41f94534d38db5a0f3cb489313e45c89a47e23007693e7e29775d6052c1`**.
- **Current exact config:** first line `-e blacklist kvm_intel` (**malformed and ignored**); second line `blacklist kvm` (**valid and currently effective** for relevant modalias-based module autoload behavior). `sudo modprobe --showconfig` reproduced the bad-line parse error and reported `blacklist kvm`, `options kvm ignore_msrs=Y`, and `options kvm report_ignored_msrs=N`.
- **Runtime remains usable before modification:** `kvm_intel` and `kvm` loaded; `/dev/kvm` present, root:kvm. No modules reloaded, config changed or reboot performed as part of Step 7A.
- **Status at the time of Step 7A (subsequently completed in Step 7B):** After checking exact source hash and matching backup, replace **only the malformed first line with a comment preserving its original text**, leave the valid `blacklist kvm` directive untouched pending separate policy review. Verify exact resulting two lines, file metadata and `modprobe --showconfig`; do not unload modules/restart/reboot.
- **Automation portability:** The eventual installer must check module config syntax, policy intent, intended autoload behavior and existing aliases; never unconditionally remove a blacklist or reuse SSL-55's expected SHA/backup path on another machine. Maintain backup, expected-state match, exact diff, verification and a separate post-reboot test.
- **Evidence detail:** [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md).

### Step 7B — First-line KVM module configuration correction VERIFIED (2026-10-09)

- **Input:** User-uploaded `SSL55_Step7B_KVM_Correction_2icT1bAB.txt` (25 physical lines); this is the **user's terminal evidence**, not an assistant-run change. No secrets or raw institutional host metadata included in GitHub.
- **Pre-change checks passed:** Output shows `Original and backup verification: PASSED`. The previous Step 7A backup SHA and matching source were verified by the user's guarded procedure before modification.
- **Exact modified config, verified by script using byte-for-byte expected-content comparison:**
  ```text
  # Malformed directive preserved for review: -e blacklist kvm_intel
  blacklist kvm
  ```
- **Post-change checks PASSED:** Owner `root:root`, mode `0644`; `modprobe --showconfig` had successful exit and no stderr (report: `modprobe configuration parsing: PASSED`); the valid `blacklist kvm` rule was preserved; `kvm_intel` and `kvm` remained loaded. **No reboot or module reload performed**. No full fresh-session/post-reboot module-loading test done.
- **Manual result:** **Step 7B SUCCESS for precise malformed-line correction**, not proof of the entire Step 7 installation or reboot readiness. Remaining valid `blacklist kvm` may affect automatic module loading and must be policy-reviewed separately; disabled `net.ipv4.tcp_syncookies=0`, masked sleep targets, and NAT/nonpersistent `default` network remain unresolved.
- **Automation:** Added [`scripts/audit_kvm_modprobe.py`](../scripts/audit_kvm_modprobe.py), a **read-only** module-policy inspector, with [14 synthetic tests](../scripts/test_audit_kvm_modprobe.py) passing. It detects the malformed original directive and recognizes the corrected file as syntax-clean but with an existing KVM blacklist requiring human review. It does not modify files, enable modules or certify reboot safety. Git blobs match locally tested content.
- **Updated analysis:** [STEP7_KVM_BACKUP.md](STEP7_KVM_BACKUP.md).

### Step 7C — SYN-cookie sysctl alias inspection VERIFIED (2026-10-09)

- **User-run read-only report:** `SSL55_Step7C_SysctlReview_DeiDOi9A.txt`. The active `net.ipv4.tcp_syncookies = 0` remains disabled. No change made in this step.
- **Identity confirmed:** `/etc/sysctl.conf`, `root:root 0644`, size 2804 bytes, contains a single active setting at line 77, `net.ipv4.tcp_syncookies = 0`. `/etc/sysctl.d/99-sysctl.conf` is a symlink `-> ../sysctl.conf`, resolving to the same underlying device/inode. **The two grep matches are ONE underlying definition.**
- **Action:** **Step 7C review completed**, **Step 7D correction NOT EXECUTED**. Proposed future backup-first, exact-line narrow change to `1`, only after policy and expected-state checks. Apply runtime change with single-key `sysctl -w`, not broad `sysctl --system`. Preserve canonical file, alias, mode/owner, other sysctl keys and host services; verify after. No reboot.
- **Automation:** New read-only [`scripts/audit_sysctl_alias.py`](../scripts/audit_sysctl_alias.py), with [15 synthetic tests](../scripts/test_audit_sysctl_alias.py) passing locally. Module compares actual file identity and settings without modifying source; GitHub blobs verified against tested files. **Not run on SSL-55**. See [STEP7_SYSCTL_REVIEW.md](STEP7_SYSCTL_REVIEW.md).
- **Remaining independent issues:** valid `blacklist kvm` needs policy review; default libvirt network has NAT and is transient; four power targets masked; guest/INetSim containment and reboot readiness unverified.

### Step 7D — First approval attempt CANCELLED (2026-10-09)

- **Observed output from user terminal:** `Step 7D: Enable TCP SYN-cookie protection.` / `Only the canonical sysctl file and one live kernel setting will change.` / `Cancelled. No changes made.` Returned to the `charan` shell prompt. Some portions of the pasted heredoc appeared garbled in the display; no separate system-change log was supplied.
- **Cause of cancellation:** Previous assistant-supplied `bash <<'BASH'` fed the script to Bash via standard input, while its `read -r -p 'Type APPLY ...' CONFIRM` also attempted to read from the same input. This **did not reliably read from the user's keyboard**. The script entered the non-`APPLY` cancellation branch. **The expected backup/file-edit/`sysctl -w` code was after this branch and therefore did not run, as far as the supplied transcript supports.**
- **Outcome:** **No Step 7D correction verified or claimed; canonical `/etc/sysctl.conf` and active `net.ipv4.tcp_syncookies` remain at the last observed value `0` unless changed independently.** Do not report a backup, `sysctl -w`, or root-owned config update from this attempt.
- **Correction to the *procedure*:** Use an explicit controlling terminal for interactive confirmation (`read ... </dev/tty`) and preferably write a privately permissioned temporary script with a heredoc, validate it using `bash -n`, then execute that saved script so it does not consume its own source as stdin. Keep all Step 7C alias/inode/metadata guards, a root-only backup, exact line diff and one-key-only `sysctl -w`. Do not blindly rerun a partially applied remediation; confirm state first.
- **No automatic host edits** were performed by the assistant. Await a user-executed corrected procedure and TXT report before marking Step 7D passed.

### Step 7D — Successful approved retry, TCP SYN-cookie protection enabled (2026-10-09)

- **Source:** User-uploaded `SSL55_Step7D_SynCookies_20261009_032549_1d5Iozfo.txt` (17 lines). This is an **executed user-controlled manual correction**; the assistant did not execute commands on SSL-55. The earlier cancelled attempt remains recorded immediately above for chronology.
- **Guarded preflight:** `Preflight: PASSED`, `Configuration sources: PASSED`; the approved script checked the observed SSL-55 canonical sysctl file identity/metadata, its `/etc/sysctl.d/99-sysctl.conf` symlink, the single original `net.ipv4.tcp_syncookies = 0` assignment, and the prior active kernel value.
- **Protected backup:** `/root/SSL55_Sysctl_Backup_JKE7DZRE/sysctl.conf`. File and backup SHA-256 both `8ee4db587d87f7377768678f2c93a68bdd624fa311b29e9b9a838e2d32d83749`; script printed **`Backup verification: PASSED`** before applying the edit. Preserve this root-only backup; do not publish its full sysctl contents.
- **Persistent change verified:** Script updated **only** line 77 of canonical `/etc/sysctl.conf`, from `net.ipv4.tcp_syncookies = 0` to `net.ipv4.tcp_syncookies = 1`, compared the modified file byte-for-byte against applying the same narrow edit to the backed-up original, checked `root:root 0644` and verified the sysctl symlink still targets `/etc/sysctl.conf`. Report prints `Persistent configuration: PASSED`.
- **Runtime change verified:** Script executed single-key `sudo sysctl -w net.ipv4.tcp_syncookies=1` and verified `sysctl -n net.ipv4.tcp_syncookies` equals `1`; report prints `Runtime configuration: PASSED` and `STEP 7D SUCCESS`.
- **Reboot/services:** Report says **no reboot or service restart**. Post-reboot persistence remains **untested**, though the current durable config and live setting were verified.
- **Status: Step 7D PASSED.** The earlier disabled-SYN-cookie finding is **resolved for current verified state**. Still unresolved: valid `blacklist kvm` policy/autoload after restart; masked sleep targets; transient `default` libvirt NAT network; safe dedicated Windows/INetSim network and negative guest-isolation testing. No malware-execution readiness claim.
- **Automation:** Current read-only [`scripts/audit_sysctl_alias.py`](../scripts/audit_sysctl_alias.py) includes synthetic tests of enabled and disabled settings but has **not** been run against the post-change SSL-55 host. Future authorized installer should capture equivalent protected backups, guarded one-key change, current-state verification and reboot checks, discovering paths/inodes afresh instead of hardcoding SSL-55.

### Step 7E — Read-only KVM boot-policy and module availability review VERIFIED (2026-10-09)

- **User-generated report:** `SSL55_Step7E_KVM_Policy_20261009_032931_nSxfpAHQ.txt` (66 lines), obtained with no changes to config/modules/libvirt and no reboot.
- **Kernel/module state:** On kernel `7.0.0-34-generic`, `kvm_intel` and `kvm` remain loaded, `/dev/kvm` exists, and the respective `kvm-intel.ko.zst` and `kvm.ko.zst` files were present. The libvirt service was **active**; `modprobe --showconfig` parsing **PASSED** after Step 7B.
- **Effective modprobe rules:** One `blacklist kvm` from `/etc/modprobe.d/blacklist-kvm.conf`, plus `options kvm ignore_msrs=Y` and `options kvm report_ignored_msrs=N` from `/etc/modprobe.d/kvm.conf`. These options can alter guest-MSR behavior and logging; future automation must validate intended use rather than universally impose them. No other matching rules appeared in the user-scanned directories; absence of entries in `/etc/modules` and modules-load files is **not** proof that KVM will fail to load at boot.
- **Dry-run:** `modprobe --dry-run --verbose kvm`, `... kvm_intel`, and blacklist-aware `... --use-blacklist kvm_intel` all indicated **SUCCESS**. Dry runs did **not load** modules, and already-loaded modules limit what can be inferred. **Do not mark boot-time autoload/persistence verified.**
- **Security cross-check:** Step 7D's `net.ipv4.tcp_syncookies=1` was independently observed again.
- **Acceptance:** **Step 7E diagnostic COMPLETED**; current basic KVM/libvirt runtime is healthy, but valid `blacklist kvm` remains **policy review required**. No justification to remove it blindly; no reboot, service restart, network modification or VM deployment authorized. Guest isolation remains unverified.
- **Automation:** [`scripts/audit_step7e_kvm_policy.py`](../scripts/audit_step7e_kvm_policy.py) safely parses a consolidated text report without touching the host or outputting raw host data. **14 synthetic cases passed** in the separate test environment, and running on the actual uploaded report yielded `BASIC_KVM_CHECKS_PASS_POLICY_REVIEW` with no basic-check blockers but the existing blacklist flagged. The script always sets `boot_autoload_verified=false`, `guest_isolation_verified=false`, `authorizes_reboot_or_malware_execution=false`. Committed module and tests match tested blob hashes.
- **Detailed evidence:** [STEP7E_KVM_POLICY.md](STEP7E_KVM_POLICY.md).

### Step 7F — Read-only power-management mask audit COMPLETE (2026-10-09)

- **User uploaded:** `SSL55_Step7F_PowerPolicy_20261009_033421_F3D5iOPz.txt`, 93 physical lines (94 indexed). Inspected without any host-side changes by assistant.
- **Persistent masks confirmed:** Four systemd targets `sleep.target`, `suspend.target`, `hibernate.target`, `hybrid-sleep.target` all have `is-enabled=masked`, `LoadState=masked` and `UnitFileState=masked`. Root-owned `/etc/systemd/system/<target>` symlinks point to `/dev/null`; no direct `/run/systemd/system/<target>` runtime override was reported. These are **persistent host-wide masks**, not transient runtime changes.
- **Installer behavior confirmed in local source:** `~/CAPEv2/installer/kvm-qemu.sh` line 76 contains `systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target`, which likely produced the masks. The report cannot prove that the administrator did not separately authorize the policy. Reboot-required marker still present.
- **Impact:** These masks prevent normal activation of the sleep/hibernate systemd targets. They may suit a dedicated always-on analysis host but may be disruptive on an ordinary workstation. **Do not automatically unmask (or remask) them until the owner confirms desired policy and approval.** No unmask/mask, daemon restart, host edits or reboot occurred in the Step 7F inspection.
- **Status:** Step 7F **diagnostic passed**, and **power policy decision remains PENDING**. This is not a virtualization installation failure by itself and is not permission to reboot or run malware. KVM `blacklist kvm` autoload intent and separate dedicated guest-isolation network remain unresolved.
- **Automation:** [`scripts/audit_step7f_power_policy.py`](../scripts/audit_step7f_power_policy.py) parses this offline user report without emitting host identifiers. **14 synthetic unit tests passed**, and the actual report classified `PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED` with all four `PERSISTENTLY_MASKED`; no parsing errors. Both Git blobs match the locally tested versions. This is read-only preflight, **not** power-policy implementation.
- **Technical details:** [STEP7F_POWER_POLICY.md](STEP7F_POWER_POLICY.md).

### Step 7F follow-up — SSL-55 identified as shared college workstation (2026-10-09)

- **New user-provided operational constraint:** CSE-SSL-55 is a **college-owned shared machine with other student login accounts**. This corrects any earlier assumption that it is a dedicated, always-on CAPEv2 appliance. Existence of multiple accounts does **not** establish who is currently signed in or whether the user has institutional authorization for host-wide changes.
- **Power-management policy:** The four persistent systemd sleep/hibernate masks found in Step 7F affect the **entire computer**, not only the user's login. **Do not automatically recommend keeping the masks merely for CAPEv2 analyses, and do not unmask them without coordination with college IT/system administrators and confirmation of baseline institutional policy.** Shared-use preference is to preserve or restore approved general workstation functionality through an authorized, documented and reversible change plan.
- **Broader host scope:** Upstream `kvm-qemu.sh all` also affected libvirt/QEMU packaging, boot/systemd/sysctl behavior, Python dependencies and virtualization networking. A shared-host compatibility, access/owner, current student sessions/processes, backup and maintenance-window review is required **before further installation, rollback, service restart or reboot**. Merely being in `sudo` does not establish administrative approval.
- **Containment boundary:** **Do not execute live malware on this shared college workstation or connect it to the institution LAN via NAT as an analysis guest.** Prefer a dedicated college-approved machine/segregated lab under explicit institutional security policy with verified IPv4/IPv6 isolation and negative egress tests; SSL-55 can be kept only as a non-malware documentation/installation reference until authorization and safety are established.
- **Outcome:** Step 7F read-only inspection COMPLETE; **policy change and reboot NOT authorized**. **Next: confirm the user's authorization and college IT's approved role for SSL-55** before issuing any modifying terminal commands. No additional host changes have been made by the assistant.

### Live-malware execution target confirmed (2026-10-09)

- **User states the final goal is running real malware inside CAPEv2 Windows analysis VMs**, not simply installing/testing the software. This intent was confirmed **after** the user's separate statement that CAPEv2 installation through `charan` is allowed on a shared college computer. These are **different authorization scopes**; explicit institutional permission for live malware on SSL-55 has not yet been confirmed.
- **Safety hold:** Existing `default` libvirt network is `<forward mode='nat'>` and not malware-safe, no dedicated isolated CAPE/INetSim network or negative IPv4/IPv6 egress verification exists; other students use accounts on the physical host. **Do not start real malware samples on SSL-55**, and do not use ordinary college LAN, NAT, WiFi or Docker/VPN paths as a sample network.
- **Continue approved platform development and non-malware diagnostics/manual setup.** Prefer a dedicated college-approved analysis workstation with separately validated security boundaries for the live phase; college security/IT must specifically approve live malware use and risk on a shared physical host if that is proposed.
- **Release gate and design:** [LIVE_MALWARE_CONTAINMENT_POLICY.md](LIVE_MALWARE_CONTAINMENT_POLICY.md) describes required approvals, separate INetSim guest, nonforwarding virtual network, Windows NIC restrictions, independent host firewall/routing inspection, guest negative IPv4/IPv6 reachability tests, snapshots and incident handling. The final 3-command automation must block live samples until all gates pass.
- **No host change:** This is a documentation and planning update only; Step 7F power masks remain unchanged, and post-reboot KVM readiness remains untested.

### Step 8 — Virt-Manager binary/version found; standalone installer not needed (2026-10-09)

- **User-run read-only evidence:** `SSL55_Step8_VirtManager_Check_3j94rYZv.txt` (18 physical lines / 19 indexed). `command -v virt-manager` returned `/usr/local/bin/virt-manager`; `virt-manager --version` returned `5.1.0`; `libvirtd.service` reported `active`.
- `dpkg-query` found **no Ubuntu `virt-manager` package** and **no `ubuntu-desktop` metapackage**. This is consistent with a **non-dpkg (likely source) installation** in `/usr/local`; it does **not** mean the executable is absent. Do not assume that a missing metapackage proves the machine has no graphical desktop; the metapackage is not necessary for all desktop setups.
- The upstream `installer/kvm-qemu.sh all` branch conditionally invokes `install_virt_manager` only if `dpkg -l` finds `ubuntu-desktop` (in inspected upstream blob `23b7eaa30bdd13bd9347098fe0d46204550b86f9`); the standalone `virtmanager` case invokes a **source/build installation** and includes system-wide schema/service changes, and the script masks sleep targets at top level even before dispatch.
- **Decision:** **SKIP** proposed `sudo ./kvm-qemu.sh virtmanager charan 2>&1 | tee ~/kvm-qemu-virtmanager.log`. It is unnecessary given the present working executable/version and could repeat invasive steps on the shared college host. No package installation or source installer was rerun.
- **Verification limit:** Binary runs with `--version`, but actual Virt-Manager **GUI launch and connection to `qemu:///system` from the current user's graphical login are NOT yet verified**. Next safe manual step: user launches the existing GUI as their **normal account (not sudo)** and confirms libvirt system connection; if it fails, gather error output and diagnose narrowly before changing packages/groups. Do not create or connect a malware VM to existing `default` NAT.
- **Automation portability:** Inspect `command -v`, `virt-manager --version`, GUI/display/session readiness and `virsh` libvirt access, and distinguish source installations from `dpkg` packages. Do not install or recompile merely because `dpkg-query` finds no `virt-manager` package. Source dependency version/provenance and GUI validation remain open.

### Step 9 — Non-root libvirt and virtual-network read-only inspection (2026-10-09)

- **User-run terminal evidence:** Under normal `charan` shell, `virsh -c qemu:///system list --all`, `virsh -c qemu:///system net-list --all`, and `ip addr show virbr0` all returned results without `sudo`. The successful queries are evidence of **read-only access to system libvirt from the current login**. They do **not** demonstrate graphical Virt-Manager GUI connectivity, write authorization or new group/session login state.
- **VM inventory:** `virsh list --all` yielded only header (no defined system-libvirt domains at inspection time); first analysis VM is not yet built.
- **Default libvirt network:** `default` was **active**, **autostart=no**, **persistent=no** (transient). The `virbr0` interface existed with `192.168.122.1/24`, `UP` flag but `NO-CARRIER` and operational `state DOWN`. With no guests, NO-CARRIER does **not** establish a malfunctioning bridge.
- **Crucial previous evidence:** Prior Step 7 `net-dumpxml` demonstrated `default` has `<forward mode='nat'>`; **NAT does not provide containment** for real malware, especially on a shared college workstation. Do **not** start sample VMs on `default`, or enable NAT network persistence/autostart as a reflexive fix for these observations.
- **Decision:** **Step 9 inspection PASSED as a non-mutating baseline check**, but no VM exists and **dedicated isolated analysis network, Windows/INetSim VM deployment, guest egress tests and GUI validation remain NOT COMPLETE**. No libvirt network, power, routes, firewall or guest state changed by this step. A subsequent safe, pre-reviewed manual step can proceed; ask user for the next installer-document instruction rather than guessing or creating the wrong network.
- **Portability:** Final installer must query `qemu:///system` using the real invoking user, handle sudo group-refresh edge cases, distinguish active vs autostart vs persistent, report empty VM domains without treating it as an error, and check forwarding/NAT XML and guest egress separately from bridge carrier status.

### Step 10 — CAPEv2 `cape2.sh base` started; awaiting completion evidence (2026-10-09)

- **User screenshot evidence (not a terminal completion log):** In normal `charan` terminal under `~/CAPEv2/installer`, the user executed `sudo chmod a+x cape2.sh` followed by `sudo ./cape2.sh base 2>&1 | tee ~/cape2-base.log`. The screenshot shows `[+] Installing dependencies`, successful `en_US.UTF-8` generation, package-resolution and ongoing apt downloads/unpacking (e.g. `cmake`, `crudini`, `libjsoncpp25`, `libhashahso`). **At screenshot time no terminal prompt/installer completion or exit code was visible.**
- **Status: STARTED / RUNNING OR OUTCOME UNKNOWN — NOT VERIFIED COMPLETE.** Do not rerun `cape2.sh base` or begin later installing steps until user's first process ends and exit/status/log/service evidence is reviewed. The shell pipeline through `tee` usually returns the tee status rather than the actual `sudo ./cape2.sh` exit code unless `pipefail` is set; ask user to capture `${PIPESTATUS[0]}` immediately after pipeline completion if still possible. Exit 0 alone may not prove all substeps succeeded.
- **Inspected current upstream source (NOT a verified copy of the local edited script):** `kevoreilly/CAPEv2/installer/cape2.sh` blob `1bb76ccb84b5f67ca877ad863550b63687f51e37`, `base` dispatch around lines 1724–1743. It invokes `dependencies`, `install_mongo`, `install_CAPE`, `install_yara`, `install_suricata`, `install_systemd`, `install_jemalloc` and scheduled cron entries. Its dependency setup invokes `timedatectl set-timezone UTC`, installs many system packages and modifies shell/installation paths; later stages install and restart CAPE systemd services. The **actual SSL-55 local copy can differ**; do not assert these phases have completed from the screenshot.
- **Shared host safeguards:** Assess host timezone, service state and side effects after completion; don't interrupt dpkg mid-transaction, blindly rerun installer stages or restart global services while student workflows may be active. Do not start actual malware samples or attach analysis VMs to the existing `default` NAT; separate containment gates remain.
- **Next validation:** Produce a single private Step10 post-run report with installer exit status if captured, log size/error summary, service active/enabled results, source revision, installed CAPE directory and timezone. Inspect raw logs for credentials before uploading; never commit raw machine reports or secrets. No user-uploaded completion report exists yet.

### Step 10 follow-up — Base installer ended with unresolved service failures (2026-10-08/09)

- **User-provided `SSL55_Step10_BaseAudit_20261008_223455_7bKUBQyO.txt`:** Installer output `~/cape2-base.log` is 286097 bytes / 4550 lines, ending `[+] cape2.sh - Done`; a separately captured `cape2-base.exitcode` shows `0`, though pipeline `tee` and capture timing can limit how strongly to interpret it. **Step 10 execution finished; do NOT mark operational installation PASS.**
- Installed project tree `/opt/CAPEv2` exists with `pyproject.toml` and is owned by `cape:cape`; active timezone **UTC** (upstream installer sets timezone globally). A read-only source revision check in `~/CAPEv2` was blocked by Git's `dubious ownership` security check; do not blindly disable Git security or chown system repositories.
- Services at audit: `cape-rooter` **active**; `cape`, `cape-processor`, `cape-web` **activating**, not confirmed healthy; `suricata` **failed**; `mongod.service` **not-found**. **IMPORTANT:** inspected upstream `cape2.sh` intentionally removes `mongod.service` and creates/starts **`mongodb.service`**; the report did **not** check this correct possible service name. MongoDB status remains **unknown**, not failed.
- Errors flagged in report: confirmed `suricata.service` startup failure, `dnspython 2.6.1` unable-to-uninstall / missing RECORD, unmatched `./conf/default/*.env` shell glob from installer config-copy loop, failed nonexistent `tor@default.service` stop, doc-base merge conflict and `upx` alternatives error. The keyword scanner also matched benign YARA signature filenames and compiler warnings; the count **15** is not 15 genuine independent failures.
- Upstream source examined: `kevoreilly/CAPEv2/installer/cape2.sh` blob `1bb76ccb84b5f67ca877ad863550b63687f51e37`. **Cannot assume user's edited copy matches upstream**; installer local SHA256 in the user's report recorded privately in [STEP10_BASE_POSTRUN_AUDIT.md](STEP10_BASE_POSTRUN_AUDIT.md). Upstream `base` includes wide apt/pip/service/systemd/cron changes and global timezone shift; don't rerun it as a blanket repair.
- **Next safe user step:** one consolidated, read-only Step 10B report checking `mongodb.service`, `suricata` failure's real journal cause, CAPE and PostgreSQL service states, installed DB packages, available CAPE config files, and relevant redacted installer-log snippets. Only fix specific root causes after report review, without interfering with shared student accounts.
- **Status: Step 10 post-run validation REVIEW REQUIRED.** Guest and host isolation, VM deployment and sample execution remain gated. [Detailed audit](STEP10_BASE_POSTRUN_AUDIT.md).

### Step 10B — Missing Windows VM explains CAPE/processor restarts (2026-10-08/09)

- **User-supplied read-only report:** `SSL55_Step10B_ServiceReview_20261008_223952_vDl4Vc9K.txt` (280 physical lines / 281 indexed). All configured CAPE files `cuckoo.conf`, `reporting.conf`, `routing.conf`, `auxiliary.conf` and `pyproject.toml` are present under `/opt/CAPEv2`; `/home/charan/CAPEv2` is root-owned and `/opt/CAPEv2` cape-owned. `conf/default` contained **zero** `*.env` templates, directly explaining the shell-glob `cp: cannot stat` message, not automatically a fatal absence of a required deployment secret.
- **Current services:** `mongodb.service` **active/running/enabled**, MongoDB 8.0.32 packages and `mongod` executable present; `mongod.service` missing is expected given upstream installer custom service replacement. `postgresql.service` active/exited (umbrella unit) and `pg_isready` accepted connections. `cape-rooter.service` and `cape-web.service` **active/running**. `cape.service` and `cape-processor.service` were in **activating/auto-restart** with `Result=exit-code`. `suricata.service` **failed**, while Suricata binary and Ubuntu package `7.0.17` present.
- **Root cause for two service restarts from journals:** CAPE and CAPE Processor both repeatedly fail with `CuckooStartupError: Error checking snapshot state for VM 'cuckoo1'`, libvirt `Domain not found`. Step 9 `virsh list --all` returned no VMs. **This particular failure is expected at this incomplete setup stage**: Windows `cuckoo1` VM and its required snapshot have not been built. Configure the first Windows guest, attach it only to a separately isolated, independently verified analysis network, and reconcile CAPE VM name/snapshot configuration before treating the daemons as healthy. Do not try to hide errors with service restarts.
- **Other findings:** `cape-web.service` is **currently active**, although its bounded journal also contains an **earlier PostgreSQL duplicate-type constraint violation** (`pg_type_typname_nsp_index`). Note historical initialization race/error and retest when all guests configured; do not infer a persistent database failure. `suricata.service` journal shows exit-code failure, but the **root error is not visible** in the filtered report; diagnose independently at a convenient later step, do not assume creating the VM will repair Suricata.
- **Dependency/install nuances:** Installation log had `dnspython 2.6.1` missing RECORD uninstall conflict; MongoDB nonetheless runs, but the global pip packaging inconsistency remains a portability issue. Root-owned original git checkout permitted **bounded read-only** `git -c safe.directory=<exact root>` revision lookups with return code 0, without globally disabling safe.directory; hashes were automatically redacted by report. No user host configuration changes in Step 10B.
- **Decision:** User reasonably expects **CAPE/processor missing-`cuckoo1` errors** to disappear after completing the Windows guest + snapshot + CAPE machine configuration; they need not block **safe onward setup**. This expectation **does not** resolve the independently failed Suricata service or prove network containment. **Step 10B read-only service diagnosis COMPLETE**; CAPEv2 overall runtime still **PARTIALLY CONFIGURED**. Do not rerun `cape2.sh base`. Next user document command should be reviewed before execution; avoid attaching sample VMs to the transient NAT `default` network or running real malware.
- Detail: [STEP10_BASE_POSTRUN_AUDIT.md](STEP10_BASE_POSTRUN_AUDIT.md).

### Step 11 — Poetry and optional Python dependency installation evidenced (2026-10-08/09)

- **User-pasted 663-line terminal transcript:** `cd /opt/CAPEv2`; `sudo apt install python3-poetry -y` installed Ubuntu Noble's `python3-poetry 1.8.2+dfsg-1ubuntu2` plus **23 packages**, then `poetry run pip3 install -r extra/optional_dependencies.txt` reported successfully built 14 wheels and ended `Successfully installed ...` and normal terminal prompt. **Do not rerun either command without evidence of a failure.**
- **Environment nuance:** The optional `pip3` run created `/home/charan/.cache/pypoetry/virtualenvs/non-package-mode-...-py3.12`. Thus optional Python requirements are installed in `charan`'s Poetry environment; **not yet confirmed** visible to `cape`'s running services. Upstream CAPE and processor systemd units specify `User=cape` with `ExecStart=/etc/poetry/bin/poetry run python ...`. Verify the **actual SSL-55 unit contents and distinct Poetry envs** read-only before altering Python dependencies.
- The Ubuntu packaged Poetry 1.8.2 may coexist with a separately installed `/etc/poetry/bin/poetry`. Presence of one executable and `Successfully installed` does not prove the service virtualenv has the same packages. Do not conflate the two interpreters; do not change host service account or force bulk reinstallation.
- **Status:** Step 11 reported install success **in a new charan virtualenv**, service-runtime integration **pending one read-only environment check**. Existing first Windows VM dependency and Suricata service issue from Step 10B remain separate. [Detailed record](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

### Step 11A — Different Poetry executables and `cape` runtime unresolved (2026-10-08/09)

- **User-executed read-only report:** `SSL55_Step11_PoetryEnv_20261008_224841_GcnbGnfH.txt` (39 physical lines / 40 indexed). This check did **not** install any package, restart services, alter networking or run VMs.
- **Two distinct Poetry commands:** `command -v poetry` gives `/usr/bin/poetry`, **version 1.8.2**; separately `/etc/poetry/bin/poetry` exists, **version 2.5.1**.
- **Local real systemd unit properties:** `cape.service` and `cape-processor.service` have `User=cape`, `WorkingDirectory=/opt/CAPEv2`, and use **`/etc/poetry/bin/poetry`** in ExecStart. `cape-web.service` likewise runs under `cape` and `/etc/poetry/bin/poetry`, with `WorkingDirectory=/opt/CAPEv2/web`. This is verified locally, not just guessed from upstream.
- **`charan` Poetry virtualenv:** `/home/charan/.cache/pypoetry/virtualenvs/non-package-mode-t2x27zRb-py3.12` is usable; package metadata confirms `ImageHash=4.3.2`, `deepdiff=9.1.0`, `binGraph=3.3.2`, `HTTPReplay=0.3`, `Socks5man=0.3.0`, `pyattck=7.2.1`. These packages are therefore **confirmed only in charan's environment**.
- **`cape` environment query:** Prior script attempted `sudo -n -u cape -H /etc/poetry/bin/poetry -C /opt/CAPEv2 env info --path` with **stderr suppressed**. It printed `No usable cape Poetry environment identified.` Crucially, this is **not proof no `cape` Python environment exists**: command could have failed due to invocation/configuration/access, returned an empty path because a system interpreter is used, or returned a path that lacked a usable Python file.
- **Decision:** Step 11 optional dependency pip command **completed successfully for the charan environment**. CAPE's service runtime / optional dependency availability is **UNDETERMINED**, not installation failure. **Do not reinstall Poetry or bulk optional dependencies**, do not point services to charan's private venv, and do not run a mutation-capable `poetry run` just to inspect. Next perform a short read-only Step11B that surfaces the cape Poetry `env info` output/exit status and venv preference explicitly; then inspect actual interpreter/package metadata if identifiable.
- Existing incomplete Windows guest `cuckoo1` and separately failed Suricata remain unchanged and must not be confused with this dependency provenance issue. [Step11 dependency record](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

### Step 11B result — CAPE service Python environment exists and is valid (2026-10-08/09)

- **User-uploaded read-only report:** `SSL55_Step11B_CapePoetry_20261008_225117_5lyCTb4w.txt` (54 physical lines, 55 line-indexed). The earlier Step 11A diagnostic misleadingly emitted `No usable cape Poetry environment identified` due to suppressed failure/ambiguous output. **That earlier unknown is now resolved.**
- **Verified actual `cape` runtime:** `sudo -u cape -H /etc/poetry/bin/poetry -C /opt/CAPEv2 env info` exited **0** and reported **Python 3.12.3**, `Virtualenv Valid: True`, `Path: /home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12`, `Executable: .../bin/python`. `env info --path` and `env info --executable` independently returned the same locations with **0** exit codes. `cape` account home `/home/cape/`, login shell `/bin/bash`.
- **Configuration:** `virtualenvs.create=true`, `virtualenvs.in-project=null`; `/opt/CAPEv2/.venv` and `.venv/bin/python` **missing by design/selection**, not a failure, because a valid user-cached virtualenv was found; project `poetry.lock` present and cape-owned. The standard `/usr/bin/poetry` is **1.8.2**, service Poetry `/etc/poetry/bin/poetry` **2.5.1**.
- **Distinction:** Prior unprivileged `poetry run pip3 install -r extra/optional_dependencies.txt` under `charan` installed selected optional modules in `/home/charan/.cache/pypoetry/virtualenvs/non-package-mode-t2x27zRb-py3.12`, **not proved present** in the now-identified `cape` environment. Do **not** reinstall the environment, re-run `cape2.sh base`, change systemd service users, or point CAPE to `charan`'s private environment.
- **Next concise check:** Read-only `importlib.metadata.version` in exactly the `cape` environment as user `cape` for optional packages (e.g., ImageHash, deepdiff, binGraph, HTTPReplay, Socks5man, pyattck), preserving command exit code; no pip action before a missing dependency is demonstrated. Step 11B **PASS**, optional dependency parity **UNVERIFIED**; prior Windows guest `cuckoo1` missing and unrelated Suricata service failure remain separate.

### Step 11C — Python path found; wrong account used for executable check (2026-10-08/09)

- User-uploaded read-only 9-line `SSL55_Step11C_OptionalDeps_qKKlJkJa.txt` shows Poetry env discovery **exit 0** and the `cape` Python at `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python`; no installations/restarts/changes.
- The assistant's Step11C script made a **privilege-context error**: checking `[ -x "$CAPE_PY" ]` under `charan` can fail to traverse `cape`'s private home even when interpreter runs fine as `cape`. This false-negative skipped all package checks, and **must not be treated as an invalid or absent CAPE environment**. The earlier Step11B report showed `Valid: True`.
- Plan short read-only Step11D to execute `test -x` and package metadata via sudo under the service account `cape`, without changing home directory permissions, reinstalling Poetry, or modifying services. Optional dependency availability remains **UNVERIFIED**. [Step11 record](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

### Step 11D — Optional dependencies missing from cape service Python (2026-10-08/09)

- **User-uploaded read-only proof:** `SSL55_Step11D_ActualCapeDeps_LWm6SH8R.txt` (13 physical lines/14 indexed). `sudo -u cape -H /etc/poetry/bin/poetry -C /opt/CAPEv2 env info --executable` **exit=0**; service-account `test -x` **PASS**; interpreter **`/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python`** ran a read-only `importlib.metadata.version` check, **exit=0**.
- **All six sampled optional packages reported NOT INSTALLED in the actual cape environment:** `ImageHash`, `deepdiff`, `binGraph`, `HTTPReplay`, `Socks5man`, `pyattck`. They were previously confirmed INSTALLED in `charan`'s different virtualenv after the user ran `poetry run pip3 install -r extra/optional_dependencies.txt` under `charan`. **Do not generalize this six-package sample to every optional or core dependency.**
- **Interpretation:** The `cape` venv is **valid and executable**, not corrupted; optional-package installation succeeded in the **wrong account's environment** for CAPE services. The six tested optional capabilities will need an explicit compatibility-checked installation into cape's venv if required. **This gap is NOT the cause of the proven missing-cuckoo1 libvirt VM startup error**.
- **Decision:** No immediate bulk install, no rerun `cape2.sh base`, no Poetry reinstall, no copying `charan`'s venv or opening `/home/cape` permissions. Preserve progression through remaining non-malware manual setup, especially first VM with independent isolated network and snapshot. Before claiming all optional processing capabilities, compare `/opt/CAPEv2/poetry.lock`, actual cape Python package metadata and version compatibility of `extra/optional_dependencies.txt`, then install only needed compatible packages as `cape` in the verified venv and re-test. Avoid inadvertent changes to core pinned versions.
- **Status:** Step 11D **PASS as diagnostic**; service-runtime optional dependency parity **FAIL for six sampled packages**, optional capabilities **PENDING**, no packages installed/no service changes in audit. Detailed record: [STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md](STEP11_OPTIONAL_PYTHON_DEPENDENCIES.md).

## Automation status after Steps 1–7

- `scripts/check_host_virtualization.sh` is an early **read-only draft** for Steps 1–3.
- `scripts/bootstrap_cape_source.sh` is a separate **Git/source bootstrap draft** based on Step 4; it would modify a host **only if intentionally executed** as an installer component. It is not one of the three final commands and is not yet release-ready.
- The user reported CAPEv2 **source clone, nine-variable installer edit, libvirt package installation and CAPE installer settings**, not CAPEv2 runtime installation. No Windows VM, INetSim VM, isolated network or full three-command deployment automation has been installed or validated as part of this canonical build.
- `scripts/prepare_acpi_replacements.py` is an early **conditional** draft: inspection is read-only and mutation requires `--apply`, reviewed values and source pin. It is not validated on SSL-55.
- `scripts/audit_libvirt_cape_network.py` is a **read-only** Step 6 diagnostic draft with 11 synthetic tests passed. It deliberately does not assert malware-ready isolation.
- `scripts/audit_kvm_build_step7.py` is an early read-only Step 7 user/build-log verifier; it must not be mistaken for a safe deployment wrapper. The source installer run reported failures and has no fully verified success status.
- **Do not** run installation or environment changes on SSL-55 without explicit user direction.
- Next manual step is chosen and executed by the user.

### Step 7F follow-up — CAPEv2 installation permission clarified (2026-10-09)

- The user explicitly states that **CAPEv2 installation using the `charan` login is permitted**, and they have performed CAPEv2 installations under that login on other college machines. Treat installing CAPEv2 as an allowed project activity; do **not** repeatedly ask for the same installation permission or assume CAPEv2 installation itself is prohibited merely because other student logins exist.
- This permission does **not automatically establish approval for unattended **system-wide** power target changes, coordinated reboot timing, disruption of active student sessions, external network redirection, or live malware execution. Continue one verified **user-executed** manual step at a time with safe preflight, narrow backups, reports, and the `development` branch only.
- Existing persistent four-target power masks remain unchanged pending workstation policy decision; boot-time KVM and analysis-network safety are still unverified. Distinguish CAPEv2 installation/development from live malware execution: **no real samples on unisolated `default` NAT or institution LAN**.
- Next useful question: whether SSL-55 will be used only to install/test the platform, or whether live samples are intended. That determines the required containment environment and whether a dedicated authorized malware lab must be involved.

## Step 12 — Windows analysis ISO source selection and third-party archive download (2026-10-09)

- **User action:** Navigated to `https://windowsxlite.com/26H1Pro_V2`, followed its download link to `https://pixeldrain.com/u/ZdPxkVmH`, and **started downloading an archive**. User described it as a ZIP; the publisher's direct file label is **`[Windows X-Lite] Optimum 11 26H1 Pro v2.7z`**, so treat it as a **7z archive** until the downloaded file's actual signature is checked. **No completed download, extraction, verified ISO, VM creation, OS installation, guest boot, snapshot, or analysis network connection has yet been reported.**
- **Publisher claims:** Windows X-Lite Optimum 11 **26H1 Pro v2**, based on Windows 11 **Canary 28000.1**, advertised ~2.4 GB ISO; modified/debloated distribution with optional Defender, removed SmartScreen, disabled UAC and other changes, paused automatic updates. These are **publisher assertions**, not independent security attestation. Product page: `https://windowsxlite.com/26H1Pro_V2`; direct publisher-linked archive: `https://pixeldrain.com/u/ZdPxkVmH`.
- **Compatibility gate:** Upstream CAPEv2 guest creation guidance recommends **Windows 10 or Windows 11 23H2**. The user's 26H1 Canary-based third-party modified build is outside that recommendation; no verified CAPE instrumentation compatibility or trust provenance. Do **not** automatically download/extract/boot this modified image for the canonical VM. Prefer an authentic, supported/licensed Microsoft Windows image, with Windows version selected against CAPE monitor support; official Microsoft Windows 11 x64 ISO page is `https://www.microsoft.com/en-in/software-download/windows11`.
- **Next safe manual step:** Wait for archive download completion. Before extracting, inspect archive filename, size, file type/magic, SHA-256, member listing and uncompressed sizes/path names using read-only diagnostics. A local SHA alone proves only file identity/integrity against a *trusted reference*, not that a third-party modified OS is safe; the Pixeldrain page does not establish Microsoft authenticity. Do not open included EXEs/scripts, install extra tools from the archive, write USB boot media, or install Windows onto SSL-55's actual host disk.
- **Network safety:** No guest attached to libvirt's `default` NAT. Dedicated lab-only, nonforwarding network and verified IPv4/IPv6 containment must precede malware execution.
- **Status:** Step 12 download **STARTED, media authenticity/compatibility not approved, no VM provisioned**. Record deterministic archive provenance and safe inspection in GitHub automation; any guest OS install action remains pending exact trusted media and reviewed VM/network plan.

### Step 12 automation added — inspect downloaded media without executing it

- `scripts/inspect_windows_media.py` (and `scripts/command1_pre_vm.sh inspect-media FILE`) offers a **read-only, non-extracting** SHA256, file size, extension and magic/signature report for an explicitly selected *completed* downloaded archive or ISO. Output is a private 0600 JSON report. Files ending in `.crdownload`/`.part` are refused. SHA256 identifies file bytes but does not attest Microsoft authenticity or confirm the OS is safe.
- Synthetic tests: `scripts/test_inspect_windows_media.py` covers 7z/ZIP magic, hashes, partial downloads, symlinks, empty files and non-authenticated ISO names. GitHub Actions workflow runs it on `development`. **No ISO or ZIP has been inspected on SSL-55 yet, and no actual guest has been installed.**

### Step 12 source decision — official Microsoft x64 Windows 11 ISO selected (2026-10-09)

- **User decision:** Discontinue the candidate third-party Windows X-Lite build for the first CAPEv2 Windows guest and download the **official Microsoft Windows 11 multi-edition ISO for x64 devices**, from `https://www.microsoft.com/en-in/software-download/windows11`. User provided a screenshot showing this official URL, the selected `Windows 11 (multi-edition ISO for x64 devices)` entry, and the available `64-bit Download` button. The user intends to start the official ISO download. **Download completion, actual filename, size and SHA-256 are not yet evidenced; no guest exists yet.**
- **Next checks:** Wait until download completes; verify it is a genuine ISO file and compare its local SHA-256 against Microsoft's **own published download verification** details for the *same* ISO. Preserve download source, digest, exact OS/build once identified, and accepted licensing/media evidence in private deployment manifest. SHA-256 without a trusted publisher-provided digest is only an identifier.
- **Deployment:** Use original ISO directly in libvirt VM setup; do not extract it. First VM requires appropriately configured UEFI/TPM if demanded by the image, correct CAPE guest tooling and an isolated, verified non-NAT, non-forwarding analysis network. Do not select `default` NAT or run malware while guest isolation is unverified.
- **Automation consequence:** Continue development of parameterized media path + hash verification + approved-source provenance; never hardcode a time-limited Microsoft download URL or a specific release/build. Existing `scripts/inspect_windows_media.py` hashes completed files read-only; it **does not independently authenticate Microsoft origin**.

### Step 12A — User reports official Microsoft ISO downloaded as Win11.iso (2026-10-09)

- User reports completing the Microsoft Windows 11 x64 ISO download and **renaming the file to `Win11.iso`**. This is a user report; actual file location, byte size, file type, local SHA-256, Microsoft-published SHA-256 comparison, and exact guest OS build are **not yet independently verified**. A filename change does not modify ISO contents.
- Assistant supplied one complete read-only Ubuntu `bash` check to search `$HOME` (up to 5 levels) for exactly one `Win11.iso`, record absolute path, size/format (`file`), ISO9660 primary volume descriptor marker `CD001` at byte offset 32769 and SHA-256 into one private `SSL55_Step12_Win11_ISO_....txt`. **The user has not executed/uploaded this check yet.**
- The portable GitHub automation `scripts/inspect_windows_media.py` and synthetic fixture `scripts/test_inspect_windows_media.py` were extended to probe the ISO9660 `CD001` marker and confirm file stability during hashing; the result always remains `trust_status=UNVERIFIED` until the exact ISO is compared against trustworthy Microsoft-published checksum information. No extraction/mount, ISO execution, VM creation or networking changes.
- **Next:** Wait for the user-uploaded Step12A verification TXT and compare the SHA-256 to Microsoft's verification details for that downloaded file. Only afterwards plan the first `cuckoo1` VM, guest UEFI/TPM, snapshot and dedicated non-forwarding analysis network; do **not** attach it to the libvirt `default` NAT for malware testing.

### Step 12A — Microsoft official English x64 checksum verified (PASS, 2026-10-09)

- **User-generated, read-only TXT evidence:** `SSL55_Step12_Win11_ISO_20261009_064011_F2EC2TtU.txt`. It located **exactly one** `Win11.iso` at `/home/charan/Downloads/Win11.iso`, regular file owned by `charan`, **9,047,330,816 bytes** (8.43 GiB), `file` identifies a **bootable ISO 9660 CD-ROM image** with volume identifier `CCCOMA_X64FRE_EN-US_DV9`; the primary volume descriptor contains **`CD001`**. No guest created, ISO mounted, files modified or services restarted.
- **Locally calculated SHA-256:** `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`.
- **Independently retrieved Microsoft SHA-256 table:** Microsoft's **Windows 11** download page, `https://www.microsoft.com/en-in/software-download/windows11`, under **Verify your download / English 64-bit**, lists the exact same **`BD4307DF32BC8AF33B39CCECB1174AEB345386630F89A2B86C7A4E36B55EA650`**. The official page's published verification instructions say a matching SHA-256 confirms the downloaded file was not altered relative to Microsoft's ISO. This is an **exact digest match**; hash provenance was independently checked against Microsoft's site in this session. Microsoft page may change as releases rotate; record digest with this verification date rather than silently using for unrelated later ISO versions.
- **Outcome:** **Step 12A ISO acquisition, bootable media signature, size, and Microsoft checksum verification PASS.** No need to download, rename, hash or revalidate this exact unchanged ISO again.
- **Separate pending task:** CAPEv2 agent/monitor guest build compatibility, Windows licence, resource allocations, UEFI/TPM, snapshot naming, and dedicated **nonforwarding analysis network** with proven IPv4/IPv6 containment. Do not connect malware-analysis guests to libvirt's default NAT network or run live malware before isolation tests. The ISO is verified; **the Windows VM and malware environment are not yet installed or certified**.

## Step 12B — Windows VM resource and libvirt preflight report (2026-10-09)

**Evidence:** User uploaded `SSL55_Step12B_VMPreflight_20261009_064559_5K3Vyjwp.txt`, produced by a read-only command. It did **not** create VMs, change networks, install packages, restart services, or modify the ISO.

### Confirmed host and virtualization results

- Intel Core **i9-13900 (13th Gen)**, `x86_64`, **32 logical CPUs** (`nproc=32`), Intel **VT-x**. Do not interpret 32 as physical core count.
- `free -h`: **62 GiB total RAM**, **56 GiB available**, **8 GiB unused swap**.
- Both `$HOME` and `/var/lib/libvirt/images` currently reside on root filesystem with **289 GiB free** (937 GiB total; 601 GiB used). This is enough for an initial proposed virtual disk, but multi-VM capacity/snapshot growth requires further budgeting.
- `virsh`, `virt-manager`, `virt-install`, `qemu-system-x86_64`, `qemu-img` all **present**; **`swtpm` absent**. OVMF UEFI code/variable firmware files **present** under `/usr/share/OVMF/`, including `OVMF_CODE_4M.fd`, `OVMF_CODE_4M.secboot.fd`, `OVMF_VARS_4M.fd`.
- `virsh -c qemu:///system version`: libvirt **11.1.0**, QEMU hypervisor **9.2.2**. `libvirtd.service` **inactive/dead** while **`virtqemud.service` active/running**; modular daemon functioning, so legacy unit inactive alone is **not** a virtualization failure.
- `virsh list --all`: **zero defined guests**. `cuckoo1`: **not found or not accessible**, consistent with earlier CAPE/processor restart root cause.
- `virsh net-list --all`: `default` **active, autostart YES, persistent YES** (**changed from earlier observed transient default network**, not an error). Actual XML `forward mode=nat`; default NAT remains **UNSAFE for live malware analysis**, not proof of isolation.

### Required preparation at the user's next manual VM steps

1. **Windows 11 TPM:** `swtpm` executable is **not found**; validate/provision software TPM 2.0 using a compatible supported package as part of the reviewed Windows VM configuration. Do not automatically bypass Windows 11 TPM requirements or alter host firmware.
2. **ISO permissions:** Verified Microsoft ISO is `/home/charan/Downloads/Win11.iso` (**9,047,330,816 bytes**, official SHA256 PASS in Step12A). `/home/charan` has `drwxr-x---` (0750) and `Downloads` 0755; therefore a libvirt/QEMU service account **may** be unable to traverse the home directory. The actual QEMU process UID/GID and file access have **not** been tested; review at the time of guest creation. Prefer controlled ISO staging to a libvirt-accessible storage area; **do not chmod /home/charan globally** or weaken home confidentiality.
3. **Networking:** Create/validate a dedicated lab-only analysis network with no external NAT/host/institution LAN path; do not attach a malware-analysis guest to the `default` NAT bridge. Guest-side IPv4 and IPv6 negative egress plus host forwarding/firewall policy must pass before handling real malware.
4. **Resources and snapshot:** Choose VM vCPU/RAM/disk with reserve for host, additional Windows guests and INetSim; guest EFI/TPM, CAPE agent/monitor, and snapshot correctness require separate verification.
5. **Services:** The previously identified unrelated Suricata startup failure and six missing optional modules in `cape` Python are still independent follow-ups; do not rerun base installer merely because `cuckoo1` is absent.

**Diagnostic conclusion:** Windows VM hardware/virt-stack preflight **PASS**, pending media access, software TPM, safe network and VM definition. **No more generic host diagnostics needed before user shares the next VM command from their document.**

### Automation

Added `scripts/audit_windows_vm_preflight.py` and synthetic tests `scripts/test_audit_windows_vm_preflight.py` to `development`, integrated via `scripts/command1_pre_vm.sh preflight-windows [--iso ABSOLUTE_PATH]`. This is **read-only**, writes one private 0600 JSON report, identifies NAT/TPM/ISO access-review issues, and never marks malware containment verified. It is **not a provisioning/guest installer**, has **not been run on SSL-55**, and does not replace user-executed Step12B evidence.

## Step 12C — GUI guest creation underway; Windows 11 Pro selected as recommended edition (2026-10-09)

**Evidence:** The user supplied twelve sequential screenshots from virt-manager's New VM wizard and Windows Setup and explicitly says they clicked `Begin Installation`, then `I don't have a product key`. Current screen is **Windows Setup → Select Image** and shows multiple Windows 11 editions. No evidence yet of final Windows installation, activation, guest integration, or snapshot.

**Verified screenshot workflow:** virt-manager connected to `QEMU/KVM`; creation with **Local install media**, selected ISO `/home/charan/Downloads/Win11.iso` (SHA256 already verified against Microsoft in Step12A), detected OS `Microsoft Windows 11`; virtual RAM **4096 MiB**, **4 vCPUs**, **64 GiB** disk (`/var/lib/libvirt/images/win11.qcow2`); proposed guest name **`win11`**, **Q35** chipset, firmware **UEFI**. The user enabled **Customize configuration before install**, showed full VM details including a NIC, then **clicked Begin Installation**. Screenshot proves Windows installation media booted, language US English and US keyboard selected, chose to install (not repair), proceeded past product-key prompt via **I don't have a product key**, and reached edition choice. The user has not yet reported selecting an edition or installing Windows.

**Critical observed issue:** Creation wizard explicitly shows `Network selection: Virtual network 'default': NAT`, with active NIC in hardware list. Step12B verified that this network forwards by NAT and is persistent/autostart. Therefore **the guest is not isolated**, and the production malware-analysis safety gate remains **BLOCKED**. Booting official Windows Setup is not itself malware execution, but the guest NIC must be disconnected/isolated before using it as a CAPE sandbox. Prefer disconnecting its NAT interface before progressing and use a subsequently validated dedicated nonforwarding network; do not alter the shared host's `default` network globally or run any samples until IPv4+IPv6 containment testing passes.

**Edition choice:** Assistant recommended **standard Windows 11 Pro (non-N)**, not Windows 11 Home/Education or their N variants, for guest administration/management feature availability and fewer missing media components; this is a deliberate practical recommendation, not a CAPE documentation guarantee. User to select Pro and proceed after network review. `I don't have a product key` allows installation to continue, but a legitimate license remains required for activation and licensing compliance. Do not advise bypassing TPM/secure boot checks.

**Other implementation flags:** `win11` conflicts with existing CAPEv2 machinery expectation **`cuckoo1`** (Step10B): decide whether to rename guest before final machine registration or deliberately update CAPE config in a traceable manner. Step12B found `swtpm` missing and OVMF present; VM can boot installer, but full Windows 11 TPM/compliance has not yet been established. Verify QEMU user ISO access, EFI/TPM if required, guest snapshot, monitor compatibility after Windows installation. Do not presume the guest ISO is currently unreadable: Setup demonstrably launched.

**Automation gap:** GUI screenshots provide a **provisional parameter set only**; do not canonize unsafe `default` NAT, the premature `win11` name, or an unverified missing TPM as desired portable defaults. Draft future `virt-install` flow must create correct guest naming, domain disk, guest device support and a verified isolated network, with successful installer boot and snapshot checks.

## Step 12D — Windows 11 Pro selected, TPM 2.0 requirement blocks Setup (2026-10-09)

- **User-provided screenshots:** Windows Setup **Select Image** page highlights **Windows 11 Pro (non-N)**; after continuing, Setup reports **`This PC doesn't currently meet Windows 11 system requirements`** because **`The PC must support TPM 2.0.`**. Windows OS installation is **BLOCKED at requirements check**; no evidence of installed desktop, snapshot, successful boot, or CAPE guest instrumentation. This is consistent with the Step12B preflight that `swtpm` was not found on SSL-55.
- **User preference:** Preserve libvirt guest name **`win11`**. Do **NOT** rename the VM to `cuckoo1` without user approval. Before CAPE integration, deliberately align CAPE KVM machinery guest identifier, IP/snapshot configuration to `win11`, rather than assuming the old sample configuration is correct. No guest integration edits have been performed yet.
- **Recommended recovery (not yet executed):** Shut off the `win11` guest **while Windows is still at the uninstalled setup page**, perform limited Ubuntu package installation `sudo apt-get install -y swtpm swtpm-tools`; check `swtpm --version` and presence of `swtpm_setup`. In virt-manager with the guest **powered off**, click hardware details → Add Hardware → TPM → **Emulated** backend, **TPM version 2.0** and supported TIS/default model → Finish; restart the installer, select Windows 11 Pro and confirm requirements check is passed. Use guest emulated TPM rather than registry bypass. No blanket QEMU reinstall or host firmware modifications. Installing new packages can affect host state and still requires the user's terminal execution.
- **Portable automation:** Existing `scripts/bootstrap_virtualization_stack.sh` was expanded to include the missing Ubuntu package `swtpm-tools` alongside `swtpm`, preserving package-manager simulation and explicit-apply semantics. `scripts/audit_windows_vm_preflight.py` now checks both `swtpm` and `swtpm_setup`. Pending reproducible VM definition must provision emulated TPM 2.0, persist TPM state separately from VM storage and include TPM state in reliable rollback/rebuild/snapshot plans. Neither Ubuntu package installation nor TPM XML change has been executed by the assistant on SSL-55.
- **Status:** Windows 11 Pro selected, guest `win11` is currently at Setup's TPM2 blocker. Await user's package installation outcome/TPM addition before progressing.

## Step 12E — swtpm and swtpm-tools installed on SSL-55; emulated TPM pending (2026-10-09)

- **User-executed terminal evidence:** `sudo apt-get install -y swtpm swtpm-tools` completed. Ubuntu packages **`swtpm=0.7.3-0ubuntu5.24.04.1`**, **`swtpm-tools=0.7.3-0ubuntu5.24.04.1`** installed, `0 upgraded, 2 newly installed, 0 to remove`. Package manager printed `146 not upgraded` and a suggestion to `apt autoremove`; these are not installation failures. Do **not** automatically run `apt autoremove` on this shared host.
- `swtpm --version` returned **`TPM emulator version 0.7.3`**, exit implied by return to shell. The `swtpm_setup` executable was not independently queried, but successful swtpm-tools dpkg configuration supports installation; runtime check can be performed only if necessary.
- **GUI:** User screenshot shows existing `win11` domain **`Shutoff (Destroyed)`**, chipset `Q35`, firmware **`UEFI`**, and the **`Add Hardware`** button at lower left. TPM does **not** yet appear in the sidebar, confirming addition still pending at this screenshot. No Windows desktop or successful Windows installation yet.
- **Exact next manual GUI procedure:** With `win11` **powered off**, virt-manager domain details → bottom left **Add Hardware** → select **TPM** → **Type: Emulated**, **Version: 2.0**, compatible model **TIS** (or supported default) → **Finish**. User should provide resulting TPM settings screenshot before restarting Windows Setup.
- **Automation requirement reaffirmed:** The already committed `scripts/bootstrap_virtualization_stack.sh` on `development` **includes both packages `swtpm` and `swtpm-tools`** in the missing-package inventory, APT simulation, opt-in `--apply` install and postinstall dpkg verification; `scripts/audit_windows_vm_preflight.py` checks `swtpm` and `swtpm_setup`. Ensure later first-Windows-VM provisioning code defines **emulated TPM 2.0** and manages persistent TPM state; no unattended VM XML changes or boot have been coded/verified yet.
- **Status:** Step12E host TPM packages **INSTALLED/VERIFIED by user**, first guest virtual TPM **PENDING**, Windows 11 TPM installation blocker expected to clear only after device is added and guest setup re-tested.

## Step 12F — Emulated TPM 2.0 added; swtpm_setup fails before win11 starts (2026-10-09)

- **User GUI evidence:** Existing `win11` guest remains shut off. Hardware list now explicitly includes `TPM v2.0`. Virt-manager TPM details show **Type: Emulated**, **Model: TIS**, **Version: 2.0**, confirming the correct user-selected software TPM device has been attached. The user attempted to start installation after adding it.
- **Exact startup error from screenshot:** `Error starting domain: internal error: Could not run '/usr/bin/swtpm_setup': exitstatus: 1; Check error log '/var/log/swtpm/libvirt/qemu/win11-swtpm.log' for details.` Virt-manager popup also shows generic Python traceback but the **actual underlying error is not visible**. No basis yet to attribute failure to AppArmor, permissions, missing libraries, certificates, malformed state, setup flags, or libvirt build mismatch. TPM packages `swtpm` and `swtpm-tools` were previously confirmed installed on the host.
- **Interpretation:** VM boot is **blocked during TPM state provisioning**, before guest Windows installer restarts. Do **not** delete/recreate VM, purge/reinstall packages, chown libvirt directories, disable AppArmor, delete TPM state, bypass TPM 2.0 or keep retrying without reading the referenced log.
- **Read-only next diagnostic supplied to user:** `sudo -v`; read package versions and `swtpm_setup --version`; extract only `<tpm>` libvirt domain XML, read **last 100 lines of the exact swtpm startup log**, inspect only directory permissions and modular `virtqemud` state/recent journal; save one private `SSL55_Step12F_TPM_Error_....txt`. User to upload report after inspecting for sensitive details. Nothing about the TPM error has yet been independently verified beyond the screenshot, since the log has not yet been supplied.
- **Automation:** Added portable read-only `scripts/diagnose_swtpm_startup.sh [VM_NAME]` under `development` (default `win11`). It collects this TPM-specific evidence without executing `swtpm_setup` or modifying host/guest; outputs a private report for troubleshooting. The script has not been run on SSL-55, and a permanent auto-repair is **not implemented** pending root-cause proof. Added Bash syntax validation to existing GitHub Actions workflow.
- **User preference:** Keep libvirt name **`win11`**; do not rename to `cuckoo1` without consent.
- **Status:** Step12F **BLOCKED**, awaiting `win11-swtpm.log` diagnostic before recommending a targeted fix. No Windows guest installation success/snapshot yet.

## Step 12F root cause — swtpm_localca tss cannot access local CA state (2026-10-09)

- **User-uploaded report:** `SSL55_Step12F_TPM_Error_20261009_070551_JYKNsXsM.txt` (117 indexed lines). **win11 shut off**; `libtpms0=0.9.3-0ubuntu4.24.04.1`, `swtpm=0.7.3-0ubuntu5.24.04.1`, `swtpm-tools=0.7.3-0ubuntu5.24.04.1`, all `install ok installed`. `/usr/bin/swtpm`, `/usr/bin/swtpm_setup` run/return version 0.7.3. Local libvirt domain XML **`<tpm model="tpm-tis"><backend type="emulator" version="2.0"/></tpm>`**. No TPM package reinstall or guest TPM replacement required on these facts.
- **Root-causing log:** `/var/log/swtpm/libvirt/qemu/win11-swtpm.log` contains **six repeat initialization failures** on 2026-10-09 07:02–07:04. Each successfully creates EK but `swtpm_localca` fails with **`Need read/write rights on statedir /var/lib/swtpm-localca for user tss.`**, **`swtpm_localca exit with status 1`**, `An error occurred. Authoring the TPM state failed.` The immediate failure is **lack of effective read/write CA statedir access under user `tss`**. The large RSA key blobs/VM UUID and other host-private log details were intentionally **not committed to GitHub**.
- **What is still unknown:** Step12F report inspected `/var/lib/libvirt/swtpm` and its `win11` child (not found), **NOT `/var/lib/swtpm-localca`**. Thus whether the exact state path is absent, wrong-owner, wrong-mode, blocked by ACL/parent traversal, or contains shared existing CA files is **not established**. Do not blindly `chown -R`, `chmod 777`, delete CA files, recreate keys, add users to unrelated groups, disable AppArmor, or restart system-wide libvirt.
- **Additional independent journal messages:** `virtnodedevd-sock` unavailable in `virtqemud` journal and `win11` domain `tainted: high-privileges` are separate observations. Do not attribute this specific `swtpm_localca` permission failure to them without evidence. `virtqemud` remains active/running.
- **Reference:** Ubuntu Noble `swtpm-localca.conf(8)` documents `statedir` (local CA data and lock location) and `swtpm-create-tpmca(8)` documents user/group ownership. Independent historical upstream issue reproduces this exact `tss` statedir error: `https://github.com/stefanberger/swtpm/issues/642`.
- **Next minimal step:** One read-only targeted inspection of **exact** `/var/lib/swtpm-localca` `namei -l`, metadata/ownership, effective `sudo -u tss test -r/-w/-x` and top-level entry names/modes; outputs one private report. Only then decide narrowly permitted ownership/mode fix; if CA contains existing keys or shared guest records, coordinate and preserve them. Re-attempt `win11` boot only after approved correction. Added `scripts/audit_swtpm_localca_access.sh` and Bash syntax CI for this precise missing signal. No host change has yet occurred from this diagnosis.

## Step 12G — Empty local CA statedir owned swtpm:root:750 blocks tss (2026-10-09)

- **User-uploaded read-only report:** `SSL55_Step12G_LocalCA_NhLNHLJ5.txt` (22 indexed lines). `namei -l /var/lib/swtpm-localca` shows parent directories are `root:root` and traversable, but the exact swtpm local CA statedir is **`drwxr-x--- swtpm:root` (mode 750)**. Checks executed under **`tss`**: read **FAIL**, write **FAIL**, directory traverse **FAIL**. No direct child metadata listed (**appears empty**); earlier TPM log explicitly requests write access by `tss`.
- **Root cause established:** ownership and mode together deny `tss` access; this is not a missing swtpm package or malformed guest TPM XML. Existing CA contents were not displayed and no user-side changes yet occurred. Vendor's swtpm local CA config documentation describes this as the writable statedir and lock-file location.
- **Narrow correction supplied to user:** Only with **win11 shut off**, user `tss` existing, real non-symlink directory still **exactly `swtpm:root:750`**, and truly empty directory (including hidden files), change only that directory's owner via **`sudo chown --no-dereference tss:root /var/lib/swtpm-localca`**. **Retain group root and mode 750**; verify `tss` can read/write/traverse afterward. One private `SSL55_Step12H_TPM_Fix_....txt` report. This is a scoped metadata change to the shared host; no `-R`, `chmod 777`, CA key deletion, AppArmor/libvirt service edits or automatic VM boot. **Not executed on SSL-55 by assistant; await user-run verification.**
- **Automation committed:** `scripts/repair_swtpm_localca_owner.sh` implements default **`--plan`** and explicit **`--apply`** with matching safety gates and postconditions. It treats already-correct `tss:root:750` as no-op without altering existing CA files; requires empty directory before changing a wrong owner. Added Bash `-n` CI to `.github/workflows/pre-vm-audit.yml`. These offline checks do **not prove** real host ownership correction or successful swtpm initialization.
- **Status:** Step12G **DIAGNOSIS COMPLETE**; Step12H focused host-ownership correction **PENDING user execution**, followed by supervised `win11` boot and Windows Setup retry. Keep guest named `win11`; no guest OS install confirmed yet.

## Step 12H — tss local CA access repaired and verified (user executed, 2026-10-09)

- **User-uploaded output:** `SSL55_Step12H_TPM_Fix_I9Blmk9D.txt` (28 indexed lines). User executed the reviewed guarded shell block; `virsh domstate win11` returned **`shut off`**, and `tss` account was present. Before correction, exact local CA statedir metadata was **`swtpm:root:750`**.
- **Successful, narrow user-performed change:** nonrecursive **`sudo chown --no-dereference tss:root /var/lib/swtpm-localca`**. The resulting `stat` reports **Owner=tss, Group=root, Mode=750**. Under the `tss` account, **read PASS, write PASS, execute/traverse PASS**. The script printed `TPM directory access correction: SUCCESS`. No recursive change, files deleted, services restarted or VM started.
- **Interpretation:** The specifically diagnosed `swtpm_localca` CA statedir access failure has been corrected and verified for `tss`; **successful swtpm manufacturing, VM startup, Windows 11 Pro installation and snapshot remain unverified** until the guest is started and tested. There is no justification to rerun package install, chown recursively, remove virtual TPM files or create another domain.
- **Next reviewed manual GUI action:** In virt-manager open the existing **`win11`** (keep name), click the triangular **Start/Play** control once, return to Windows Setup display; if setup resumes, select ordinary **Windows 11 Pro** and proceed step by step. If libvirt reports a new error, capture screenshot/report instead of repeating arbitrary fixes. Watch for ISO boot chooser if boot does not directly enter Setup.
- **Automation:** `scripts/repair_swtpm_localca_owner.sh` already codifies the exact guarded ownership fix (default read-only `--plan`; explicit `--apply`, exact initial state, empty-directory gate, service-account postchecks). It was CI shell-syntax checked on `development`; the **equivalent manual correction is now proven on SSL-55**, while actual execution of the repository script and any repeatability on a clean machine are still not tested.
- **Status:** Step 12H manual fix **PASS**; subsequent `win11` boot/TPM certificate manufacture **PENDING**.

## Step 12I — QEMU cannot connect to TPM socket (permission denied) (2026-10-09)

- User retried the existing `win11` VM after the Step12H `tss` CA-directory ownership correction. Virt-manager now reports **`qemu-system-x86_64: -chardev socket,id=chrtpm,path=/var/run/libvirt/qemu/swtpm/9-win11-swtpm.sock: Failed to connect ... Permission denied`**. This is a **different startup-stage error** from `swtpm_localca` failure: swtpm initialization proceeded far enough for QEMU to attempt its Unix socket connection, but a complete guest boot is still not verified.
- **User-uploaded read-only Step12I:** `SSL55_Step12I_TPMSocket_4fBAmVKr.txt` (23 indexed lines). `namei -l /run/libvirt/qemu/swtpm` shows parent `/run/libvirt/qemu` **`root:libvirt 0755`**, TPM socket directory **`root:tss 0770`**. No `win11` socket file or running QEMU/swtpm processes remained after startup failure; no AppArmor DENIED lines surfaced in the queried kernel log, but this **does not exclude** AppArmor/sockets/security denial. Active qemu.conf user/group assignment was not found by the current read-only grep. Do **not** assume which UID QEMU uses or change group memberships broadly.
- Socket permissions at failure time were **not captured** (libvirt cleans up after failed start). The socket itself may have strict `0600` mode even if its containing directory can be traversed. Related issue: `https://github.com/stefanberger/swtpm/issues/840` documents non-root QEMU denied access to a mode-0600 swtpm socket. This is supporting precedent **not proof** of exact SSL-55 mechanism.
- **Next minimal step:** read-only service account / directory access test under likely `libvirt-qemu`, `qemu`, `tss`, qemu.conf `user`/`group` fields and AppArmor profile status. User given single-script `SSL55_Step12J_SocketAccess_XXXXXXXX.txt` instructions; matching `scripts/audit_swtpm_socket_access.sh` committed on **development** and Bash syntax CI added. No host state modifications. Identify effective QEMU user and confinement before any ownership/ACL, libvirt config or TPM socket changes.
- User requested fast remediation; avoid redundant scans but **do not** `chmod 777`, change tss ownership state or disable AppArmor globally just to make this guest start. Keep name `win11`.

## Step 12J — swtpm directory accessible to tss; QEMU account unresolved (2026-10-09)

- **User-uploaded read-only report:** `SSL55_Step12J_SocketAccess_dFsoA8TQ.txt` (66 indexed lines). There is no explicit uncommented `user/group` in `/etc/libvirt/qemu.conf` from the selected query. `getent`/`id`: **libvirt-qemu and qemu accounts not found**, but **tss exists as UID/GID 105**. **Do not infer** the effective QEMU process identity merely from absent accounts; process startup policy and dynamic security driver remain unknown.
- `/run/libvirt/qemu/swtpm`: **root:tss 0770**, parents `/run/libvirt/qemu` are traversable by others, and `sudo -u tss test -r/-w/-x` all **PASS**. Thus changing this directory's ownership/mode is not presently justified. No socket remained when inspected after failed startup; socket file owner/mode **at connection time** remain unknown.
- AppArmor module **loaded**, 228 profiles, 129 enforced, but the supplied top-of-list `aa-status` output does **not identify win11's generated per-domain AppArmor profile**; prior kernel-journal grep had no explicit DENIED lines. Absence of such excerpts does **not prove** AppArmor is uninvolved. The libvirt developers described a **matching /var/run vs /run AppArmor socket-path mismatch** in 2025 (`https://lists.libvirt.org/archives/list/devel@lists.libvirt.org/thread/GF4A5L5FYG4XRF552EFKKNGKSAFP75LP/`); swtpm #840 documents a separate socket permission/mode 0600 case (`https://github.com/stefanberger/swtpm/issues/840`). Both are plausible precedents, not yet established on SSL-55.
- **Next Step12K (read only):** Inspect per-domain AppArmor generated path rules for the exact `win11` UUID, `/var/run` symlink versus `/run`, active `security_driver` or process user overrides, targeted `/var/log/libvirt/qemu/win11.log` errors, and kernel audit DENIED lines. One private TXT with no VM launch or host modifications. Assistant supplied direct copy-paste terminal block; matching `scripts/audit_swtpm_socket_security.sh` and Bash syntax CI added to `development`. Await report before any repair; **never disable AppArmor globally, change broad permissions or recreate VM**.
- **Status:** TPM guest startup still **BLOCKED by QEMU-to-swtpm Unix socket permission denied**. Earlier local CA permission fix remains verified; `win11` not yet installed.

## Step 12K — Socket created with mode 0600, AppArmor profile missing TPM path rules (2026-10-09)

- **User-uploaded read-only report:** `SSL55_Step12K_TPMSecurity_PWr6ntZO.txt` (33 indexed lines). `win11` remains **shut off**; `/var/run -> /run`; `/etc/libvirt/qemu.conf` explicitly contains `security_driver = "apparmor"`.
- Local VM dynamic AppArmor file `/etc/apparmor.d/libvirt/libvirt-<guest UUID>` is present, but grepping it for `swtpm`, `@{run}`, `/var/run/libvirt`, `/run/libvirt` returned **zero lines**. Associated `<UUID>.files` not present when checked after failed boot. **Neither result proves AppArmor allowed or denied TPM socket**: generated profiles and file rules can be removed after failed launch, and no kernel DENIED audit line was observed.
- Actual `/var/log/libvirt/qemu/win11.log` shows libvirt spawned `/usr/bin/swtpm socket --ctrl type=unixio,path=/var/run/libvirt/qemu/swtpm/{8,9}-win11-swtpm.sock,mode=0600`, with TPM-state files also mode 0600. QEMU's `-chardev` attempted to connect to the *same socket path* and exited **Permission denied**. The 0600 socket allows only owner under ordinary DAC, but the effective QEMU UID and socket owner **at failure time remain unmeasured**.
- **Outside technical references:** [swtpm issue #840](https://github.com/stefanberger/swtpm/issues/840) documents 0600 TPM socket permissions denying unprivileged QEMU despite group ownership; [2025 libvirt patch discussion](https://lists.libvirt.org/archives/list/devel@lists.libvirt.org/message/RTL4QWDH5PH2AQUSES32Y4AANCMSDHZR/) documents AppArmor dynamic rules containing `/var/run` while kernel evaluates symlink-resolved `/run`, producing the same socket connect denial. **Neither cause is yet uniquely established on SSL-55**, and the user-provided `security_driver=apparmor` is a reason NOT to disable protections globally.
- **Next high-signal action:** An explicitly supervised **single guest-start attempt**, concurrently capturing the transient **socket file owner/group/mode**, **QEMU EUID/EGID**, and process AppArmor profile before libvirt cleans up after failure. New opt-in `scripts/probe_swtpm_socket_start_once.sh` does that with a bounded monitoring loop and one private TXT report; it starts `win11` only once and **if successful leaves the VM running**. It does not edit host permissions, service config, domain XML or TPM state. User must choose to execute it. Avoid another run if other malware/testing workflows are active.
- **No fix yet implemented:** Current proven symptom is QEMU-to-TPM Unix socket `Permission denied`; initial swtpm-localca directory issue was fixed in Step12H. Do not blindly `chmod`, chown the socket folder or change AppArmor without confirming the actual failing identity/policy. Guest Windows installation and snapshot are still pending.
