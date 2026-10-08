# SSL-55 canonical manual installation log

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

## Automation status after Steps 1–7

- `scripts/check_host_virtualization.sh` is an early **read-only draft** for Steps 1–3.
- `scripts/bootstrap_cape_source.sh` is a separate **Git/source bootstrap draft** based on Step 4; it would modify a host **only if intentionally executed** as an installer component. It is not one of the three final commands and is not yet release-ready.
- The user reported CAPEv2 **source clone, nine-variable installer edit, libvirt package installation and CAPE installer settings**, not CAPEv2 runtime installation. No Windows VM, INetSim VM, isolated network or full three-command deployment automation has been installed or validated as part of this canonical build.
- `scripts/prepare_acpi_replacements.py` is an early **conditional** draft: inspection is read-only and mutation requires `--apply`, reviewed values and source pin. It is not validated on SSL-55.
- `scripts/audit_libvirt_cape_network.py` is a **read-only** Step 6 diagnostic draft with 11 synthetic tests passed. It deliberately does not assert malware-ready isolation.
- `scripts/audit_kvm_build_step7.py` is an early read-only Step 7 user/build-log verifier; it must not be mistaken for a safe deployment wrapper. The source installer run reported failures and has no fully verified success status.
- **Do not** run installation or environment changes on SSL-55 without explicit user direction.
- Next manual step is chosen and executed by the user.
