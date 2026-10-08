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
