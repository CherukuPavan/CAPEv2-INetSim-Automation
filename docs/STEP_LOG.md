# SSL-55 canonical manual installation log

**Status:** Steps 1–4 reported with terminal evidence. CAPEv2 upstream **source checkout** was performed in Step 4; CAPEv2 runtime installation, Windows VMs and INetSim deployment remain unverified/not reported.

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

## Automation status after Steps 1–4

- `scripts/check_host_virtualization.sh` is an early **read-only draft** for Steps 1–3.
- `scripts/bootstrap_cape_source.sh` is a separate **Git/source bootstrap draft** based on Step 4; it would modify a host **only if intentionally executed** as an installer component. It is not one of the three final commands and is not yet release-ready.
- The user reported a successful CAPEv2 **source clone**, not CAPEv2 runtime installation. No Windows VM, INetSim VM, isolated network or full three-command deployment automation has been installed or validated as part of this canonical build.
- **Do not** run installation or environment changes on SSL-55 without explicit user direction.
- Next manual step is chosen and executed by the user.
