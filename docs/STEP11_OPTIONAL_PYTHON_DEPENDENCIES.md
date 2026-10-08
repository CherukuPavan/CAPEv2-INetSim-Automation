# Step 11 — Ubuntu Poetry package and optional CAPEv2 dependencies

**Evidence:** User pasted terminal output (663 physical lines / 664 indexed) from SSL-55 showing actual commands `cd /opt/CAPEv2`, `sudo apt install python3-poetry -y`, and `poetry run pip3 install -r extra/optional_dependencies.txt`. These were **already executed by the user**; do not ask them to rerun.

## Verified from terminal output

- Ubuntu Noble `python3-poetry 1.8.2+dfsg-1ubuntu2` and **23 additional dependencies** were installed via APT (24 total newly installed); the terminal returned to the `charan` prompt.
- Within `/opt/CAPEv2`, unprivileged `poetry run pip3 install -r extra/optional_dependencies.txt` initialized a Poetry virtual environment named `non-package-mode-...-py3.12` under `/home/charan/.cache/pypoetry/virtualenvs`. This confirms **a new virtualenv for the charan user**; it is not proof that the `cape` service environment was changed.
- The optional requirements operation fetched Python packages and VCS dependencies, built all 14 listed wheels successfully and finished with `Successfully installed ...`, followed by the shell prompt. Notable optional package names include `binGraph`, `HTTPReplay`, `Socks5man`, `XLMMacroDeobfuscator`, `peepdf-3`, `pyattck`, `ImageHash`, `deepdiff`, `python-tlsh`. No pip error shown in this operation.
- The output is a pasted transcript, not a saved original raw exit-code report, so **do not assert an independently captured pip exit status**. Successful final pip output supports install completion in the selected environment.
- **Critical separation:** Upstream `kevoreilly/CAPEv2` systemd `cape.service` uses `ExecStart=/etc/poetry/bin/poetry run python cuckoo.py`, `User=cape`, and `WorkingDirectory=/opt/CAPEv2/` (blob `2b1da435d1652f30220a7df270e6d76a89c2e169`). `cape-processor.service` likewise uses `/etc/poetry/bin/poetry` as user `cape` (blob `004fc7cc8e2f6ebb12dd05b05102337175ea20ca`). The **actual local unit contents have not yet been checked**, so these are upstream reference observations, not claims about SSL-55.
- The upstream project `pyproject.toml` has `package-mode = false`; this is consistent with the observed virtualenv prefix `non-package-mode`, but local project revision and Poetry path/virtualenv selection require verification.
- The `cape` account's Poetry environment may differ from `charan`'s. **Do not immediately install the same large optional requirements a second time**. First inspect current effective service units, executables and both Poetry env paths/selected package metadata, using read-only commands. Do not switch the running CAPE service to an unreviewed user environment, and do not replace globally installed Poetry.
- Keep Python dependency sets isolated to the correct service account and reproducibly pinned in the future automation. Avoid relying on `poetry run pip3` unless the correct environment and `pip3` resolution are explicitly verified. Validate import availability in the actual runtime `python`, not only pip's installation message.

**Outcome:** **Step 11 APT + optional-package installation completed according to terminal log; actual `cape` service environment availability unverified.** Next is one read-only environment review report (Step 11A) before any further Python-package install. No malware execution; Step 10B first Windows guest and independent Suricata issue remain open.

See [STEP_LOG.md](STEP_LOG.md), [ROADMAP.md](ROADMAP.md), and [PORTABILITY.md](PORTABILITY.md).

## Step 11A — Local Poetry environment comparison (2026-10-08/09)

User-generated read-only `SSL55_Step11_PoetryEnv_20261008_224841_GcnbGnfH.txt` confirms:
- `/usr/bin/poetry` version **1.8.2**, but CAPE service runtime explicitly invokes `/etc/poetry/bin/poetry` version **2.5.1**.
- Actual `cape.service`, `cape-processor.service`, `cape-web.service` run as `User=cape` and use `/etc/poetry/bin/poetry`; their workdirs are `/opt/CAPEv2`, `/opt/CAPEv2`, and `/opt/CAPEv2/web` respectively.
- `charan` virtualenv exists at `~/.cache/pypoetry/virtualenvs/non-package-mode-t2x27zRb-py3.12` with `ImageHash=4.3.2`, `deepdiff=9.1.0`, `binGraph=3.3.2`, `HTTPReplay=0.3`, `Socks5man=0.3.0`, `pyattck=7.2.1`.
- A `cape` virtualenv was **not identified** because the earlier check discarded stderr and reported a generic result when the `env info --path` command failed, returned empty, or pointed to a path without an executable. It is **not justified** to claim `cape` has no environment or that packages must be copied/reinstalled.

**Next:** A small non-mutating Step11B query under `cape` with visible `env info` status, Poetry virtualenv config, and in-project `.venv` metadata; avoid `poetry run` or global pip until correct interpreter proven. Keep full CAPE runtime readiness pending.

## Step 11B — Valid CAPE service venv established (2026-10-08/09)

User-uploaded read-only report `SSL55_Step11B_CapePoetry_20261008_225117_5lyCTb4w.txt` shows both Poetry executables: packaged `/usr/bin/poetry` **1.8.2**, systemd-selected `/etc/poetry/bin/poetry` **2.5.1**. `cape` account home is `/home/cape/`. `/opt/CAPEv2/poetry.lock` is present, while project-local `/opt/CAPEv2/.venv` is absent; this is consistent with the **valid** cached virtualenv identified by Poetry.

The `cape` Poetry `env info` command exited 0, reporting Python **3.12.3**, **Valid: True**, interpreter `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python`; `env info --path` and `env info --executable` also exited 0 and agreed. `virtualenvs.create=true` and `virtualenvs.in-project=null`. Thus **the Step 11A inability to identify the `cape` environment was a diagnostic limitation, not a real installation defect.**

**Outstanding:** The optional dependencies installed under `charan` are not *verified* installed under `cape`. Query `importlib.metadata` in the **actual cape interpreter**, as `cape`, before any repeat of optional pip installation. Step 11B PASS; do not reinstall Poetry, delete/merge venvs, or change systemd service users.

## Step 11C — Diagnostic permission-context error, no evidence of bad Python (2026-10-08/09)

- User-uploaded `SSL55_Step11C_OptionalDeps_qKKlJkJa.txt` contains: `Environment lookup exit status: 0` and `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python`; later says `Unable to identify a usable CAPE Python executable`. It also reports **no package/service/config changes**.
- **Bug in assistant-provided read-only diagnostic:** It obtained the path via `sudo -n -u cape -H /etc/poetry/bin/poetry -C /opt/CAPEv2 env info --executable`, but then performed Bash `[ -x "$CAPE_PY" ]` **as charan** instead of `cape`. If `/home/cape` restricts directory traversal, this check returns false despite an executable valid for cape. The report does **not prove** the Python executable is damaged or missing; Step11B separately reported `Virtualenv Valid: True`.
- The Step 11C package metadata phase was skipped because of this flawed current-user executable-access gate. **Optional dependency presence in cape's venv is still unknown.** Fix the auditor to check/launch the interpreter **as cape**, with `sudo -n -u cape -H`, then run `python -B` and read-only `importlib.metadata.version` queries. Do not reinstall Poetry, rerun package installation, open permissions on /home/cape, chown service files, or reconfigure systemd based on the false negative.
- Add synthetic test for user-home directory with 0700/0750 permissions (file accessible to service user but not invoking user) to future portable automation.

## Step 11D — Six optional distributions absent from actual cape interpreter (2026-10-08/09)

The user ran the corrected audit under `cape` and uploaded `SSL55_Step11D_ActualCapeDeps_LWm6SH8R.txt`. The Poetry interpreter query exited **0**; `sudo -u cape -H test -x` **PASS**; `sudo -u cape -H <verified-python> -B` ran `importlib.metadata.version` and exited **0**. The actual CAPE service Python is `/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.12/bin/python`.

**Confirmed absence in cape's service venv (all six inspected):** ImageHash; deepdiff; binGraph; HTTPReplay; Socks5man; pyattck. The corresponding six distributions were previously found in `charan`'s separate environment after the successful manual optional requirements command. This is a **real runtime package-target mismatch** for optional modules, **not** a failed Python interpreter or missing Poetry environment. Only the sampled packages were checked; do not infer state for all optional requirements.

**Next action:** No immediate destructive change or blanket rerun. Continue supervised manual CAPEv2/first Windows VM setup and isolated INetSim network work; optional features requiring these packages remain pending. Before installing any extras into `cape`'s Python, evaluate actual `extra/optional_dependencies.txt` against `poetry.lock` and installed versions; use a controlled installer as `cape`, with explicit interpreter, logging/exit capture and post-install verification. Don't copy charan's venv, weaken home permissions, reinstall Poetry, or risk untested upgrades of CAPE's core dependencies. Missing VM `cuckoo1` remains the known driver of CAPE/processor auto-restart, independently of this optional package gap; Suricata has its own startup issue.

**Step 11D status: read-only audit PASS; optional dependency parity incomplete; no further host mutation performed.**
