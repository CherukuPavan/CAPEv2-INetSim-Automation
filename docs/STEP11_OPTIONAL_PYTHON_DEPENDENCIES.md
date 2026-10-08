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
