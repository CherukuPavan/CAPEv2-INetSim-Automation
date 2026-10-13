# Command 3 operator-verified step tracker (development)

**Source of truth:** operator's manual changes on reference host SSL-55, recorded
one by one. Screenshots can document the *guide's intended* change, but do not
prove the running SSL-55 config unless the operator confirms or a masked
read-only host audit is inspected. No assistant execution on SSL-55 occurred.

## Step 1 — reported completed on SSL-55 (2026-10-13)

- Guide: Section 13, "Tell CAPE About the Virtual Machine"; 13.2.1 API configuration.
- File: \`/opt/CAPEv2/conf/api.conf\`.
- Section: \`[api]\`.
- Operator reports changing **\`ratelimit = yes\` -> \`ratelimit = no\`** on SSL-55.
- This is a *configuration-file edit*, not evidence that any CAPE service was
  restarted or that the change has taken effect in a live API process.
- Do not infer network exposure, API authentication, actual contents of the
  file on disk, or any completed multi-VM CAPE registration from the picture.
- **Security:** \`ratelimit = no\` disables an abuse-prevention control.
  Apply only in a trusted, access-controlled lab and never expose the API to
  arbitrary Internet users. If an API endpoint is broadly reachable,
  retain/restore \`ratelimit = yes\` until access restrictions are verified.

### Development automation

- \`scripts/command3_cape_api_ratelimit.py\` supports a read-only \`plan\`
  and explicitly approved root-only \`apply\`. Its parser requires one \`[api]\`
  section and one live \`ratelimit\` key, changes no other setting, writes
  a root-private \`0600\` backup before replacing the config atomically,
  preserves original owner/mode, checks the source hash again before writing,
  blocks ambiguous/missing/insecure files, and is idempotent when value is
  already \`no\`. It does **not** restart any service.
- \`scripts/test_command3_cape_api_ratelimit.py\` is a synthetic regression
  suite that touches only temporary files. GitHub Actions offline tests run on
  supported Python versions; success does not establish SSL-55 configuration
  or service-level behavior.
- Operator should **not run this apply script again on SSL-55** simply to
  "match automation"; the manual change is already reported complete.
- The script is a **component** of a future all-configuration Command 3
  orchestration, not the finished one-command Command 3 installer.

## Pending operator steps

Await the next supplied configuration-file edit. For each step, document
exact file/section/key, operator's desired value, project-specific reason,
the old value if known, dependency/security impact, and idempotent regression.
Do not invent unspecified \`kvm.conf\`, \`cuckoo.conf\`, \`routing.conf\` values.

Restart CAPE/related services **only after** the complete reviewed change
set and its service dependency order have been validated. Do not assume a
service restart is sufficient proof of correct CAPE machinery, snapshot
revert, all-N analysis guest visibility, or network/malware containment.

## Global status

Commands 1 and 2 still have blockers documented in
\`docs/COMMAND12_PRE_COMMAND3_ENGINEERING_AUDIT_20261013.md\`. Protected
original Windows master \`win11\`, reference clone \`win11_1\`, existing
snapshot records, SSL-55 host state and GitHub \`main\` branch are not
changed by this development-only Command 3 code.
