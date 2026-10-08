# Step 5 — ACPI detection and nine CAPEv2 installer placeholders

**State:** Canonical SSL-55 manual action recorded; portable guarded automation **draft**. This is not a production-certified anti-detection configuration and has not been run on SSL-55.

## Evidence and technical references

- User-supplied complete SSL-55 terminal transcript, 2026-10-08 (full output is in the conversation; do **not** commit raw ACPI dumps or host-sensitive data).
- Reference guide: `Finalpdf.pdf`, Part 3.3, PDF pages 17–18; the reference manually replaces all nine placeholders with an OEM Table ID.
- Inspected CAPEv2 upstream source: [`kevoreilly/CAPEv2/installer/kvm-qemu.sh`](https://github.com/kevoreilly/CAPEv2/blob/master/installer/kvm-qemu.sh), blob SHA `23b7eaa30bdd13bd9347098fe0d46204550b86f9` **at the time of inspection**. SSL-55 Git HEAD / exact installer file SHA are **not supplied**, so equality with this upstream revision is **unverified**.
- ACPI specification: [system description table header](https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html) specifies **6 bytes** for OEM ID (offset 10) and **8 bytes** for OEM Table ID (offset 16); checksum covers whole table.

## SSL-55 observations

User installed `acpica-tools` **20230628-1** through APT (`1 newly installed, 192 not upgraded`), captured firmware with `acpidump`, extracted with `acpixtract`, disassembled `dsdt.dat` with `iasl`, and inspected DSDT and hardware IDs.

DSDT header: `DefinitionBlock ("", "DSDT", 2, "DELL  ", "Dell Inc", 0x00000002)`. The OEM ID is `DELL` with trailing spaces (6-byte field), OEM Table ID is **`Dell Inc`** (8-byte field). These **must not** be conflated. The generic `PNP0*` device `_HID` entries are not suitable OEM identifier sources.

`iasl -d dsdt.dat` generated `dsdt.dsl`, but warned about unresolved external control methods and potential failure to recompile the DSL without additional SSDT declarations. This warning does **not** invalidate the quoted DSDT header; it should not be classified as a clean, warning-free disassembly.

**Actual manual mutation, recorded as user performed:** `sudo sed -i 's/<WOOT>/DELL/g' kvm-qemu.sh`. The separate `895C` commands in the explanation were **reference examples**, not evidence they were executed on SSL-55. The final `grep -n "<WOOT>\\|DELL" kvm-qemu.sh` output showed nine variables changed to `DELL` and **no remaining `<WOOT>`**, plus a comment mentioning DELL.

No backup was shown before the user's actual manual `sed -i`. The checkout and installer files appeared root-owned, consistent with the earlier `sudo git clone`. Do **not** alter ownership or undo manual work without user authorization.

The `acpidump.out`, `*.dat` and `dsdt.dsl` files were generated inside the upstream clone's `installer` directory (under sudo for the first steps). These contain firmware data and should **not** be committed, published, or treated as source files in the automation repository.

## Additional illustrated ACPI methods supplied by the user (2026-10-09)

Six screenshots were provided as **supplementary reference examples**, not machine-specific evidence from SSL-55. They describe three methods for choosing an illustrative `<WOOT>` string:

1. **ACPI table dump:** A VM-hosted Ubuntu 22.04.5 example shows a DSDT header with OEM ID resembling `PTLTD` and OEM Table ID **`Custom`**. Importantly, `Custom` has **six** characters, so it fails a four-byte code requirement as written. Being visually highlighted in the guide is not a technical length/field compatibility test.
2. **Hardware ID inspection:** A `_HID` such as `PNP0A03` was used to suggest `PNP0`. This is a **generic Plug-and-Play identifier prefix**, not reliably the host vendor's OEM identity; a generic prefix must not become the automatic fallback.
3. **External ACPI collections:** A Dell Inspiron 5566 entry shows **OEM ID `DELL`** and **OEM Table ID `CBX3`**. This is a valid *example of distinct four-character fields*, but it is data for that specific hardware/firmware, **not** proof that the current SSL-55 Dell machine uses `CBX3`.

The screenshots' prose says `four character letters` while examples `PNP0`, `CBX3`, and historical `895C` contain digits. The conservative syntax rule is **four ASCII alphanumeric characters**, not exclusively letters, as supported by the examples. This only validates shape, **not firmware provenance or QEMU/SeaBIOS compatibility**.

**Selection design:** Read the actual local DSDT header first; never copy a value from a model-mismatched online ACPI table. Refuse `PNP0` and known generic/virtualization markers (`QEMU`, `BXPC`, `VBOX`, `ACPI`) as OEM candidates even if four characters long. A successful `DELL` OEM candidate on SSL-55 remains unchanged. A DSDT with `DELL` + `CBX3` presents **two different plausible 4-byte choices**; the current fail-closed script requires review instead of assuming the Dell model or automatically picking the table ID. Further policy or explicit verified model-specific mapping is needed for fully unattended operation on such a machine.

**Boundary:** The images do not establish that the eight disk/tablet/BIOS fields should all reuse one DSDT field. Do not remove the per-field verification requirement on the strength of the screenshots.

## Why one universal replacement string cannot be certified

Inspection of the **actual upstream source** confirms nine variables, all initialized to `'<WOOT>'`, at approximately lines 116–144, but they are used for **different guest-emulated devices/firmware surfaces**:

| Source variable | Intended string context |
| --- | --- |
| `PEN_REPLACER` | QEMU USB PenPartner tablet / pointing device |
| `SCSI_REPLACER` | QEMU SCSI disk vendor |
| `ATAPI_REPLACER` | QEMU ATAPI identification, padded into an eight-byte field |
| `MICRODRIVE_REPLACER` | QEMU microdrive product string |
| `BOCHS_BLOCK_REPLACER` | QEMU Bochs block format string |
| `BOCHS_BLOCK_REPLACER2` | SeaBIOS Bochs/QEMU reference strings |
| `BOCHS_BLOCK_REPLACER3` | Additional SeaBIOS block command reference |
| `BXPC_REPLACER` | Four-character `BXPC` ACPI-related label in QEMU and SeaBIOS |
| `BOCHS_SEABIOS_BLOCK_REPLACER` | SeaBIOS/Bochs identification in `src/config.h` |

**Only the BXPC field has a plausible direct relationship to a four-character ACPI OEM candidate.** A device brand cannot reliably be inferred from an ACPI DSDT OEM ID. Four ASCII characters matching a source token does **not** prove the guest devices become indistinguishable from physical hardware. The reference PDF's ninefold uniform substitution is a historical method, **not a general ACPI correctness rule**.

Furthermore, the inspected upstream installer optionally **sources `./kvm-config.sh`** after defaults are assigned. A future supported design may prefer a controlled config override rather than mutating third-party source; however, the user's manual path remains the canonical recorded history. Either strategy requires tests against the exact CAPEv2/QEMU/SeaBIOS versions.

## Safe-portability design and supported behavior

Source: [`scripts/prepare_acpi_replacements.py`](../scripts/prepare_acpi_replacements.py); synthetic tests: [`scripts/test_prepare_acpi_replacements.py`](../scripts/test_prepare_acpi_replacements.py).

**Read-only default:** Reads the raw DSDT binary header (normally from `/sys/firmware/acpi/tables/DSDT`) and the candidate installer file. Does **not** require ACPI disassembly or automatically install `acpica-tools`. Future prerequisite bootstrap must make Python 3 available before invoking this module; on systems without readable firmware tables the module must stop or accept an explicitly obtained alternate DSDT via `--dsdt`.

- Verify DSDT signature, header length, checksum, ASCII fields and explicit space padding.
- Examine both OEM ID and OEM Table ID, accepting a four-character alphanumeric candidate **only if exactly one unambiguous value exists** and excluding known generic or virtual-machine markers. SSL-55-style `DELL  ` + `Dell Inc` selects `DELL`. SSL-45-style `HPQOEM` + `895C    ` selects `895C`. Conflicting viable four-character candidates or lack of one must **stop**, not guess or truncate.
- Validate nine exact source assignments, each occurring once. Default audit prints the original source SHA-256 and existing values without modification.
- **Do not automatically derive the remaining eight device/BIOS replacement values from ACPI.** Require an explicitly *reviewed*, per-variable JSON mapping; conservative draft syntax allows 2–8 ASCII alphanumeric characters. The format check prevents unsafe patch strings but does **not** certify the truth of their identities. A future version may use verified device profiles with explicit compatibility evidence.
- Dry-run shows the precise variable-only diff; `--apply` is an **explicitly authorized** operation requiring a reviewed profile, a matching pinned original file SHA-256, and an absolute backup directory **outside** the CAPEv2 checkout.
- If source has unexpected lines, duplicate or partial placeholders, mismatched revision, invalid data or no valid profile, stop before changing the source.
- Keep a hashed backup, write replacement through temporary file and `os.replace`, check nine values and no `<WOOT>` afterwards, preserve mode and ownership where permitted. Repeated application with identical values must be a no-op; mismatched premodified values must not be overwritten.
- **No claim** of compile success, runtime functionality, full anti-evasion, safe malware execution or cross-machine compatibility is made based on these checks.

### Example commands for an authorized isolated test host (NOT for SSL-55)

Read-only audit (may need authorized access to the DSDT):

```bash
python3 scripts/prepare_acpi_replacements.py --script /absolute/path/to/CAPEv2/installer/kvm-qemu.sh
```

Reviewed per-field JSON example, **illustrative only** and not a validated hardware profile:

```json
{
  "PEN_REPLACER": "WACOM",
  "SCSI_REPLACER": "SEAGATE",
  "ATAPI_REPLACER": "SAMSUNG",
  "MICRODRIVE_REPLACER": "SANDISK",
  "BOCHS_BLOCK_REPLACER": "SAMSUNG",
  "BOCHS_BLOCK_REPLACER2": "SEAGATE",
  "BOCHS_BLOCK_REPLACER3": "SEAGATE",
  "BOCHS_SEABIOS_BLOCK_REPLACER": "PHOENIX"
}
```

These sample values are **not approved for actual deployment**; they demonstrate configuration syntax only.

`--profile reviewed.json` performs dry-run; `--apply` requires `--expected-sha256 <verified-64-digit-hash> --backup-dir /absolute/outside/checkout`. **Do not run on SSL-55 without explicit agreement**; SSL-55's nine placeholders are already modified by the user.

## Verification performed on the draft module
- **Five additional regression tests committed** for the supplied examples (VM `Custom`, Dell `CBX3` with conflicting `DELL`, eligible `CBX3` with no conflict, generic `PNP0`, and virtual-machine tokens). There are **18 tests in the suite**; this message does **not** claim the updated whole suite was re-executed on a real Ubuntu host.
- **Nine targeted synthetic ACPI candidate-selection cases** were executed independently in a separate environment and passed using the updated selection rules. This targeted check is narrower than executing the committed full test suite or building QEMU/SeaBIOS.


- Python syntax compilation: **passed**.
- **13 original local synthetic tests**: **previously passed** (DSDT checksum/signature, Dell-like and HP-like header selection, ambiguous/invalid IDs, missing profile, safe diff/backup, source hash pin rejection, partial edit rejection, symlink rejection, successful idempotent rerun, mismatched rerun rejection).
- GitHub committed source and local tested source have **matching Git blob SHA**: `ac80d41890c638fa3f0e85e9268cd0301e7ef78c`; tests match blob `3e11b2c9c2e94f4968344af47cf3342b2210f971`.
- **Not tested:** Real SSL-55 DSDT binary; exact SSL-55 `kvm-qemu.sh` binary/source SHA; root-owned on-host write permissions; actual Ubuntu fresh-machine installation, real QEMU/SeaBIOS build, malware-analysis guest behavior, firmware anti-detection effectiveness, dynamic handling of every vendor and hardware configuration.

**Acceptance gate:** Must reproduce on supported clean Ubuntu hosts and in an end-to-end CAPEv2 build before release. Fail closed on incompatible or unknown hardware rather than claim universal hardware support.
