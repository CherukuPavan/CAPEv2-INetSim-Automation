# CAPE Python 3.12 reproducible offline dependency artifact evidence

**Evidence date:** 2026-10-16. **Branch:** `development`.
**Verified source:** upstream `kevoreilly/CAPEv2` commit
`004d73c51dcd12dacb97b3657262bdea8376d710`.
**Disposable build target:** signed Ubuntu 26.04 amd64,
managed CPython 3.12.12 (not system Python 3.14), uv 0.9.15.

## Independently checked CI result

GitHub Actions [real wheel build and offline install,
run 38912898327](https://github.com/CherukuPavan/CAPEv2-INetSim-Automation/actions/runs/38912898327)
successfully:

- Compiled the exact upstream PEP-621 dependency graph using pinned
  upstream package distributions and a source hash-based requirements
  lock.
- Built **170 package wheels twice** in isolated scratch directories.
  Exactly one native wheel, `python-tlsh==4.5.0`, had previously differed
  due to random pip temporary-directory strings in DWARF and a resulting
  GNU ELF build-ID. The two archived originals were inspected without
  executing them. Both binaries became **byte-identical** after removing
  only `.debug_*` sections and `.note.gnu.build-id` in a disposable
  build with `objcopy`. ZIP metadata/order were retained, and the ELF
  checksum/size in wheel `RECORD` was regenerated. Neither the original
  sdist nor the upstream source checkout was modified.
- Independently compared **all 170 normalized wheel SHA256 digests**:
  `CAPE_TWICE_BUILT_WHEEL_DIFF_COUNT 0`.
- Successfully ran the host-facing SHA-locked manifest/ZIP admission
  against actual compiled wheels; verified that all 170 wheels were
  root-owned and protected from the unprivileged CAPE account, and
  rejected a deliberately group/world-writable wheel.
- Installed the exact offline wheel set into a fresh Python 3.12 venv
  without network or pip dependency resolution. Imported
  `gevent`, `greenlet`, Django, SQLAlchemy, and YARA and successfully
  invoked `cuckoo.py --help` as an unprivileged user.
- Separately created an offline uv-managed venv with **no target pip**
  and installed/imported pinned dependencies there too.

The Python 3.10/3.12 synthetic regression suite and repository-wide
structural audit verify the normalizer's fixed-wheel scope, failure
handling, and the SHA-locked admission refusal logic. No Windows guest,
real CAPE scheduler, database or service, network, or source host was
started or changed in these jobs.

## Exact reviewed hashes (from the uploaded CI artifact)

| Artifact | Verified value |
|---|---|
| Manifest JSON SHA256 | `2e1773f8b1fa418e5e4f9871fd678adc77422c7f3afa261360225ab5600f69ca` |
| 170-package requirement lock SHA256 | `4fcc66a0437189c18e14de68e6480702b3966c394ac1338f599ef6bfbf520408` |
| Full wheel set total bytes | `159787257` |
| Normalized python-tlsh wheel SHA256 | `0d4d4cc200500f486ce553b902dea499d3cb05fd8e29fc1161f7ff78ef4adf34` |
| Normalized python-tlsh ELF SHA256 | `6252e8a5a06395e3f3c4fd7257ef51253d774e5129ec2efcf6348d24feca8f0a` |
| Entire GitHub Actions ZIP containing wheelhouse | `sha256:08fb70dcf16c741e7afb4f043a4b1de009501f8a0f12ff48094c516a467011d1` |

The last value is an upload-archive digest, not a GitHub release asset
identity. It must not substitute for independent verification of every
wheel from the approved manifest/lock.

**Retention limitation:** GitHub Actions scratch review artifacts in this
job are short-lived, not a permanent authorized worldwide distribution
channel. Before operator deployment, publish an independently verified,
immutable approved release containing all reviewed wheel bytes with
documented provenance, review the external CPython/uv build chain, and
provision a read-only accessible distribution path. A production host
must take the manifest SHA256 from an independently pinned trusted
release, *not* compute it from the downloaded manifest itself.

## Remaining production acceptance

A fully integrated, rootless CAPE service account/venv installation,
database, restricted routing, the exact separately encrypted Windows
master, unique running Windows clones, Windows TPM NV/PCR witnesses
after two physical KVM snapshot reverts, and complete service/network/
VM/TPM rollback still require independently verified end-to-end tests.
This evidence alone does not authorize the requested final three-command
deployment.
