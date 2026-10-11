# Portable no-NIC domain renderer — Command 2 development

**GitHub-only, pure XML. Creates/boots NO VM and reads no host files.**

Component: `scripts/command2_portable_zero_nic_xml.py`
Function: `render_no_nic(master_xml, candidate, expected_master_disk=...,
expected_master_nvram=...)`.

This derives a new independent candidate VM definition from the EXACT
verified Command 1 Windows master XML supplied by the future target
adapter, without referencing hardcoded SSL-55 paths.

Fail-closed checks:
- KVM source and expected master name, canonical source/clone UUIDs.
- Exactly one file-backed QCOW2 OS disk matching expected master.
- Separate expected OVMF NVRAM, with declared firmware template.
- Emulator TPM 2.0 without explicit inherited backend source/encryption.
- Refusal of hostdev, filesystem, PCI direct NIC, network passthrough,
  smartcard, redirection, channels, shmem and QEMU commandline overrides.
- Remove source network or bridge NICs entirely; generated XML has ZERO
  NICs, so no guest traffic can be sent by this definition alone.
- Media-less source CDROM, remove inherited guest security labels and
  metadata, reset SPICE/VNC to localhost and dynamic port.
- Assign new libvirt UUID, SMBIOS generation ID, independent QCOW2
  source path and independent VARS path.

`scripts/test_command2_portable_zero_nic_xml.py` uses synthetic
source domains to test network stripping, TPM/UEFI constraints,
unique identity and refusal of unsafe devices, while ensuring the
source XML is not mutated. CI tests both Python 3.10 and Python 3.12.

This XML renderer is not a verified libvirt domain definition until
a separate, approved host accepts `virsh define` under a guarded
transaction after live collision checks, root-private files and
exact separate VM firmware/TPM state are prepared. Windows hostname
and IP are not applied. Runtime IPv4+IPv6 egress containment, CAPE
positive path and reboot guard persistence remain unverified.

**Never use this to create additional VMs on SSL-55.**
