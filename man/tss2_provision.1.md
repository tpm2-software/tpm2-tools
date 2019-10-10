% tss2_provision(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_provision**(1) -

# SYNOPSIS

**tss2_provision** [*OPTIONS*]

# DESCRIPTION

**tss2_provision**(1) - This command provisions a FAPI instance and its associated TPM. The steps taken SHALL be:

  * Retrieve the EK template, nonce and certificate, verify that they match the TPM’s EK and store them in the key store.
  * Set the authValues and policies for the Owner (Storage Hierarchy), the Privacy Administrator (Endorsement Hierarchy) and the lockout authority.
  * Scan the TPM’s nv indices and create entries in the metadata store. This operation MAY use a heuristic to guess the originating programs for nv indices found and name the entries accordingly.
  * Create the SRK (storage primary key) inside the TPM and make it persistent if required by the FAPI configuration and stored its metadata in the system-wide metadata store. Note that the SRK will not have an authorization value associated.

If an authorization value is associated with the storage hierarchy, it is highly RECOMMENDED that the SRK
without authorization value is made persistent.

# OPTIONS

These are the available options:

  * **-E**, **\--authValueEh**:
    The authorization value for the privacy admin, i.e. the endorsement hierarchy. MAY be NULL.

  * **-S**, **\--authValueSh**:
    The authorization value for the owner, i.e. the storage hierarchy. SHOULD be NULL.

  * **-L**, **\--authValueLockout**:
    The authorization value for the lockout authorization. SHOULD NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_provision
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
