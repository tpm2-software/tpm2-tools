% tss2_provision(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_provision**(1) -

# SYNOPSIS

**tss2_provision** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_provision**(1) - This command provisions a FAPI instance and its associated TPM. The steps taken are:

  * Retrieve the EK template, nonce and certificate, verify that they match the TPM's EK and store them in the key store.
  * Set the authValues and policies for the Owner (Storage Hierarchy), the Privacy Administrator (Endorsement Hierarchy) and the lockout authority.
  * Scan the TPM's nv indices and create entries in the FAPI metadata store. This operation MAY use a heuristic to guess the originating programs for nv indices found and name the entries accordingly.
  * Create the SRK (storage primary key) inside the TPM and make it persistent if required by the cryptographic profile (cf., **fapi-profile(5)**) and store its metadata in the system-wide FAPI metadata store. Note that the SRK will not have an authorization value associated.

If an authorization value is associated with the storage hierarchy, it is highly recommended that the SRK
without authorization value is made persistent.

The paths of the different metadata storages for keys and nv indices are configured
in the FAPI configuration file (cf., **fapi-config(5)**).

# OPTIONS

These are the available options:

  * **-E**, **\--authValueEh**=_STRING_:
    The authorization value for the privacy admin, i.e. the endorsement hierarchy.
    Optional parameter.

  * **-S**, **\--authValueSh**=_STRING_:
    The authorization value for the owner, i.e. the storage hierarchy. Optional parameter.

  * **-L**, **\--authValueLockout**=_STRING_:
    The authorization value for the lockout authorization. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_provision
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
