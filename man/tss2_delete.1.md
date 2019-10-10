% tss2_delete(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_delete**(1) - This command deletes the given key, policy or NV from the system. Depending on the entity type, one of the following
actions SHALL be taken:

    * Non-persistent key: Flush from TPM (if loaded) and delete blobs public and private blobs from keystore.
    * Persistent keys: Evict from TPM and delete public and private blobs from keystore
    * Primary keys: Flush from TPM and delete public blobs from keystore
    * NV index: Undefine NV index from TPM and delete public blob from metadata store
    * Policies: Delete entry from policy store
    * Hierarchy, PCR: Return TSS2_FAPI_RC_NOT_DELETABLE
    * Special keys EK, SRK: Return TSS2_FAPI_RC_NOT_DELETABLE

# SYNOPSIS

**tss2_delete** [*OPTIONS*]

# DESCRIPTION

**tss2_delete**(1) -

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    The path to the entity to delete. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

# Deletes storage hierarchy (HS) and everything below it:
```
tss2_delete --path /HS
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
