% tss2_delete(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_delete**(1) -

# SYNOPSIS

**tss2_delete** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_delete**(1) - This command deletes the given key, policy or NV from the
FAPI metadata store and the TPM. Depending on the entity type, one of the following
actions are taken:

    - Non-persistent key: Flush from TPM (if loaded) and delete public and private blobs from keystore.
    - Persistent keys: Evict from TPM and delete public and private blobs from keystore
    - Primary keys: Flush from TPM and delete public blob from keystore
    - NV index: Undefine NV index from TPM and delete public blob from FAPI metadata store
    - Policies: Delete entry from policy store
    - Hierarchy, PCR: These are not deletable
    - Special keys ek, srk: These are not deletable

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    The path to the entity to delete.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

# Deletes storage hierarchy (HS) and everything below it:
```
tss2_delete --path=/HS
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
