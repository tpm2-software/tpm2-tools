% tss2_createseal(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createseal**(1) -

# SYNOPSIS

**tss2_createseal** [*OPTIONS*]

# DESCRIPTION

**tss2_createseal**(1) - This command creates a sealed object and stores it in the FAPI metadata store. If no data is provided (i.e. a NULL-pointer) then the TPM generates random data and fills the sealed object.

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    The path to the new key. MUST NOT be NULL.

  * **-t**, **\--type**:

    Identifies the intended usage. For possible values see FAPI specification. MAY be NULL.

  * **-P**, **\--policyPath**:

    Identifies the policy to be associated with the new key. MAY be NULL. If NULL then no policy will be associated with the key.

  * **-a**, **\--authValue**:

    The new authorization value for the key. MAY be NULL. If NULL then the authorization value will be the empty string.

  * **-i**, **\--data**:

    the data to be sealed by the TPM. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

## Create a key without password and read data to be sealed from file.
```
tss2_createseal --path HS/SRK/mySealKey --type "noDa" --authValue abc --data abc
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
