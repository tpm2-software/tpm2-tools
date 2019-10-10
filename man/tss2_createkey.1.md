% tss2_createkey(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createkey**(1) -

# SYNOPSIS

**tss2_createkey** [*OPTIONS*]

# DESCRIPTION

**tss2_createkey**(1) - This commands creates a key inside the TPM and stores it in the FAPI metadata store and if requested persistently inside the TPM.

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    The path to the new key. MUST NOT be NULL.

  * **-t**, **\--type**:

    Identifies the intended usage. For possible values see FAPI specification. MAY be NULL.

  * **-P**, **\--policyPath**:

    The policy to be associated with the new key. policyPath MAY be NULL. If NULL then no policy will be associated with the key.

  * **-a**, **\--authValue**:

    The new authorization value for the key. authValue MAY be NULL. If NULL then the authorization value will be the empty string.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

## Create a key without password
```
tss2_createkey --path HS/SRK/myRsaCryptKey --type "noDa, decrypt"
```

## Create a key, ask for password on the command line
```
tss2_createkey --path HS/SRK/myRsaCryptKey --type "noDa, decrypt" --authValue
```

## Create a key with password “abc”.
```
tss2_createkey --path HS/SRK/myRsaCryptKey --type "noDa, decrypt" --authValue abc
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
