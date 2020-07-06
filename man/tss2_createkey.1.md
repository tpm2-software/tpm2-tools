% tss2_createkey(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createkey**(1) -

# SYNOPSIS

**tss2_createkey** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_createkey**(1) - This commands creates a key inside the TPM and stores it
in the FAPI metadata store and if requested
persistently inside the TPM. Depending on the  specified key type, cryptographic
algorithms and parameters for the created key are determined by the
corresponding cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    The path to the new key.

  * **-t**, **\--type**=_STRING_:

    Identifies the intended usage. Optional parameter.
    Types may be any comma-separated combination of:

        - "sign": Sets the sign attribute of a key.
        - "decrypt": Sets the decrypt attribute of a key.
        - Hint: If neither sign nor decrypt are provided, both attributes are set.
        - "restricted": Sets the restricted attribute of a key.
        - Hint: If restricted is set, sign or decrypt (but not both) need to be set.
        - "exportable": Clears the fixedTPM and fixedParent attributes of a key or
          sealed object.
        - "noda": Sets the noda attribute of a key or NV index.
        - "system": Stores the data blobs and metadata for a created key or seal
          in the system-wide directory instead of user's personal directory.
        - A hexadecimal number (e.g. "0x81000001"): Marks a key object to be
          made persistent and sets the persistent object handle to this value.

  * **-P**, **\--policyPath**=_STRING_:

    The policy to be associated with the new key. Optional parameter. If omitted
    then no policy will be associated with the key.

    A policyPath is composed of two elements, separated by "/". A policyPath
    starts with "/policy". The second path element identifies the policy
    or policy template using a meaningful name.

  * **-a**, **\--authValue**=_STRING_:

    The new UTF-8 password. Optional parameter. If it is neglected then the user
    is queried interactively for a password. To set no password, this option
    should be used with the empty string (""). The maximum password size is
    determined by the digest size of the chosen name hash algorithm in the
    cryptographic profile (cf., **fapi-profile(5)**). For example, choosing
    SHA256 as hash algorithm, allows passwords of a maximum size of 32
    characters.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

## Create a key without password
```
tss2_createkey --path=HS/SRK/myRsaCryptKey --type="noDa, decrypt" --authValue=""
```

## Create a key, ask for password on the command line
```
tss2_createkey --path=HS/SRK/myRsaCryptKey --type="noDa, decrypt"
```

## Create a key with password "abc".
```
tss2_createkey --path=HS/SRK/myRsaCryptKey --type="noDa, decrypt" --authValue=abc
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
