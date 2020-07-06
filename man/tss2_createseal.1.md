% tss2_createseal(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_createseal**(1) -

# SYNOPSIS

**tss2_createseal** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_createseal**(1) - This command creates a sealed object and stores it in the FAPI metadata store. If no data is provided (i.e. a NULL-pointer) then the TPM generates random data and fills the sealed object. TPM signing schemes are used as specified in
the cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    The path to the new key.

  * **-t**, **\--type**=_STRING_:

    Identifies the intended usage. Optional parameter.
    Types may be any comma-separated combination of:

        - "exportable": Clears the fixedTPM and fixedParent attributes of a key or
          sealed object.
        - "noda": Sets the noda attribute of a key or NV index.
        - "system": Stores the data blobs and metadata for a created key or seal
          in the system-wide directory instead of user's personal directory.
        - A hexadecimal number (e.g. "0x81000001"): Marks a key object to be
          made persistent and sets the persistent object handle to this value.

  * **-P**, **\--policyPath**=_STRING_:

    Identifies the policy to be associated with the new key. Optional parameter.
    If omitted then no policy will be associated with the key.

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

  * **-i**, **\--data**=_FILENAME_ or _-_ (for stdin):

    The data to be sealed by the TPM. Optional parameter. Must not be used
    together with \--size.

  * **-s**, **\--size**=_INTEGER_:

    Determines the number of random bytes the TPM should generate and seal.
    Optional parameter. Must not be "0". Must no be used together with \--data.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

## Create a key with password "abc" and read sealing data from file.
```
tss2_createseal --path=HS/SRK/mySealKey --type="noDa" --authValue=abc --data=data.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
