% tss2_exportkey(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_exportkey**(1) -

# SYNOPSIS

**tss2_exportkey** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_exportkey**(1) - This command will duplicate a key and encrypt it using the public key of a new parent. The
exported data will contain the re-wrapped key pointed to by the pathOfKeyToDuplicate and then the JSON encoded policy. Encryption is done according to TPM encryption
schemes specified in the cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-e** **\--pathToPublicKeyOfNewParent**=_STRING_:

    The path to the public key of the new parent. This key MAY be in the public key hierarchy /ext.
    Optional parameter. If omitted only the public key will exported.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--exportedData**=_FILENAME_ or _-_ (for stdout):

    Returns the exported subtree.

  * **-p**, **\--pathOfKeyToDuplicate**=_STRING_:

    The path to the root of the subtree to export.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_exportkey --pathOfKeyToDuplicate=HS/SRK/myRSADecrypt --exportedData=exportedData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
