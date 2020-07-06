% tss2_unseal(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_unseal**(1) -

# SYNOPSIS

**tss2_unseal** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_unseal**(1) - This command unseals data from a seal in the FAPI metadata store.
The used decryption scheme is specified in the cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**=_STRING_:

    Path of the object for which the blobs will be returned.

  * **-o**, **\--data**=_FILENAME_ or _-_ (for stdout):

    The decrypted data after unsealing. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_unseal --path=HS/SRK/myRSACrypt --data=data.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
