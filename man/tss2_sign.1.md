% tss2_sign(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_sign**(1) -

# SYNOPSIS

**tss2_sign** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_sign**(1) - This command uses a key inside the TPM to sign a digest value
using the TPM signing schemes as specified in the cryptographic profile
(cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**=_STRING_:

    The path to the signing key.

  * **-s**, **\--padding**=_STRING_:

    The padding scheme used. Possible values are "RSA_SSA", "RSA_PSS" (case insensitive). Optional parameter.
    If omitted, the default padding specified in the cryptographic profile
    (cf., **fapi-profile(5)**) is used.

  * **-c**, **\--certificate**=_FILENAME_ or _-_ (for stdout):

    The certificate associated with keyPath in PEM format. Optional parameter.

  * **-d**, **\--digest**=_FILENAME_ or _-_ (for stdin):

    The data to be signed, already hashed.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-k**, **\--publicKey**=_FILENAME_ or _-_ (for stdout):

    The public key associated with keyPath in PEM format. Optional parameter.

  * **-o**, **\--signature**=_FILENAME_ or _-_ (for stdout):

    Returns the signature in binary form.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_sign --keyPath=HS/SRK/myRSASign --padding="RSA_PSS" --digest=digest.file --signature=signature.file --publicKey=publicKey.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
