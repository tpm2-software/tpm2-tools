% tss2_verifysignature(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_verifysignature**(1) -

# SYNOPSIS

**tss2_verifysignature** [*OPTIONS*]

# DESCRIPTION

**tss2_verifysignature**(1) - This command verifies a signature using a public key found in the passed key path. The used signature verification scheme is specified in the cryptographic profile (cf., **fapi-profile(5)**).

# OPTIONS

These are the available options:

  * **-d**, **\--digest**=_FILENAME_ or _-_ (for stdin):

    The data that was signed, already hashed according to the cryptographic
    profile (cf., **fapi-profile(5)**).

  * **-p**, **\--keyPath**=_STRING_:

    Path to the verification public key.

  * **-i**, **\--signature**=_FILENAME_ or _-_ (for stdin):

    The signature to be verified.


[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_verifysignature --keyPath=ext/myRSASign --digest=digest.file --signature=signature.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
