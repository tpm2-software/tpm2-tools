% tss2_sign(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_sign**(1) -

# SYNOPSIS

**tss2_sign** [*OPTIONS*]

# DESCRIPTION

**tss2_sign**(1) - This command uses a key inside the TPM to sign a digest value.

# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**:

    The path to the signing key.

  * **-s**, **\--padding**:

    The padding scheme used. Possible values are "RSA_SSA", "RSA_PSS" (case insensitive). Optional parameter.
    If omitted, the default padding specified in the crypto profile is used.

  * **-c**, **\--certificate**:

    The certificate associated with keyPath in PEM format. Optional parameter.

  * **-d**, **\--digest**:

    The data to be signed, already hashed.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-k**, **\--publicKey**:

    The public key associated with keyPath in PEM format. Optional parameter.

  * **-o**, **\--signature**:

    Returns the signature in binary form.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_sign --keyPath HS/SRK/myRSASign --padding "RSA_PSS" --digest digest.file --signature signature.file --publicKey public_key.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
