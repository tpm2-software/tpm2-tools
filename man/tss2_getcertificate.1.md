% tss2_getcertificate(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getcertificate**(1) -

# SYNOPSIS

**tss2_getcertificate** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_getcertificate**(1) - This command returns the PEM encoded X.509 certificate associated with the key at path.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**=_STRING_:

    The entity whose certificate is requested.

  * **-o**, **\--x509certData**=_FILENAME_ or _-_ (for stdout):

    Returns the PEM encoded certificate. If no certificate is stored, then an empty string is returned.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_getcertificate --path=HS/SRK/myRSACrypt --x509certData=x509certData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
