% tss2_setcertificate(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_setcertificate**(1) -

# SYNOPSIS

**tss2_setcertificate** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_setcertificate**(1) - This command associates an x509 certificate in PEM encoding into the path of a key.

# OPTIONS

These are the available options:

  * **-p**, **\--path**=_STRING_:

    Identifies the entity to be associated with the certificate.

  * **-i**, **\--x509certData**=_FILENAME_ or _-_ (for stdin):

    The PEM encoded certificate. Optional parameter. If omitted, then the stored
    x509 certificate is removed.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_setcertificate --path=HS/SRK/myRSACrypt --x509certData=x509certData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
