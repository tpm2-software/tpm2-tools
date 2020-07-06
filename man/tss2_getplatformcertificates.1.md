% tss2_getplatformcertificates(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getplatformcertificates**(1) -

# SYNOPSIS

**tss2_getplatformcertificates** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_getplatformcertificates**(1) - This command returns the set of platform certificates concatenated in a continuous buffer if the platform provides platform certificates. Platform certificates for TPM 2.0 can consist not only of a single certificate but also a series of so-called delta certificates.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--certificates**=_FILENAME_ or _-_ (for stdout):

    Returns a continuous buffer containing the concatenated platform certificates.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_getplatformcertificates --certificates=certificates.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
