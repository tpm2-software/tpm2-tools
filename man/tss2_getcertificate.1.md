% tss2_getcertificate(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getcertificate**(1) -

# SYNOPSIS

**tss2_getcertificate** [*OPTIONS*]

# DESCRIPTION

**tss2_getcertificate**(1) - This command returns the PEM encoded X.509 certificate associated with the key at path.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**:

    The entity whose certificate is requested. MUST NOT be NULL.

  * **-o**, **\--x509certData**:

    Returns the PEM encoded certificate. MUST NOT be NULL. If no certificate is stored, then an empty string is returned.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_getcertificate --path HS/SRK/myRSACrypt --x509certData myRSACrypt.cert

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
