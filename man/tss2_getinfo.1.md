% tss2_getinfo(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getinfo**(1) -

# SYNOPSIS

**tss2_getinfo** [*OPTIONS*]

# DESCRIPTION

**tss2_getinfo**(1) - This command returns a UTF-8 string identifying the version of the FAPI, the TPM, configurations and other relevant information in a human readable format. The concrete content of this string is implementation specific.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--info**:

    Returns the FAPI and TPM information. MUST NOT be NULL.


[common tss2 options](common/tss2-options.md)

# EXAMPLE

tss2_getinfo --info data.info

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
