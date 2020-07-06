% tss2_getinfo(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getinfo**(1) -

# SYNOPSIS

**tss2_getinfo** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_getinfo**(1) - This command returns a UTF-8 string identifying the version of the FAPI, the TPM, configurations and other relevant information in a human readable format.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--info**=_FILENAME_ or _-_ (for stdout):

    Returns the FAPI and TPM information.


[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_getinfo --info=info.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
