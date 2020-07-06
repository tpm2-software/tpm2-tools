% tss2_nvread(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvread**(1) -

# SYNOPSIS

**tss2_nvread** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_nvread**(1) - This command reads the entire data from an NV index of the TPM.

# OPTIONS

These are the availabe options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--data**=_FILENAME_ or _-_ (for stdout):

    Returns the value read from the NV space.

  * **-p**, **\--nvPath**=_STRING_:

    Identifies the NV space to read.

  * **-l**, **\--logData**=_FILENAME_ or _-_ (for stdout):

    Returns the JSON encoded log, if the NV index is of type "extend" and an empty string otherwise. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_nvread --nvPath=/nv/Owner/myNV --data=data.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
