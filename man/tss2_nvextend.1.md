% tss2_nvextend(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvextend**(1) -

# SYNOPSIS

**tss2_nvextend** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_nvextend**(1) - This command performs an extend operation on an NV index
(i.e. an NV index that behaves similar to a PCR).

# OPTIONS

These are the available options:

  * **-i**, **\--data**=_FILENAME_ or _-_ (for stdin):

    The data to be extended into the NV space.

  * **-p**, **\--nvPath**=_STRING_:

    Identifies the NV space to write.

  * **-l**, **\--logData**=_FILENAME_ or _-_ (for stdin):

    A JSON representation of data to be written to the PCR's event log. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_nvextend --nvPath=/nv/Owner/NvExtend --data=data.file --logData=logData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
