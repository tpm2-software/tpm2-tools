% tss2_nvwrite(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_nvwrite**(1) -

# SYNOPSIS

**tss2_nvwrite** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_nvwrite**(1) - This command writes data to a "regular" (not pin, extend or counter) NV index. Only the full index can be written, partial writes are not allowed. If the provided data is smaller than the NV index's size, then it is padded up with zero bytes at the end.

# OPTIONS

These are the available options:

  * **-i**, **\--data**=_FILENAME_ or _-_ (for stdin):

    The data to write to the NV space.

  * **-p**, **\--nvPath**=_STRING_:

    Identifies the NV space to write to.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_nvwrite --nvPath=/nv/Owner/myNV --data=data.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
