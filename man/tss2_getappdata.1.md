% tss2_getappdata(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getappdata**(1)

# SYNOPSIS

**tss2_getappdata** [*OPTIONS*]

# DESCRIPTION

**tss2_getappdata**(1) - This command returns the previously stored application data for an object.

# OPTIONS

These are the available options:

  * **-p**, **\--path** _STRING_:

    Path of the object for which the appData will be loaded.

  * **-o**, **\--appData** _FILENAME_ or _-_ (for stdout):

    Returns a copy of the stored data. Optional parameter.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_getappdata --path HS/SRK/myRSACrypt --appData appData.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
