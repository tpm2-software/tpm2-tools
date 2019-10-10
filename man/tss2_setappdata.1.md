% tss2_setappdata(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_setappdata**(1)

# SYNOPSIS

**tss2_setappdata** [*OPTIONS*]

# DESCRIPTION

**tss2_setappdata**(1) - allows an application to associate an arbitrary data blob with a given object. The data SHALL be stored and the same data SHALL be returned upon Fapi_GetAppData. Previously stored data SHALL be overwritten by this function. If NULL is passed in, stored data SHALL be deleted.

# OPTIONS

These are the available options:

  * **-p**, **\--path**:

    Path of the object for which the appData will be stored. MUST NOT be NULL.

  * **-i**, **\--appData**:

    The data to be stored. MAY be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_setappdata --path HS/SRK/myRSACrypt --appData appData
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
