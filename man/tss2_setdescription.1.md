% tss2_setdescription(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_setdescription**(1)

# SYNOPSIS

**tss2_setdescription** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_setdescription**(1) - This command allows an application to assign a human readable description to an object in the FAPI metadata store. The stored data can be returned with tss2_getdescription. Previously stored data is overwritten by this function. If an empty description is passed in, the stored data is deleted.

# OPTIONS

These are the available options:

  * **-i**, **\--description**=_STRING_:

    The data to be stored as description for the object. Optional parameter.
    Previously stored descriptions are overwritten by this function. If omitted
    any stored description is deleted.

  * **-p**, **\--path**=_STRING_:

    The path of the object for which the description will be stored.


[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_setdescription --path=HS/SRK --description=description
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
