% tss2_setdescription(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_setdescription**(1)

# SYNOPSIS

**tss2_setdescription** [*OPTIONS*]

# DESCRIPTION

**tss2_setdescription**(1) - This command allows an application to assign a human readable description to an object in the metadata store. Previously stored descriptions SHALL be overwritten by this function. If NULL is passed in, any stored description SHALL be deleted.

# OPTIONS

These are the available options:

  * **-i**, **\--description**:

    The data to be stored as description for the object. MAY be NULL.

  * **-p**, **\--path**:

    The path of the object for which the description will be stored. MUST NOT be NULL.


[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_setdescription --path HS/SRK --description object-description
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
