% tss2_getdescription(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getdescription**(1)

# SYNOPSIS

**tss2_getdescription** [*OPTIONS*]

# DESCRIPTION

**tss2_getdescription**(1) - This command returns the previously stored application data for an object. If no description is present, description SHALL be set to an empty string.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**:

    The path of the object for which the appData will be loaded. MUST NOT be NULL.

  * **-o**, **\--description**:

    Returns the stored description. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

```
tss2_getdescription --path HS/SRK --description description.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
