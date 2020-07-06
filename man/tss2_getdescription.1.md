% tss2_getdescription(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getdescription**(1)

# SYNOPSIS

**tss2_getdescription** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_getdescription**(1) - This command returns the previously stored application data for an object. If no
description is present, an empty string is returned.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**=_STRING_:

    The path of the object for which the description will be loaded.

  * **-o**, **\--description**=_FILENAME_ or _-_ (for stdout):

    Returns the stored description.

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
tss2_getdescription --path=HS/SRK --description=description.file
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
