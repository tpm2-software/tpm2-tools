% tss2_gettpm2object(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_gettpm2object**(1)

# SYNOPSIS

**tss2_gettpm2object** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_gettpm2object**(1) -  With this command for FAPI objects context
files which can be used by tpm2 tool commands can be created.
For persistent object only the textual representation of the handle number as
hex number will be written and for keys a tpm2 tool context file will
be written.
If the default TCTI differs from the FAPI profile the default the tcti can
be defined with the -T (--tcti) option.
**Note** To avoid wrong nv_written state in keystore before writing data
to the NV ram with tpm2_nvwrite, at least an empty string should be
written with tss2_nvwrite.

# OPTIONS

These are the available options:

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-p**, **\--path**=_STRING_:

    Path of the object for which the application data will be loaded.

  * **-c**, **\--context**=_FILENAME_ or _-_ (for stdout):

     The returned key context or handle.

[common tss2 options](common/tss2-options.md)

# EXAMPLES
```
tss2_gettpm2object --path=/HS/SRK/myRSACrypt --key-context=mykey.ctx
tss2_gettpm2object --path=/nv/Owner/mynv -c-
```
The command can be used in options of tpm2 commands:

```
handle=$(tss2_gettpm2object --path=/nv/Owner/mynv -c-)
tpm2_nvread $handle

```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
