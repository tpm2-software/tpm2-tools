% tpm2_readpublic(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_readpublic**(1) - Read the public area of a loaded object.

# SYNOPSIS

**tpm2_readpublic** [*OPTIONS*]

# DESCRIPTION

**tpm2_readpublic**(1) Reads the public area of a loaded object.

# OPTIONS

  * **-H**, **--object**=_HANDLE_:

    The loaded object handle to read the public data of.

  * **-c**, **--context-object**=_OBJECT\_CONTEXT\_FILE_:

    Filename for object context.

  * **-o**, **--opu**:

    The output file path, recording the public portion of the object.

  * **-f**, **--format**=_FORMAT_:

    Specify the output format. Valid output formats are:
    * yaml - output in the YAML file format.

[pubkey options](common/pubkey.md)

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_readpublic -H 0x81010002 --opu output.dat
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)
