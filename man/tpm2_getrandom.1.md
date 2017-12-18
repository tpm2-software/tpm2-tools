% tpm2_getrandom(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_getrandom**(1) - Retrieves random bytes from the TPM.

# SYNOPSIS

**tpm2_getrandom** [*OPTIONS*] _SIZE_

# DESCRIPTION

**tpm2_getrandom**(1) - Returns the next _SIZE_ octets from the random number
generator. The _SIZE_ parameter is expected as the only argument to the tool.

# OPTIONS

  * **-o**, **--out-file**=_FILE_
    specifies the filename to output the raw bytes to. Defaults to stdout as a hex
    string.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

Generate a random 20 bytes and output the binary data to a file:

```
tpm2_getrandom -o random.out 20
```

Generate a random 8 bytes and output the hex formated data to stdout:

```
tpm2_getrandom 8
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)

