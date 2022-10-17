% tss2_getrandom(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_getrandom**(1) -
# SYNOPSIS

**tss2_getrandom** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_getrandom**(1) - This command uses the TPM to create an array of random bytes.

# OPTIONS

These are the available options:

  * **-n**, **\--numBytes**=_INTEGER_:

    The number of bytes requested by the caller.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-o**, **\--data**=_FILENAME_ or _-_ (for stdout):

    The returned random bytes.

  * **\--hex**

    Convert the output data to hex format without a leading "0x".

[common tss2 options](common/tss2-options.md)

# EXAMPLE
```
    tss2_getrandom --numBytes=20 --data=- | hexdump -C
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
