% tpm2_getrandom(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getrandom**(1) - Retrieves random bytes from the TPM.

# SYNOPSIS

**tpm2_getrandom** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_getrandom**(1) - Returns the next _SIZE_ octets from the random number
generator. The _SIZE_ parameter is expected as the only argument to the tool.

Note that the TPM specification recommends that TPM's fix the number of
available entry to the maximum size of a hash algorithm output in bytes.

Most TPMs do this, and thus the tool verifies that input size is bounded by
property **TPM2_PT_MAX_DIGEST** and issues an error if it is too large.

Output defaults to *stdout* and binary format unless otherwise specified with
**-o** and **--hex** options respectively.

# OPTIONS

  * **-o**, **\--output**=_FILE_

    Specifies the filename to output the raw bytes to. Defaults to stdout as a
    hex string.

  * **\--hex**

	Convert the output data to hex format without a leading "0x".

  * **-f**, **\--force**

    Override checking that the:
    - Requested size is within the hash size limit of the TPM.
    - Number of retrieved random bytes matches requested amount.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. Multiple of these can
    be specified. For example, you can have one session for auditing and another
    for encryption of the parameters.

  * **\--cphash**=_FILE_:

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, in absence of rphash
    option, The tool will not actually execute the command, it simply returns a
    cpHash.

  * **\--rphash**=_FILE_:

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

* **ARGUMENT** the command line argument specifies the size of the output.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Generate a random 20 bytes and output the binary data to a file
```bash
tpm2_getrandom -o random.out 20
```

## Generate a random 8 bytes and output the hex formatted data to stdout
```bash
tpm2_getrandom 8
```

[returns](common/returns.md)

[footer](common/footer.md)
