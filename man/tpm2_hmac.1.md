% tpm2_hmac(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_hmac**(1) - Performs an HMAC operation with the TPM.

# SYNOPSIS

**tpm2_hmac** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_hmac**(1) - Performs an HMAC operation and returns the results.
If argument file is not specified, then data is read from stdin.

The hashing algorithm defaults to the keys scheme or sha256 if the key has a
NULL scheme.

Output defaults to _STDOUT_ and binary format unless otherwise specified via
**-o** and **--hex** options respectively.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    The context object of the symmetric signing key providing the HMAC key.
    Either a file or a handle number. See section "Context Object Format".

  * **-p**, **\--auth**=_AUTH_:

    Optional authorization value to use the key specified by **-c**.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm to use.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **\--hex**

	Convert the output hmac to hex format without a leading "0x".

  * **-o**, **\--output**=_FILE_:

    Optional file record of the HMAC result. Defaults to _STDOUT_.

  * **-t**, **\--ticket**=_FILE_:

    Optional file record of the ticket result.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the file path for the data
    to HMAC. Defaults to _STDIN_ if not specified.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[authorization formatting](common/alg.md) details the methods for specifying
_ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Setup
```bash
# create a primary object
tpm2_createprimary -c primary.ctx

# create an hmac key
tpm2_create -C primary.ctx -G hmac -c hmac.key
```

### Perform an HMAC with Default Hash Algorithm
Perform an hmac using the key's default scheme (hash algorithm) and
output to stdout in hexidecimal format.

```bash
tpm2_hmac -c hmac.key --hex data.in
e6eda48a53a9ddbb92f788f6d98e0372d63a408afb11aca43f522a2475a32805
```

[returns](common/returns.md)

[footer](common/footer.md)
