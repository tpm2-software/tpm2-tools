% tpm2_hash(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_hash**(1) - Performs a hash operation with the TPM.

# SYNOPSIS

**tpm2_hash** [*OPTIONS*] [*ARGUMENT* OR *STDIN*]

# DESCRIPTION

**tpm2_hash**(1) - Performs a hash operation on file and returns the results.
If argument is not specified, then data is read from stdin. If the results of the
hash will be used in a signing operation that uses a restricted signing key,
then the ticket returned by this command can indicate that the hash is safe to
sign.

Output defaults to *stdout* and binary format unless otherwise specified via
**-o** and **--hex** options respectively.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Hierarchy to use for the ticket. Defaults to **o**, **TPM_RH_OWNER**, when
    no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **e** for **TPM_RH_ENDORSEMENT**
      * **n** for **TPM_RH_NULL**

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hashing algorithm for the digest operation.

  * **\--hex**

	Convert the output hmac to hex format without a leading "0x".

  * **-o**, **\--output**=_FILE_ or _STDOUT_:

    Optional file to save the hash result. Defaults to stdout in hex form.

  * **-t**, **\--ticket**=_TICKET\_FILE_

    Optional file record of the ticket result. Defaults to stdout in hex form.

  * **ARGUMENT** or **STDIN** the command line argument specifies the _FILE_ to
    hash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/alg.md) details the methods for specifying the
_ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Hash a file with sha1 hash algorithm and save the hash and ticket to a file
```bash
tpm2_hash -C e -g sha1 -o hash.bin -t ticket.bin data.txt
```

[returns](common/returns.md)

[footer](common/footer.md)
