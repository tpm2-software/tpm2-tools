% tpm2_pcrevent(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrevent**(1) - Hashes a file and optionally extends a pcr.

# SYNOPSIS

**tpm2_pcrevent** [*OPTIONS*] _FILE_ _PCR\_INDEX_

# DESCRIPTION

**tpm2_pcrevent**(1) - Hashes _FILE_ if specified or stdin. It uses all of the
hashing algorithms that the TPM supports.

Optionally, if a PCR index is specified, it extends that PCR for all
supported algorithms with the hash digest. _FILE_ and _PCR\_INDEX\_ arguments
don't need to come in any particular order.

In either case, it
outputs to stdout the hash algorithm used and the digest value,
one per line:

_alg_:_digest_

Where _alg_ is the algorithm used (like sha1) and _digest_ is the digest
resulting from the hash computation of _alg_ on the data.

See sections 23.1 and sections 17 of the [TPM2.0 Specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)

# OPTIONS

These options control extending the pcr:

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for PCR.

  * **-S**, **\--session**=_FILE_:

    Specifies the auxiliary sessions for the command.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Hash a file
```bash
echo "foo" > data
tpm2_pcrevent data
```

## Hash a file and extend PCR 8
```bash
echo "foo" > data
tpm2_pcrevent 8 data
```

[returns](common/returns.md)

[footer](common/footer.md)
