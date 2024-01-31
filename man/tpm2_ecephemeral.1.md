% tpm2_ecephemeral(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_ecephemeral**(1) - Creates an ephemeral key for use in a two-phase key
exchange protocol.

# SYNOPSIS

**tpm2_ecephemeral** [*OPTIONS*]

# DESCRIPTION

**tpm2_ecephemeral**(1) - Creates an ephemeral key for use in a two-phase key
exchange protocol.

# OPTIONS

  * **ARGUMENT**=_ALGORITHM_:

    Specify the ECC curve. Example ecc521.

  * **-u**, **\--public**=_FILE_

    Specify the file path to save the ephemeral public point Q ≔ [r]G.

  * **-t**, **\--counter**=_FILE_

    Specify file path to save the least-significant 16 bits of commit count.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_ecephemeral -u ecc.q -t ecc.ctr ecc256
```

[returns](common/returns.md)

[footer](common/footer.md)
