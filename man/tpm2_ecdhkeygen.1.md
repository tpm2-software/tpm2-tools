% tpm2_ecdhkeygen(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_ecdhkeygen**(1) - Creates an ephemeral key and uses it to generate the
shared secret value using the parameters from a ECC public key.

# SYNOPSIS

**tpm2_ecdhkeygen** [*OPTIONS*]

# DESCRIPTION

**tpm2_ecdhkeygen**(1) - Creates an ephemeral key and uses it to generate the
shared secret value using the parameters from a ECC public key.

# OPTIONS

  * **-c**, **\--context**=_FILE_:

    Context object pointing to ECC public key.
    Either a file or a handle number. See section "Context Object Format".

  * **-u**, **\--public**=_FILE_:

    Output ECC point Q.

  * **-o**, **\--output**=_FILE_

    Specify file path to save the calculated ecdh secret or Z point.

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
tpm2_createprimary -C o -c prim.ctx -Q

tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdaa

tpm2_ecdhkeygen -u ecdh.pub -o ecdh.priv -c key.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
