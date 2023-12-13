% tpm2_ecdhzgen(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_ecdhzgen**(1) - Recovers the shared secret value (Z) from a public point
and a specified private key.

# SYNOPSIS

**tpm2_ecdhzgen** [*OPTIONS*]

# DESCRIPTION

**tpm2_ecdhzgen**(1) - Recovers the shared secret value (Z) from a public point
and a specified private key. It will perform the multiplication of the provided
inPoint (QB) with the private key (ds) and return the coordinates of the
resultant point (Z = (xZ , yZ) ≔ [hds]QB; where h is the cofactor of the curve).

# OPTIONS

  * **-c**, **\--key-context**=_FILE_:

    Context object pointing to ECC key.
    Either a file or a handle number. See section "Context Object Format".

  * **-p**, **\--key-auth**=_AUTH_:

    The authorization value for the ECC key object.

  * **-u**, **\--public**=_FILE_:

    Input ECC point Q.

  * **-k**, **\--public-key**=_FILE_:

    Input ECC public key with point Q.

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

tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdh

tpm2_ecdhkeygen -u ecdh.pub -o ecdh.priv -c key.ctx

tpm2_ecdhzgen -u ecdh.pub -o ecdh.dat -c key.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
