% tpm2_commit(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_commit**(1) - Performs the first part of an ECC anonymous signing
operation.

# SYNOPSIS

**tpm2_commit** [*OPTIONS*]

# DESCRIPTION

**tpm2_commit**(1) - Performs the first part of an ECC anonymous signing
operation. The TPM will perform the point multiplications on the provided points
and return intermediate signing values. The signing key is an ECC key. The key
cannot be a sign+decrypt key and must have an anonymous signing scheme.
TPM_ALG_ECDAA is the only supported anonymous scheme.

# OPTIONS

  * **ARGUMENT**=_FILE_:

    Specify the input data used to derive the x coordinate of the basepoint.

  * **\--basepoint-y**=_FILE_:

    Specify the y coordinate of the basepoint.

  * **\--eccpoint-P**=_FILE_:

    Specify a point on the curve used by sign handle.

  * **\--eccpoint-K**=_FILE_:

    Output ECC point K ≔ \[ds\](x2, y2).

  * **\--eccpoint-L**=_FILE_:

    Output ECC point L ≔ \[r\](x2, y2).

  * **-u**, **\--public**=_FILE_:

    Output ECC point E ≔ [r]P1.

  * **-t**, **\--counter**=_FILE_

    Specify file path to save the least-significant 16 bits of commit count.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the created object.

  * **-c**, **\--context**=_FILE_:

    Context object pointing to the the key used for signing. Either a file or a
    handle number. See section "Context Object Format".

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

tpm2_commit -c key.ctx -t count.er \
--eccpoint-K K.bin --eccpoint-L L.bin -u E.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
