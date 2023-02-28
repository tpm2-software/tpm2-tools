% tpm2_tr_encode(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_tr_encode**(1) - Encodes a peristent handle and `TPM2B_NAME` as a serialized `ESYS_TR` as
output.

# SYNOPSIS

**tpm2_tr_encode** [*OPTIONS*]

# DESCRIPTION

**tpm2_tr_encode**(1) - Encodes a peristent TPM2 handle along with a populated `TPM2B_PUBLIC` as
a serialized `ESYS_TR`. This is useful for moving a public and handle from one environment
where a TPM is not available to another environment with a TPM and make use of it through the
ESAPI API or tpm2-tools(1).

# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    Persistent handle.

[pubkey options](common/pubkey.md)

    Public key format.

  * **-o**, **\--output**=_FILE_:

    The output file path, recording the serialized `ESYS_TR`.


## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Serialize a public and handle as an ESYS_TR

```bash
tpm2_createprimary -c primary.ctx
tpm2_evictcontrol -c primary.ctx -o primary.tr 0x81000002
tpm2_readpublic -c primary.tr -o primary.pub
tpm2_tr_encode -c 0x81000002 -u primary.pub -o primary2.tr
```

[returns](common/returns.md)

[footer](common/footer.md)
