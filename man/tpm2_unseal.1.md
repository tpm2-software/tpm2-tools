% tpm2_unseal(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_unseal**(1) - Returns a data blob in a loaded TPM object. The data blob
is returned in clear.

# SYNOPSIS

**tpm2_unseal** [*OPTIONS*]

# DESCRIPTION

**tpm2_unseal**(1) - Returns a data blob in a loaded TPM object. The data blob
is returned in clear. The data is sealed at the time of the object creation using
the **tpm2_create** tool. Such an object intended for sealing data has to be of
the type _TPM\_ALG\_KEYEDHASH_.

# OPTIONS

  * **-c**, **\--object-context**=_CONTEXT\_OBJECT_:

    Object context for the loaded object. Either a file or a handle number.
    See section "Context Object Format".

  * **-p**, **\--auth**=_KEY\_AUTH_:

    Optional auth value to use for the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-o**, **\--output**=_OUT\_FILE_:

    Output file name containing the unsealed data. Defaults to stdout if not
    specified.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[pcr bank specifiers](common/pcr.md)

# EXAMPLES

```bash
echo "secretdata" > secret.data

tpm2_createprimary -Q -C e -g sha256 -G rsa -c primkey.ctx

tpm2_create -Q -g sha256 -u key_pub -r key.priv -i secret.data -C primkey.ctx

tpm2_load -Q -C primkey.ctx  -u key.pub  -r key.priv -n key.name -c key.ctx

tpm2_unseal -Q -c key.ctx -o unsealed.data

cat unsealed.data
secretdata
```

[returns](common/returns.md)

[footer](common/footer.md)
