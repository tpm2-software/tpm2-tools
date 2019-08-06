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

tpm2_unseal -c item.context -p abc123 -o out.dat

tpm2_unseal -c 0x81010001 -p "hex:123abc" -o out.dat

tpm2_unseal -c item.context -p pcr:sha256:0,1=pcr.value -o out.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
