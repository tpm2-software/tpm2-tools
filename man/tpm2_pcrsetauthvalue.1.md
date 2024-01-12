% tpm2_pcrsetauthvalue(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_pcrsetauthvalue**(1) - Add or change the authvalue of a PCR handle which
is in the authorization set.

# SYNOPSIS

**tpm2_pcrsetauthvalue** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_pcrsetauthvalue**(1) - Add or change the authvalue of a PCR handle which
is in the authorization set. Only those PCR handles which are in the
authorization set can be specified. To retrieve which specific PCR handles in a
given TPM implementation are in the authorization set, run **tpm2_getcap** with
option **pcrhandles-with-auth**.

# OPTIONS

  * **-P**, **\--auth**=_AUTH_:

    Specifies the existing authorization value for the PCR handle.

  * **-p**, **\--newauth**=_AUTH_:

    Specifies the new authorization value to be set for the PCR handle.

  * **ARGUMENT** the command line argument specifies the PCR handle.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Change authvalue of the PCR handle 20

```bash
tpm2_pcrsetauthvalue -p newauthvalue 0x00000014
```

[returns](common/returns.md)

[footer](common/footer.md)
