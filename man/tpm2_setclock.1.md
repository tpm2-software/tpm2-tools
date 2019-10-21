% tpm2_setclock(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_setclock**(1) - Sets the time on the TPM.

# SYNOPSIS

**tpm2_setclock** [*OPTIONS*] __TIME__

# DESCRIPTION

**tpm2_setclock**(1) - Sets the clock on the TPM to a time in the **future**. The
sole argument is the clock time as a number to set.

# OPTIONS

  * **-c**, **\--hierarchy**=_OBJECT_:

    The hierarchy to use for authorization, either platform or owner.
    Defaults to the owner hierarchy if not specified.

  * **-p**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy specified by option
    **-c**.

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

## Set the clock

Set the clock using the owner password.

```bash
tpm2_setclock -p ownerpw 13673142
```

[returns](common/returns.md)

[footer](common/footer.md)
