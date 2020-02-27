% tpm2_clear(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_clear**(1) - Clears lockout, endorsement and owner hierarchy
authorization values.

# SYNOPSIS

**tpm2_clear** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_clear**(1) - Send a clear command to the TPM to clear the 3 hierarchy
authorization values. As an argument takes the auth value for either platform or
lockout hierarchy

**NOTE**: All objects created under the respective hierarchies are lost.

# OPTIONS

  * **-c**, **\--auth-hierarchy**=_OBJECT_:

    Specifies the hierarchy the tools should operate on. By default
    it operates on the lockout hierarchy.

    **NOTE : Operating on platform hierarchy require platform authentication.**

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the _AUTH_ to be set for
    the object specified with **-c**.

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

## Set owner, endorsement and lockout authorizations to an empty value

```bash
tpm2_clear lockoutpasswd
```

## Clear the authorization values on the platform hierarchy
```bash
tpm2_clear -c p
```

[returns](common/returns.md)

[footer](common/footer.md)
