% tpm2_nvundefine(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvundefine**(1) - Undefine a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvundefine** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvundefine**(1) - Undefine a Non-Volatile (NV) index that was previously
defined with **tpm2_nvdefine**(1). The index is specified as an argument. It can
be specified as raw handle or an offset value to the nv handle range
"TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle may be specified.

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

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

```bash
tpm2_nvdefine   0x1500016 -C 0x40000001 -s 32 -a 0x2000A

tpm2_nvundefine   0x1500016 -C 0x40000001
```

[returns](common/returns.md)

[footer](common/footer.md)
