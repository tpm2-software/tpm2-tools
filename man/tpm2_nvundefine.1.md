% tpm2_nvundefine(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvundefine**(1) - Undefine a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvundefine** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvundefine**(1) - Undefine a Non-Volatile (NV) index that was previously
defined with **tpm2_nvdefine**(1). The index is specified as an argument. It can
be specified as raw handle or an offset value to the nv handle range
"TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_AUTH\_HANDLE_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle may be specified.

  * **-P**, **\--auth**=_AUTH\_VALUE_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

```
tpm2_nvundefine   0x1500016 -C 0x40000001 -P passwd
```

[returns](common/returns.md)

[footer](common/footer.md)
