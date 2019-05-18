% tpm2_nvrelease(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvrelease**(1) - Release a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvrelease** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvrelease**(1) - Release a Non-Volatile (NV) index that was previously
defined with **tpm2_nvdefine**(1).

# OPTIONS

  * **-x**, **\--index**=_NV\_INDEX_:

    Specifies the index to release.

  * **-a**, **\--hierarchy**=_AUTH_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-P**, **\--auth-hierarchy**=_AUTH\_HIERARCHY\_VALUE_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

```
tpm2_nvrelease -x 0x1500016 -a 0x40000001 -P passwd
```

[returns](common/returns.md)

[footer](common/footer.md)
