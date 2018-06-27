% tpm2_nvrelease(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvrelease**(1) - Release a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvrelease** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvrelease**(1) - Release a Non-Volatile (NV) index that was previously
defined with tpm2_nvdefine(1).

# OPTIONS

  * **-x**, **--index**=_NV\_INDEX_:
    Specifies the index to release.

  * **-a**, **--hierarchy**=_AUTH_:
    specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-s**, **--size**=_SIZE_:
    specifies the size of data area in bytes.

  * **-P**, **--auth-hierarchy**=_AUTH\_HIERARCHY\_VALUE_:
    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/password.md)

# EXAMPLES

```
tpm2_nvrelease -x 0x1500016 -a 0x40000001 -P passwd
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
