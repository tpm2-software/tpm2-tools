% tpm2_nvreadlock(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvreadlock**(1) - Lock the Non-Volatile (NV) index for further reads.

# SYNOPSIS

**tpm2_nvreadlock** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvreadlock**(1) - Lock the Non-Volatile (NV) index for further reads. The index
is released on subsequent restart of the machine.

# OPTIONS

  * **-x**, **--index**=_NV\_INDEX_:

    Specifies the index to define the space at.

  * **-a**, **--hierarchy**=_AUTH_:

    Specifies the hierarchy used to authorize:
    * **o** for **TPM_RH_OWNER**
    * **p** for **TPM_RH_PLATFORM**
    Defaults to **o**, **TPM_RH_OWNER**, when no value has been
    specified.

  * **-P**, **--auth-hierarchy**=_AUTH\_HIERARCHY\_VALUE_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Lock an index protected by a password
```
tpm2_nvreadlock -x 0x1500016 -a 0x40000001 -P passwd
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
