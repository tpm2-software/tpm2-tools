% tpm2_nvwrite(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvwrite**(1) - Write data to a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvwrite** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_nvwrite**(1) - Write data specified via _FILE_ to a Non-Volatile (NV) index.
If _FILE_ is not specified, it defaults to stdin.

# OPTIONS

  * **-x**, **--index**=_NV\_INDEX_:
    Specifies the index to define the space at.

  * **-o**, **--offset**=_OFFSET_:
    The offset within the NV index to start writing at.

  * **-a**, **--auth-handle**=_SECRET\_DATA\_FILE_:
    specifies the handle used to authorize:
    * **0x40000001** for **TPM_RH_OWNER**
    * **0x4000000C** for **TPM_RH_PLATFORM**

  * **-P**, **--handle-passwd**=_HANDLE\_PASSWORD_:
    specifies the password of authHandle. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-L**, **--set-list**==_PCR\_SELECTION\_LIST_:

    The list of pcr banks and selected PCRs' ids.
    _PCR\_SELECTION\_LIST_ values should follow the
    pcr bank specifiers standards, see section "PCR Bank Specfiers".

  * **-F**,**--pcr-input-file=_PCR\_INPUT\_FILE_

    Optional Path or Name of the file containing expected pcr values for the specified index.
    Default is to read the current PCRs per the set list.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

To write the file nv.data to index 0x150016:

```
tpm2_nvwrite -x 0x1500016 -a 0x40000001 -f nv.data
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
