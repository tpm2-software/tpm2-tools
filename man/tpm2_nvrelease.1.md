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

  * **-a**, **--auth-handle**=_SECRET\_DATA\_FILE_:
    specifies the handle used to authorize:
    * **0x40000001** for **TPM_RH_OWNER**
    * **0x4000000C** for **TPM_RH_PLATFORM**

  * **-s**, **--size**=_SIZE_:
    specifies the size of data area in bytes.

  * **-P**, **--handle-passwd**=_HANDLE\_PASSWORD_:
    specifies the password of authHandle. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-S**, **--input-session-handle**=_SIZE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

```
tpm2_nvrelease -x 0x1500016 -a 0x40000001 -P passwd
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)