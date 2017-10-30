% tpm2_nvdefine(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvdefine**(1) - define a TPM Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvdefine** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvdefine**(1) - Define NV index with given auth value.

# OPTIONS

  * **-x**, **--index**=_NV\_INDEX_:
    Specifies the index to define the space at.

  * **-a**, **--auth-handle**=_SECRET\_DATA\_FILE_:
    specifies the handle used to authorize:
    * **0x40000001** for **TPM_RH_OWNER**
    * **0x4000000C** for **TPM_RH_PLATFORM**

  * **-s**, **--size**=_SIZE_:
    specifies the size of data area in bytes. Defaults to MAX_NV_INDEX_SIZE
    which is typically 2048.

  * **-t**, **--attributes**=_ATTRIBUTES_
    Specifies the attribute values for the nv region used when creating the
    entitiy. Either the raw bitfield mask or "nice-names" may be used. See
    section "NV Attributes" for more details.

  * **-P**, **--handle-passwd**=_HANDLE\_PASSWORD_:
    specifies the password of authHandle. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-I**, **--index-passwd**=_INDEX\_PASSWORD_:
    specifies the password of NV Index when created. Follows the same formatting
    guidelines as the handle password or -P option.

  * **-L**, **--policy-file**=_POLICY\_FILE_:
    Specifies the policy digest file for policy based authorizations.

  * **-S**, **--input-session-handle**=_SIZE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[nv attributes](common/nv-attrs.md)

[password formatting](common/password.md)

# EXAMPLES

```
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t 0x2000A
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t ownerread|ownerwrite|policywrite -I 1a1b1c
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)