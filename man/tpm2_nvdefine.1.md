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

  * **-a**, **--hierarchy**=_AUTH\_HIERARCHY_:
    specifies the handle used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-s**, **--size**=_SIZE_:
    specifies the size of data area in bytes. Defaults to MAX_NV_INDEX_SIZE
    which is typically 2048.

  * **-t**, **--attributes**=_ATTRIBUTES_
    Specifies the attribute values for the nv region used when creating the
    entity. Either the raw bitfield mask or "nice-names" may be used. See
    section "NV Attributes" for more details.

  * **-P**, **--auth-hierarchy**=_AUTH\_HIERARCHY\_VALUE_:
    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-p**, **--auth-index**=_INDEX\_PASSWORD_:
    Specifies the password of NV Index when created.
    HMAC and Password authorization values should follow the "authorization
    formatting standards", see section "Authorization Formatting".

  * **-L**, **--policy-file**=_POLICY\_FILE_:
    Specifies the policy digest file for policy based authorizations.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[nv attributes](common/nv-attrs.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

```
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t 0x2000A
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t ownerread|ownerwrite|policywrite -p 1a1b1c
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
