% tpm2_nvdefine(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvdefine**(1) - Define a TPM Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvdefine** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvdefine**(1) - Define an NV index with given auth value. The index is
specified as an argument. It can be specified as raw handle or an offset value
to the nv handle range "TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the handle used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

  * **-s**, **\--size**=_NATURAL_NUMBER_:

    Specifies the size of data area in bytes. Defaults to **MAX_NV_INDEX_SIZE**
    which is typically 2048.

  * **-a**, **\--attributes**=_ATTRIBUTES_

    Specifies the attribute values for the nv region used when creating the
    entity. Either the raw bitfield mask or "nice-names" may be used. See
    section "NV Attributes" for more details.

  * **-P**, **\--hierarchy-auth**=_AUTH_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-p**, **\--index-auth**=_AUTH_:

    Specifies the password of NV Index when created.
    HMAC and Password authorization values should follow the "authorization
    formatting standards", see section "Authorization Formatting".

  * **-L**, **\--policy**=_FILE_:

    Specifies the policy digest file for policy based authorizations.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[object attribute specifiers](common/obj-attrs.md) details the options for
specifying the object attributes _ATTRIBUTES_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_nvdefine   0x1500016 -C 0x40000001 -s 32 -a 0x2000A

tpm2_nvdefine   0x1500016 -C 0x40000001 -s 32 \
-a ownerread|ownerwrite|policywrite -p 1a1b1c
```

[returns](common/returns.md)

[footer](common/footer.md)
