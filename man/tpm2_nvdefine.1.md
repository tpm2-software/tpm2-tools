% tpm2_nvdefine(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvdefine**(1) - Define a TPM Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvdefine** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvdefine**(1) - Define an NV index with given auth value. The index is
specified as an argument. It can be specified as raw handle or an offset value
to the nv handle range "TPM2_HR_NV_INDEX". If an index isn't specified, the tool
uses the first free index. The tool outputs the nv index defined on success.

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

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used to compute the name of the Index and used for the
    authorization policy. If the index is an extend index, the hash algorithm is
    used for the extend.

  * **-a**, **\--attributes**=_ATTRIBUTES_

    Specifies the attribute values for the nv region used when creating the
    entity. Either the raw bitfield mask or "nice-names" may be used. See
    section "NV Attributes" for more details. If not specified, the attributes
    default to various selections based on the hierarchy the index is defined in.

    For the owner hiearchy the defaults are:
      - TPMA_NV_OWNERWRITE
      - TPMA_NV_OWNERREAD

    For the platform hiearchy, the defaults are:
      - TPMA_NV_PPWRITE
      - TPMA_NV_PPREAD

    If a policy file is specified, the hiearchy chosen default attributes are bitwise or'd with:
      - TPMA_NV_POLICYWRITE
      - TPMA_NV_POLICYREAD

    If a policy file is **NOT** specified, the hiearchy chosen default attributes are bitwise or'd with:
      - TPMA_NV_AUTHWRITE
      - TPMA_NV_AUTHREAD

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

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. Multiple of these can
    be specified. For example, you can have one session for auditing and another
    for encryption/decryption of the parameters.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[object attribute specifiers](common/nv-attrs.md) details the options for
specifying the nv attributes _ATTRIBUTES_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_nvdefine   0x1500016 -C o -s 32 -a 0x2000A

tpm2_nvdefine   0x1500016 -C o -s 32 -a ownerread|ownerwrite|policywrite -p 1a1b
```

[returns](common/returns.md)

[footer](common/footer.md)
