% tpm2_nvundefine(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvundefine**(1) - Delete a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvundefine** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvundefine**(1) - Deletes a Non-Volatile (NV) index that was previously
defined with **tpm2_nvdefine**(1). The index is specified as an argument. It can
be specified as raw handle or an offset value to the nv handle range
"TPM2_HR_NV_INDEX".

The tool is also capable of deleting NV indices with attribute `TPMA_NV_POLICY_DELETE`, and
the tool uses this attribute for the default hierarchy to select when `-C` is missing. The
default value for `-C` is the "owner" hierarchy when `TPMA_NV_POLICY_DELETE` is clear and
"platform" when `TPMA_NV_POLICY_DELETE` is set.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle may be specified.

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-S**, **\--session**=_POLICY_SESSION_:

    Specify a policy session to use when the NV index has attribute
    `TPMA_NV_POLICY_DELETE` set. This can also be used to specify an auxiliary
    session for auditing and or encryption/decryption of the parameters.
    Note:
    1. If TPM2_CC_NV_UndefineSpaceSpecial is invoked then only one additional
       aux session can be specified. The order of how sessions are specified
       also matters. First specification of `-S` is interpreted as the session
       for satisfying the ADMIN role required for
       TPM2_CC_NV_UndefineSpaceSpecial.

    2. If TPM2_CC_NV_Undefine is invoked then only two additional aux sessions
       can be specified.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, it simply returns
    a cpHash unless rphash is also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **\--with-policydelete**=_NONE_

    This must be specified when calculating cpHash with **\--tcti=none**. This
    is a requirement because there is no way to know if the attribute
    TPMA_NV_POLICYDELETE has been set from the NV index name alone.

  * **-n**, **\--name**=_FILE_:

    The name of the NV index that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Define an ordinary NV index and delete it
```bash
tpm2_nvdefine 1

tpm2_nvundefine 1
```

## Define an ordinary NV index with attribute `TPMA_NV_POLICY_DELETE` and delete it
```bash
tpm2_startauthsession -S s.ctx

tpm2_policyauthvalue -S s.ctx

tpm2_policycommandcode -S s.ctx -L policy.dat TPM2_CC_NV_UndefineSpaceSpecial

tpm2_nvdefine -C p -s 32 \
  -a "ppread|ppwrite|authread|authwrite|platformcreate|policydelete|write_stclear|read_stclear" \
  -L policy.dat 1

tpm2_flushcontext s.ctx

tpm2_startauthsession --policy-session -S s.ctx

tpm2_policyauthvalue -S s.ctx

tpm2_policycommandcode -S s.ctx TPM2_CC_NV_UndefineSpaceSpecial

tpm2_nvundefine -S s.ctx 1
```

[returns](common/returns.md)

[footer](common/footer.md)
