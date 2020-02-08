% tpm2_policyauthorizenv(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyauthorizenv**(1) - Allows for mutable policies by referencing to a
policy from an NV index.

# SYNOPSIS

**tpm2_policyauthorizenv** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policyauthorizenv**(1) - This command allows for policies to change by
referencing the authorization policy written to an NV index. The NV index
containing the authorization policy should remain readable even for trial
session. The index can be specified as raw handle or an offset value to the nv
handle range "TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-C** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Create a policypassword and write the policy digest to an NV Index. Build a
policyauthorizenv policy referencing the NV index in a *trial* session. The
resultant policy digest is then used in creation of objects.

In a policy authorization session, first satisfy the policy written to the
NV index. Then run the policyauthorizenv which satisfies the authorization for
the object.

## Define the test NV Index to store the auth policy
```bash
nv_test_index=0x01500001
tpm2_nvdefine -C o -p nvpass $nv_test_index -a "authread|authwrite" -s 34
```

## Define the auth policy
```bash
tpm2_startauthsession -S session.ctx
tpm2_policypassword -S session.ctx -L policy.pass
tpm2_flushcontext session.ctx
```

## Write the auth policy to the NV Index
```bash
echo "000b" | xxd -p -r | cat - policy.pass | \
tpm2_nvwrite -C $nv_test_index -P nvpass $nv_test_index -i-
```

## Define the policyauthorizenv
```bash
tpm2_startauthsession -S session.ctx
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass \
-L policyauthorizenv.1500001 $nv_test_index
tpm2_flushcontext session.ctx
```

## Create and load a sealing object with auth policy = policyauthorizenv
```bash
tpm2_createprimary -C o -c prim.ctx

echo "secretdata" | \
tpm2_create -C prim.ctx -u key.pub -r key.priv \
-a "fixedtpm|fixedparent|adminwithpolicy" -L policyauthorizenv.1500001 -i-

tpm2_load -C prim.ctx -u key.pub -r key.priv -c key.ctx
```

## Satisfy the auth policy stored in the NV Index and thus policyauthorizenv
```bash
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypassword -S session.ctx
tpm2_policyauthorizenv -S session.ctx -C $nv_test_index -P nvpass $nv_test_index
tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
