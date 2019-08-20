% tpm2_policyduplicationselect(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyduplicationselect**(1) - Restricts duplication to a specific new
parent.

# SYNOPSIS

**tpm2_policyduplicationselect** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyduplicationselect**(1) - Restricts duplication to a specific new
parent.

# OPTIONS

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-n**, **\--object-name**=_FILE_:

    Input name file of the object to be duplicated.

  * **-N**, **\--parent-name**=_FILE_:

    Input name file of the new parent.

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **\--include-object**:

    If exists, the object name will be included in the value in policy digest.


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Setup a duplication role policy to restricted new parent

### Create source parent and destination(or new) parent
```bash
tpm2_createprimary -C n -g sha256 -G rsa -c dst_n.ctx -Q
tpm2_createprimary -C o -g sha256 -G rsa -c src_o.ctx -Q
```

### Create the restricted parent policy
```bash
tpm2_readpublic -c dst_n.ctx -n dst_n.name -Q
tpm2_startauthsession -S session.ctx
tpm2_policyduplicationselect -S session.ctx  -N dst_n.name \
-L policydupselect.dat -Q
tpm2_flushcontext session.ctx
rm session.ctx
```

### Create the object to be duplicated using the policy
```bash
tpm2_create -C src_o.ctx -g sha256 -G rsa -r dupkey.priv -u dupkey.pub \
-L policydupselect.dat  -a "sensitivedataorigin|sign|decrypt" -c dupkey.ctx -Q
tpm2_readpublic -c dupkey.ctx -n dupkey.name -Q
```

### Satisfy the policy and duplicate the object
```bash
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policyduplicationselect -S session.ctx  -N dst_n.name -n dupkey.name -Q
tpm2_duplicate -C dst_n.ctx -c dupkey.ctx -G null -p session:session.ctx \
-r new_dupkey.priv -s dupseed.dat
tpm2_flushcontext  session.ctx
rm session.ctx
```

# NOTES

* This command usually cooperates with **tpm2_duplicate**(1), so referring to
the man page of **tpm2_duplicate**(1)
is recommended.

* This command will set the policy session's command code to
**TPM_CC_Duplicate** which enables duplication role of the policy.

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
