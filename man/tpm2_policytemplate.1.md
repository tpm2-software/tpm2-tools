% tpm2_policytemplate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policytemplate**(1) - Couples a policy with public template data digest
of an object.

# SYNOPSIS

**tpm2_policytemplate** [*OPTIONS*]

# DESCRIPTION

**tpm2_policytemplate**(1) - Couples a policy with public template data digest
of an object. This is a deferred assertion where the hash of the public template
data of an object is checked against the one specified in the policy.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **--template-hash**=_FILE_:

    The file containing the hash of the public template of the object.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

# Restrict the primary object type created under a hierarchy

```bash
tpm2_createprimary -C o -c prim.ctx --template-data template.data

cat template.data | openssl dgst -sha256 -binary -out template.hash

tpm2_startauthsession -S session.ctx -g sha256
tpm2_policytemplate -S session.ctx -L policy.template \
--template-hash template.hash
tpm2_flushcontext session.ctx

tpm2_setprimarypolicy -C o -g sha256 -L policy.template

tpm2_startauthsession -S session.ctx -g sha256 --policy-session
tpm2_policytemplate -S session.ctx --template-hash template.hash
tpm2_createprimary -C o -c prim2.ctx -P session:session.ctx
tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
