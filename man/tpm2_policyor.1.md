% tpm2_policyor(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyor**(1) - logically OR's two policies together.

# SYNOPSIS

**tpm2_policyor** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyor**(1) - Generates a policy_or event with the TPM. It expects a
session to be already established via **tpm2_startauthsession**(1). If
the input session is a trial session this tool generates a policy digest that
compounds two or more input policy digests such that the resulting policy digest
requires at least one of the policy events being true. If the input session is
real policy session **tpm2_policyor**(1) authenticates the object successfully
if at least one of the policy events are true.

# OPTIONS

  * **-L**, **\--policy**=_FILE_:

    File to save the compounded policy digest.

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **ARGUMENT** the command line argument specifies the list of files for the
    policy digests that has to be compounded resulting in individual policies
    being added to final policy digest that can authenticate the object. The
    list begins with the policy digest hash alg. Example sha256:policy1,policy2

  * **-l**, **\--policy-list**=_POLICY\_FILE_\_LIST:

    This option is DEPRECATED yet is retained for backwards compatibility. Use the
    argument method instead. **NOTE**: When **-l** and an argument is specified
    it's the same as specifying it all at once. For instance:
    `tpm2_policyor -l sha256:file1 sha256:file2` is the same as
    `tpm2_policyor sha256:file1,file2`.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Create an authorization policy for a sealing object that compounds a pcr policy
and a policypassword in an OR fashion and show satisfying either policies could
unseal the secret.

## Create policypcr as first truth value for compounding the policies
```bash
tpm2_startauthsession -S session.ctx
tpm2_policypcr -S session.ctx -L policy.pcr -l sha256:0,1,2,3
tpm2_flushcontext session.ctx
```

## Create policypassword as second truth value for compounding the policies
```bash
tpm2_startauthsession -S session.ctx
tpm2_policypassword -S session.ctx -L policy.pass
tpm2_flushcontext session.ctx
```

## Compound the two policies in an OR fashion with tpm2_policyor command
```bash
tpm2_startauthsession -S session.ctx
tpm2_policyor -S session.ctx -L policy.or sha256:policy.pass,policy.pcr
tpm2_flushcontext session.ctx
```

## Create a sealing object and attach the auth policy from tpm2_policyor command
```bash
tpm2_createprimary -c prim.ctx -Q
echo "secret" | tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv \
-L policy.or -i-
```

## Satisfy auth policy using password and unseal the secret
```bash
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypassword -S session.ctx
tpm2_policyor -S session.ctx sha256:policy.pass,policy.pcr
tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx
```

## Satisfy auth policy using pcr and unseal the secret
```bash
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha256:0,1,2,3
tpm2_policyor -S session.ctx sha256:policy.pass,policy.pcr
tpm2_unseal -c key.ctx -p session:session.ctx
tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
