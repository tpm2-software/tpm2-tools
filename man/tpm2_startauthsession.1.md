% tpm2_startauthsession(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_startauthsession**(1) - Start a session with the TPM.

# SYNOPSIS

**tpm2_startauthsession** [*OPTIONS*]

# DESCRIPTION

**tpm2_startauthsession**(1) - Starts a session with the TPM. The default is
to start a *trial* session unless the **-a** option is specified.
Saves the policy session data to a file. This file can then be used in subsequent
tools that can use a policy file for authorization or policy events.

This will not work with resource managers (RMs) outside of [tpm2-abrmd](https://
github.com/tpm2-software/tpm2-abrmd), as most RMs will flush session handles
when a client disconnects from the IPC channel.

This will work with direct TPM access, but note that internally this calls a
*ContextSave* and a *ContextLoad* on the session handle, thus the session
**cannot** be saved/loaded again.

# OPTIONS

  * **\--policy-session**:

    Start a policy session of type **TPM_SE_POLICY**. Default without this option
    is **TPM_SE_TRIAL**.
    **NOTE**: A *trial* session is used when building a policy and a *policy*
    session is used when authenticating with a policy.

  * **\--audit-session**:

    Start an HMAC session to be used as an audit session. Default without
    this option is **TPM2_SE_TRIAL**.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used in computation of the policy digest.

  * **-c**, **\--key-context**=_OBJECT_:

    Set the session encryption and bind key. When using this, sensitive data
    transmitted to the TPM will be encrypted with AES128CFB. **This prevents bus
    snooping attacks.**

  * **-S**, **\--session**=_FILE_:

    The name of the policy session file, required.

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

## Start a *trial* session and save the session data to a file
```bash
tpm2_startauthsession -S mysession.ctx
```

## Start a *policy* session and save the session data to a file
```bash
tpm2_startauthsession --policy-session -S mysession.ctx
```

## Start an encrypted and bound *policy* session and save the session data to a file
```bash
tpm2_createprimary -c primary.ctx
tpm2_startauthsession --policy-session -c primary.ctx -S mysession.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
