% tpm2_startauthsession(1) tpm2-tools | General Commands Manual
%
% JANUARY 2018

# NAME

**tpm2_startauthsession**(1) - Start a session with the TPM.

# SYNOPSIS

**tpm2_startauthsession** [*OPTIONS*]

# DESCRIPTION

**tpm2_startauthsession**(1) Starts a session with the TPM. The default is
to start a *trial* session unless the **-a** option is specified.
Saves the policy session data to a file. This file can then be used in subsequent
tools that can use a policy file for authorization or policy events. **NOTE**: That
this will not work with resource managers (RMs) outside of tpm2-abrmd, as most RMs will
flush session handles when a client disconnects from the IPC channel. This will work
with direct TPM access, but note that internally this calls a *ContextSave* and a
*ContextLoad* on the session handle, thus the session **cannot** be saved/loaded
again.

# OPTIONS

  * **-a**, **--auth-policy-session**:

    Change the policy session from a *trial* session to a *policy* session.
    **NOTE**: A *trial* session is used when building a policy and a *policy*
    session is used when authenticating with a policy.

  * **-g**, **--policy-digest-alg**=_HASH\_ALGORITHM_:

    The hash algorithm used in computation of the policy digest. Algorithms
    should follow the "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-S**, **--session**=_SESSION\_FILE\_NAME_:

    The name of the policy session file, optional. Defaults to *session.ctx*.


[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Start a *trial* session and save the session data to a file.
```
tpm2_startauthsession -S mysession.ctx
```

Start a *policy* session and save the session data to a file.
```
tpm2_startauthsession -S mysession.ctx -a
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
