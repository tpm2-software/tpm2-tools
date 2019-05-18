% tpm2_policyrestart(1) tpm2-tools | General Commands Manual
%
% JANUARY 2018

# NAME

**tpm2_policyrestart**(1) - Restart an existing session with the TPM.

# SYNOPSIS

**tpm2_policyrestart** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyrestart**(1) - Restarts a session with the TPM back to it's
initial state. This is useful when the TPM gives one a **TPM_RC_PCR_CHANGED**
(`0x00000128`) error code when using a PCR policy session.

This will be returned if a PCR state affecting policy is altered during the session. One could restart the session and try again, however, the PCR
state would still need to satisfy the policy

# OPTIONS

  * **-S**, **\--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.
    This session is used in lieu of starting a session and using the PCR policy options.
    **-L** is mutually exclusive of this option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Start a *policy* session and restart it, unsealing some data.

```
tpm2_startauthsession \--policy-session

tpm2_policypcr -Q -S session.dat -L "sha1:0,1,2,3" -F pcr.dat -o policy.dat

# PCR event occurs here causing unseal to fail
tpm2_unseal -S session.dat -c unseal.key.ctx
"Sys_Unseal failed. Error Code: 0x00000128"

# Clear the policy digest by restarting the policy session, try again, PCR state must satisfy policy
tpm2_policyrestart -S session.dat

tpm2_policypcr -Q -S session.dat -L "sha1:0,1,2,3" -F pcr.dat -o policy.dat

tpm2_unseal -S session.dat -c unseal.key.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
