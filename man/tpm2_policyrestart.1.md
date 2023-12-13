% tpm2_policyrestart(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policyrestart**(1) - Restart an existing session with the TPM.

# SYNOPSIS

**tpm2_policyrestart** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyrestart**(1) - Restarts a session with the TPM back to it's
initial state. This is useful when the TPM gives one a **TPM_RC_PCR_CHANGED**
(`0x00000128`) error code when using a PCR policy session.

This will be returned if a PCR state affecting policy is altered during the
session. One could restart the session and try again, however, the PCR state
would still need to satisfy the policy.

# OPTIONS

  * **-S**, **\--session**=_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.
    This session is used in lieu of starting a session and using the PCR policy
    options.

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

## Start a *policy* session and restart it, unsealing some data.

```bash
# create a policy and bind it to an object
tpm2_startauthsession -S session.dat

tpm2_policypcr -S session.dat -l "sha1:0,1,2,3" -L policy.dat

tpm2_createprimary -c primary.ctx

tpm2_create -Cprimary.ctx -u key.pub -r key.priv -L policy.dat -i- <<< "secret"

tpm2_load -C primary.ctx -c key.ctx -u key.pub -r key.priv

tpm2_flushcontext session.dat

# satisfy the policy and use the object
tpm2_startauthsession --policy -S session.dat

tpm2_policypcr -S session.dat -l "sha1:0,1,2,3"

# PCR event occurs here causing unseal to fail
tpm2_pcrevent 0 <<< "event data"

tpm2_unseal -psession:session.dat -c key.ct
ERROR: Esys_Unseal(0x128) - tpm:error(2.0): PCR have changed since checked

# Clear the policy digest to initial state, note access to object no longer allowed by
# policy so policyor would be useful here.
tpm2_policyrestart -S session.dat
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
