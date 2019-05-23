% tpm2_dictionarylockout(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_dictionarylockout**(1) - setup or clear dictionary-attack-lockout parameters.

# SYNOPSIS

**tpm2_dictionarylockout** [*OPTIONS*]

# DESCRIPTION

**tpm2_dictionarylockout**(1) - setup dictionary-attack-lockout parameters or clear
dictionary-attack-lockout state, if any password option is missing, assume NULL.

# OPTIONS

  * **-s**, **--setup-parameters**:
    specifies the tool should operate to setup dictionary-attack-lockout
    parameters.

  * **-c**, **--clear-lockout**:
    specifies the tool should operate to clear dictionary-attack-lockout state.

  * **-l**, **--lockout-recovery-time**=_LOCKOUT\_TIME_:
    specifies the wait time in seconds before another TPM_RH_LOCKOUT
    authentication attempt can be made after a failed authentication.

  * **-P** ,**--lockout-passwd**=_LOCKOUT\_PASSWORD_:
    specifies the password of TPM_RH_LOCKOUT required for both setting up
    parameters / clearing dictionary-attack-lockout state.

  * **-t**, **--recovery-time**=_RECOVERY\_TIME_:
    specifies the wait time in seconds before another DA-protected-object
    authentication attempt can be made after max-tries number of failed
    authentications.

  * **-n**, **--max-tries**=_MAX\_TRYS_:
    specifies the maximum number of allowed authentication attempts on
    DA-protected-object; after which DA is activated.

  * **-S**, **--input-session-handle**=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_dictionarylockout -c -P password
tpm2_dictionarylockout -s -n 5 -t 6 -l 7 -P password
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
