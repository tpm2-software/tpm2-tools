% tpm2_dictionarylockout(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_dictionarylockout**(1) - Setup or clear dictionary-attack-lockout
parameters.

# SYNOPSIS

**tpm2_dictionarylockout** [*OPTIONS*]

# DESCRIPTION

**tpm2_dictionarylockout**(1) - Setup dictionary-attack-lockout parameters or
clear dictionary-attack-lockout state.

# OPTIONS

  * **-s**, **\--setup-parameters**:

    Specifies the tool should operate to setup dictionary-attack-lockout
    parameters.

  * **-c**, **\--clear-lockout**:

    Specifies the tool should operate to clear dictionary-attack-lockout state.

  * **-l**, **\--lockout-recovery-time**=_NATURAL_NUMBER_:

    Specifies the wait time in seconds before another **TPM_RH_LOCKOUT**
    authentication attempt can be made after a failed authentication.

  * **-t**, **\--recovery-time**=_NATURAL_NUMBER_:

    Specifies the wait time in seconds before another DA-protected-object
    authentication attempt can be made after max-tries number of failed
    authentications.

  * **-n**, **\--max-tries**=_NATURAL_NUMBER_:

    Specifies the maximum number of allowed authentication attempts on
    DA-protected-object; after which DA is activated.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the lockout handle.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

```bash
tpm2_dictionarylockout -c -p passwd

tpm2_dictionarylockout -s -n 5 -t 6 -l 7 -p passwd
```

[returns](common/returns.md)

[footer](common/footer.md)
