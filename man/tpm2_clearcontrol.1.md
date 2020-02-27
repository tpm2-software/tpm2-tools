% tpm2_clearcontrol(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_clearcontrol**(1) - Set/ Clear TPMA_PERMANENT.disableClear attribute to
effectively block/ unblock lockout authorization handle for issuing TPM clear.

# SYNOPSIS

**tpm2_clearcontrol** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_clearcontrol**(1) - Allows user with knowledge of either lockout auth
and or platform hierarchy auth to set disableClear which prevents the lockout
authorization's capability to execute tpm2_clear. Only user with authorization
knowledge of the platform hierarchy can clear the disableClear. By default it
attempts to clear the disableClear bit.

Note: Platform hierarchy auth handle can always be used to clear the TPM with
tpm2_clear command.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies what auth handle, either platform hierarchy or lockout the tool
    should operate on. By default it operates on the platform hierarchy handle.
    Specify the handle as p|l|platform|lockout.

    **NOTE : Operating on platform hierarchy require platform authentication.**

  * **-P**, **\--auth**=_AUTH_:

    The authorization value of the hierarchy specified with **-C**.
    This tool only respects the *Password* and *HMAC* options.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT**  ** Specify an integer 0|1 or string c|s to clear or set the
    disableClear attribute.

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

## Set the disableClear to block the lockout authorization's access to TPM clear
```bash
tpm2_clearcontrol -C l s
```

## Clear the disableClear to unblock lockout authorization for TPM clear
```bash
tpm2_clearcontrol -C p c
```

[returns](common/returns.md)

[footer](common/footer.md)
