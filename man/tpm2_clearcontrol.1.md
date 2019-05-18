% tpm2_clearcontrol(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_clearcontrol**(1) - Set/ Clear TPMA_PERMANENT.disableClear attribute to
effectively block/ unblock lockout authorization handle for issuing TPM clear.

# SYNOPSIS

**tpm2_clearcontrol** [*OPTIONS*] _OPERATION_

# DESCRIPTION

**tpm2_clearcontrol**(1) - Allows user with knowledge of either lockout auth
and or platform hierarchy auth to set disableClear which prevents the lockout
authorization's capability to execute tpm2_clear. Only user with authorization
knowledge of the platform hierarchy can clear the disableClear. ** As an argument
the tool takes the _OPERATION_ as an integer 0|1 or string c|s to clear or set
the disableClear attribute. By default it attempts a CLEAR operation**
Note: Platform hierarchy auth handle can always be used to clear the TPM with
tpm2_clear command. If password option is missing, assume NULL.

# OPTIONS

  * **-a**, **\--auth-handle**=_TPM\_HANDLE:

    Specifies what auth handle, either platform hierarchy or lockout the tool
    should operate on. By default it operates on the platform hierarchy handle.
    Specify the handle as p|l|platform|lockout.

    **NOTE : Operating on platform hierarchy require platform authentication.**

  * **-p**, **\--auth**=_HANDLE\_PASSWORD:

    The handle's authorization value.

    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".
    This tool only respects the *Password* and *HMAC* options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Set the disableClear to block the lockout authorization's access to TPM clear
```
tpm2_clearcontrol -a l s
```

## Clear the disableClear to unblock lockout authorization for TPM clear operation
```
tpm2_clearcontrol -a p c
```

[returns](common/returns.md)

[footer](common/footer.md)
