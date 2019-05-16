% tpm2_clearcontrol(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_clearcontrol**(1) - Set/ Clear TPMA_PERMANENT.disableClear attribute to
effectively block/ unblock lockout authorization handle for issuing TPM clear.

# SYNOPSIS

**tpm2_clearcontrol** [OPTIONS]

# DESCRIPTION

**tpm2_clearcontrol**(1) - Allows user with knowledge of either lockout auth
and or platform hierarchy auth to set disableClear which prevents the lockout
authorization's capability to execute tpm2_clear. Only user with authorization
knowledge of the platform hierarchy can clear the disableClear.
Note: Platform hierarchy auth handle can always be used to clear the TPM with
tpm2_clear command. If password option is missing, assume NULL.

# OPTIONS

  * **-c**, **\--clear**:

    Specifies the tool should unblock access to the clear command.
    This default operation will try clearing the disableClear to enable the
    lockout authorization capability to execute the TPM clear command.

    **NOTE : Only platform hierarchy auth is acceptable to clear disableClear**

  * **-s**, **\--set**:

    Specifies the tool should block lockout authorization access to the TPM clear
    command by setting the disableClear.

  * **-a**, **\--auth-handle**=_TPM\_HANDLE:

    Specifies what auth handle, either platform hierarchy or lockout the tool
    should operate on. By default it operates on the lockout permanent handle.

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
tpm2_clearcontrol -s -p lockoutpasswd
```

## Clear the disableClear to unblock lockout authorization for TPM clear operation
```
tpm2_clearcontrol -c -a p platformpasswd
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
