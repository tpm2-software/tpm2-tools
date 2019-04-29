% tpm2_clearlock(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_clearlock**(1) - Lock/unlock access to the clear operation.

# SYNOPSIS

**tpm2_clearlock** [OPTIONS]

# DESCRIPTION

**tpm2_clearlock**(1) - Allow a user to enable (unlock) or disable (lock)
access to the **tpm2_clear** operation. If the lockout password option
is missing, assume NULL.

# OPTIONS

  * **-c**, **\--clear**:

    Specifies the tool should unlock access to the clear command.
    By default it will try to disable the clear command.

  * **-p**, **\--platform**:

    Specifies the tool should operate on the platform hierarchy. By default
    it operates on the lockout hierarchy.

    **NOTE : Operating on platform hierarchy require platform authentication.**

  * **-L**, **\--auth-lockout**=_LOCKOUT\_PASSWORD_:

    The lockout authorization value.

    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".
    This tool only respects the *Password* and *HMAC* options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Enable the clear command on the platform hierarchy
```
tpm2_clearlock -c -p -L lockoutpasswd
```

## Disable the clear command on the lockout hierarchy
```
tpm2_clearlock
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
