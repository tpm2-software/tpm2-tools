% tpm2_clearlock(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

tpm2_clearlock(1) - lock/unlock access to the clear operation.

# SYNOPSIS

`tpm2_clearlock` [OPTIONS]

# DESCRIPTION

tpm2_clearlock(1) - allows a user to enable (unlock) or disable (lock)
access to the TPM2_Clear() operation. If the lockout password option
is missing, assume NULL.

# OPTIONS

  * **-c**, **--clear**:
    specifies the tool should unlock access to the clear command.
    By default it will try to disable the clear command.

  * **-p**, **--platform**:
    specifies the tool should operate on the platform hierarchy. By default
    it operates on the lockout hierarchy.

  * **-L**, **--lockout-passwd**=_LOCKOUT\_PASSWORD_:
    The lockout authorization value.

    Passwords should follow the password formatting standards, see section
    "Password Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

Enable the clear command on the platform hierarchy.

```
tpm2_clearlock -c -p -L lockoutpasswd
```

Disable the clear command on the lockout hierarchy

```
tpm2_clearlock
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
