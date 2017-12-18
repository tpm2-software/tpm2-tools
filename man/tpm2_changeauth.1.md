% tpm2_changeauth(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_changeauth**(1) - Insert authorization values for the owner, endorsement
and lockout authorizations.

# SYNOPSIS

**tpm2_changeauth** [*OPTIONS*]

# DESCRIPTION

**tpm2_changeauth**(1) - set the various (owner, endorse, locakout)
authorization values.

# OPTIONS

  * **-o**, **--owner-passwd**=_OWNER\_PASSWORD_:
    The new owner authorization value.

    Passwords should follow the password formatting standards, see section
    "Password Formatting".

  * **-e**, **--endorse-passwd**=_ENDORSE\_PASSWORD_:

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * **-l**, **--lockout-passwd**=_LOCKOUT\_PASSWORD_:

    The new lockout authorization value.

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * **-O**, **--old-owner-passwd**=_OLD\_OWNER\_PASSWORD_:

    The old owner authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * **-E**, **--old-endorse-passwd**=_OLD\_ENDORSE\_PASSWORD_:

    The old endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * **-L**, **--old-lockout-passwd**=_OLD\_LOCKOUT\_PASSWORD_:

    The old lockout authorization value. Passwords should follow the same
    formatting requirements as the -o option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

Set owner, endorsement and lockout authorizations to a new value:

```
tpm2_changeauth -o newo -e newe -l newl -O oldo -E olde -L oldl
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)
