% tpm2_changeauth(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_changeauth**(1) - Insert authorization values for the owner, endorsement
and lockout authorizations.

# SYNOPSIS

**tpm2_changeauth** [*OPTIONS*]

# DESCRIPTION

**tpm2_changeauth**(1) - set the various (owner, endorse, lockout)
authorization values.

# OPTIONS

  * **-o**, **--owner-passwd**=_OWNER\_PASSWORD_:
    The new owner authorization value.

    Passwords should follow the password authorization formatting standards,
    see section "Authorization Formatting".

  * **-e**, **--endorse-passwd**=_ENDORSE\_PASSWORD_:

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the **-o** option.

  * **-l**, **--lockout-passwd**=_LOCKOUT\_PASSWORD_:

    The new lockout authorization value.

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the **-o** option.

  * **-O**, **--old-auth-owner**=_OLD\_OWNER\_AUTH_:

    The old owner authorization value.
    Authorization values should follow the password authorization formatting
    standards, see section "Authorization Formatting".

  * **-E**, **--old-auth-endorse**=_OLD\_ENDORSE\_AUTH_:

    The old endorse authorization value. Authorizations should follow the same
    formatting requirements as the **-O** option.

  * **-L**, **--old-auth-lockout**=_OLD\_LOCKOUT\_AUTH_:

    The old lockout authorization value. Authorizations should follow the same
    formatting requirements as the **-O** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/password.md)

# EXAMPLES

Set owner, endorsement and lockout authorizations to a new value:

```
tpm2_changeauth -o newo -e newe -l newl -O oldo -E olde -L oldl
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
