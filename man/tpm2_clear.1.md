% tpm2_clear(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_clear**(1) - Send a clear command to the TPM.

# SYNOPSIS

**tpm2_clear** [OPTIONS]

# DESCRIPTION

**tpm2_clear**(1) - Send a clear command to the TPM, i.e. clear the 3 authorization
values. If the lockout password option is missing, assume NULL.

# OPTIONS

  * **-p**, **\--platform**:

    Specifies the tool should operate on the platform hierarchy. By default
    it operates on the lockout hierarchy.

    **NOTE : Operating on platform hierarchy require platform authentication.**

  * **-L**, **\--auth-lockout**=_LOCKOUT\_AUTH_:

    The lockout authorization value.

    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Set owner, endorsement and lockout authorizations to an empty value

```
tpm2_clear -L oldlockoutpasswd
```

## Clear the authorization values on the platform hierarchy
```
tpm2_clear -p
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
