% tpm2_changeauth(1) tpm2-tools | General Commands Manual
%
% OCTOBER 2018

# NAME

**tpm2_changeauth**(1) - Configuring authorization for TPM OWNER/ENDORSEMENT/LOCKOUT hierarchies,
NV Handles and Transient & Persistent object handles.

# SYNOPSIS

**tpm2_changeauth** [*OPTIONS*]

# DESCRIPTION

**tpm2_changeauth**(1) - Managing authorization passwords for TPM objects/ handles.
1. Permanent Handles (Owner, Endorsement, Lockout).
2. Persistent Handles (0x81XX_XXXX).
3. Transient Handles (0x80XX_XXXX).
4. NV Handles (0x01XX_XXXX).

Note: For non-permanent objects (Transient objects and Persistent objects),
copies of the private information (files or persistent handles) created prior
to changing auth are not invalidated.

# OPTIONS

Passwords should follow the "password authorization formatting standards",
see section "Authorization Formatting".

  * **-w**, **\--new-owner-passwd**=_OWNER\_PASSWORD_:

    The new authorization value for the owner hierarchy.

  * **-e**, **\--new-endorsement-passwd**=_ENDORSEMENT\_PASSWORD_:

    The new authorization value for the endorsement hierarchy.

  * **-l**, **\--new-lockout-passwd**=_LOCKOUT\_PASSWORD_:

    The new authorization value for the dictionary lockout.

  * **-W**, **\--current-owner-passwd**=_CURRENT\_OWNER\_AUTH_:

    The current authorization value for the owner hierarchy .

  * **-E**, **\--current-endorsement-passwd**=_CURRENT\_ENDORSEMENT\_AUTH_:

    The current authorization value for the endorsement hierarchy.

  * **-L**, **\--current-lockout-passwd**=_CURRENT\_LOCKOUT\_AUTH_:

    The current authorization value for the dictionary lockout authority.

  * **-p**, **\--new-handle-passwd**=_TPM\_HANDLE\_PASSWORD_:

    The new authorization value for the TPM handle.

  * **-P**, **\--current-handle-passwd**=_CURRENT\_TPM\_HANDLE\_PASSWORD_:

    The current authorization value for the TPM handle .

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Name of the key context object to be used for the operation.
    Either a file or a handle number. See section "Context Object Format".

  * **-C**, **\--parent-context**=_PARENT\_CONTEXT\_OBJECT_:
    Name of the parent context object specified either with a file or a handle number
    (see section "Context Object Format").
    This is the parent of the object whose auth is being modified with **\--key-context** option.

  * **-r**, **\--privfile**=_OUTPUT\_PRIVATE\_FILE_:
    The output file which contains the new sensitive portion of the object whose auth was being changed.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Set owner, endorsement and lockout authorizations
```
tpm2_changeauth -o newo -e newe -l newl
```

## Set owner, endorsement and lockout authorizations to a new value
```
tpm2_changeauth -o newo -e newe -l newl -O oldo -E olde -L oldl
```

## Unset/Clear owner authorization which was previously set to value newo
```
tpm2_changeauth -O newo
```

## Modify authorization for a loadable transient object
```
tpm2_createprimary -Q -a o -o prim.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx

tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -o key.ctx

tpm2_changeauth -p newkeyauth -c key.ctx -a prim.ctx -r key.priv
```

## Modify authorization for a NV Index - Requires Extended Session Support
```
tpm2_startauthsession -S session.ctx

TPM2_NV_ChangeAuth=0x13B
tpm2_policycommandcode -S session.ctx -c $TPM2_NV_ChangeAuth -o policy.nvchange
tpm2_flushcontext -S session.ctx

NVIndex=0x1500015
tpm2_nvdefine -x $NVIndex -a o -s 32 -t "authread|authwrite" -L policy.nvchange
tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policycommandcode -S session.ctx -c $TPM2_NV_ChangeAuth -o policy.nvchange

tpm2_changeauth -P session:session.ctx -p newindexauth -c $NVIndex
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
