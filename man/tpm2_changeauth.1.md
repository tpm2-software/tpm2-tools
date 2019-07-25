% tpm2_changeauth(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_changeauth** - Changes authorization values for TPM objects.

# SYNOPSIS

**tpm2_changeauth** [*OPTIONS*] [NEW\_PASSWORD]

# DESCRIPTION

**tpm2_changeauth** - Configures authorization values for the various hierarchies,
NV indices, transient and persistent objects.

Note: For non-permanent objects (Transient objects and Persistent objects),
copies of the private information (files or persistent handles) created prior
to changing auth are not invalidated.

# OPTIONS

Passwords should follow the "password authorization formatting standards",
see section "Authorization Formatting".

  * **-p**, **\--object-auth**=_OBJECT\_AUTH_:

    The old authorization value for the TPM object. Follows the "Authorization Formatting"
    section below.

  * **-c**, **\--object-context**=_OBJECT\_CONTEXT\_OBJECT_:

    The key context object to be used for the operation.
    See section "Context Object Format" for details.

  * **-C**, **\--parent-context**=_PARENT\_CONTEXT\_OBJECT_:

    The parent object. This is required if the object for the operation is a
    transient or persistent object.
    See section "Context Object Format" for details.

  * **-r**, **\--private**=_OUTPUT\_PRIVATE\_FILE_:
    The output file which contains the new sensitive portion of the object whose auth was being changed.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[context object format](common/ctxobj.md)

# EXAMPLES

## Set owner, endorsement and lockout authorizations to newpass
```
tpm2_changeauth -c owner newpass
tpm2_changeauth -c endorsement newpass
tpm2_changeauth -c lockout newpass
```

## Change owner, endorsement and lockout authorizations from newpass to a new value
```
tpm2_changeauth -c o -p newpass newerpass
tpm2_changeauth -c e -p newpass newerpass
tpm2_changeauth -c l -p newpass newerpass
```

## Set owner authorization to empty password
```
tpm2_changeauth -c o -p oldpass
```

## Modify authorization for a loadable transient object
```
tpm2_createprimary -Q -C o -c prim.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx

tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -c key.ctx

tpm2_changeauth -c key.ctx -C prim.ctx -r key.priv newkeyauth
```

## Modify authorization for a NV Index

Requires Extended Session Support.

```
tpm2_startauthsession -S session.ctx

tpm2_policycommandcode -S session.ctx -L policy.nvchange nvchangeauth
tpm2_flushcontext session.ctx

NVIndex=0x1500015
tpm2_nvdefine -x $NVIndex -a o -s 32 -t "authread|authwrite" -L policy.nvchange
tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policycommandcode -S session.ctx -L policy.nvchange nvchangeauth

tpm2_changeauth -p session:session.ctx -c $NVIndex newindexauth
```

[returns](common/returns.md)

[footer](common/footer.md)
