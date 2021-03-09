% tpm2_changeauth(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_changeauth** - Changes authorization values for TPM objects.

# SYNOPSIS

**tpm2_changeauth** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_changeauth** - Configures authorization values for the various
hierarchies, NV indices, transient and persistent objects.

Note: For non-permanent objects (Transient objects and Persistent objects),
copies of the private information (files or persistent handles) created prior
to changing auth are not invalidated.

# OPTIONS

Passwords should follow the "password authorization formatting standards",
see section "Authorization Formatting".

  * **-c**, **\--object-context**=_OBJECT_:

    The key context object to be used for the operation.

  * **-p**, **\--object-auth**=_AUTH_:

    The old authorization value for the TPM object specified with **-c**.

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent object. This is required if the object for the operation is a
    transient or persistent object.

  * **-r**, **\--private**=_FILE_:
    The output file which contains the new sensitive portion of the object whose
    auth was being changed.
    [protection details](common/protection-details.md)

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is
    also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

  * **ARGUMENT** the command line argument specifies the _AUTH_ to be set for
    the object specified with **-c**.

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

## Set owner, endorsement and lockout authorizations to newpass
```bash
tpm2_changeauth -c owner newpass
tpm2_changeauth -c endorsement newpass
tpm2_changeauth -c lockout newpass
```

## Change owner, endorsement and lockout authorizations
```bash
tpm2_changeauth -c o -p newpass newerpass
tpm2_changeauth -c e -p newpass newerpass
tpm2_changeauth -c l -p newpass newerpass
```

## Set owner authorization to empty password
```bash
tpm2_changeauth -c o -p oldpass
```

## Modify authorization for a loadable transient object
```bash
tpm2_createprimary -Q -C o -c prim.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv -C prim.ctx

tpm2_load -C prim.ctx -u key.pub -r key.priv -n key.name -c key.ctx

tpm2_changeauth -c key.ctx -C prim.ctx -r key.priv newkeyauth
```

## Modify authorization for a NV Index

Requires Extended Session Support.

```bash
tpm2_startauthsession -S session.ctx

tpm2_policycommandcode -S session.ctx -L policy.nvchange TPM2_CC_NV_ChangeAuth
tpm2_flushcontext session.ctx

NVIndex=0x1500015
tpm2_nvdefine   $NVIndex -C o -s 32 -a "authread|authwrite" -L policy.nvchange
tpm2_startauthsession \--policy-session -S session.ctx

tpm2_policycommandcode -S session.ctx -L policy.nvchange TPM2_CC_NV_ChangeAuth

tpm2_changeauth -p session:session.ctx -c $NVIndex newindexauth
```

[returns](common/returns.md)

[footer](common/footer.md)
