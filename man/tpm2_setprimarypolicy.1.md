% tpm2_setprimarypolicy(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_setprimarypolicy**(1) - Sets the authorization policy for the lockout
(lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy
(ownerPolicy), and the endorsement hierarchy (endorsementPolicy).

# SYNOPSIS

**tpm2_setprimarypolicy** [*OPTIONS*]

# DESCRIPTION

**tpm2_setprimarypolicy**(1) -  Sets the authorization policy for the lockout
(lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy
(ownerPolicy), and the endorsement hierarchy (endorsementPolicy).

# OPTIONS

These options control creating the policy authorization session:

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy whose authorization policy is to be setup. It can be
    specified as o|p|e|l

 * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-L**, **\--policy**=_FILE_:

    The file path of the authorization policy data.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used in computation of the policy digest.

 * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

## Set a blank authorization policy for endorsement hierarchy
```bash
tpm2_setprimarypolicy -C e
```

[returns](common/returns.md)

[footer](common/footer.md)
