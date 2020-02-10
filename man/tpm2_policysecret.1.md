% tpm2_policysecret(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policysecret**(1) - Couples the authorization of an object to that of an
existing object.

# SYNOPSIS

**tpm2_policysecret** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_policysecret**(1) - Couples the authorization of an object to that of an
existing object without requiring exposing the existing secret until time of
object use.

# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    A context object specifier of a transient/permanent/persistent object. Either
    a file path of a object context blob or a loaded/persistent/permanent handle
    id. See section "Context Object Format". As an argument, it takes the auth
    value of the associated TPM object, a single dash - can be used to read the
    auth value from stdin. The argument follows the "authorization formatting
    standards", see section "Authorization Formatting".

  * **-S**, **\--session**=_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-L**, **\--policy**=_FILE_:

    File to save the policy digest.

  * **-t**, **\--expiration**=_NATURAL_NUMBER_:

    Set the expiration time of the policy in seconds. In absence of nonceTPM
    the expiration time is the policy timeout value. If expiration value
    is 0 then the policy does not have a time limit on the authorization.

  * **\--ticket**=_FILE_:

    The ticket file to record the authorization ticket structure.

  * **\--timeout**=_FILE_:

    The file path to record the timeout structure returned.

  * **-x**, **\--nonce-tpm**:

    Enable the comparison of the current session's nonceTPM to ensure the
    validity of the policy authorization is limited to the current session.

  * **-q**, **\--qualification**=_FILE\_OR\_HEX\_STR_:

    Optional, the policy qualifier data that the signer can choose to include in the
    signature. Can be either a hex string or path.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash to be used in
    an audit or a policycphash.

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

Associate auth value of a sealing object to the owner hierarchy password.
* Start a trial auth session and run **tpm2_policysecret**(1) to create policy
that can only be satisfied if owner hierarchy auth value is supplied.
* Start a real policy session and provide the owner hierarchy auth value.
* Provide the session input where in the policysecret for owner hierarchy auth
was satisfied to the unseal tool.
* If the policy was satisfied unsealing should succeed.

## Generate a policy that binds to the secret of the owner hiearchy
```bash
tpm2_startauthsession -S session.ctx

tpm2_policysecret -S session.ctx -c o -L secret.policy

tpm2_flushcontext session.ctx
```

## Create a TPM object using the policy
```bash
tpm2_createprimary -Q -C o -g sha256 -G rsa -c prim.ctx

tpm2_create -Q -g sha256 -u sealing_key.pub -r sealing_key.priv -i- \
  -C prim.ctx -L secret.policy <<< "SEALED-SECRET"

tpm2_load -C prim.ctx -u sealing_key.pub -r sealing_key.priv \
  -c sealing_key.ctx
```

## Satisfy the policy and unseal the secret
```bash
tpm2_startauthsession --policy-session -S session.ctx

tpm2_policysecret -S session.ctx -c o -L secret.policy

tpm2_unseal -p "session:session.ctx" -c sealing_key.ctx
SEALED-SECRET

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[limitations](common/policy-limitations.md)

[footer](common/footer.md)
