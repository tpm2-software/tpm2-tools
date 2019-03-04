% tpm2_policysecret(1) tpm2-tools | General Commands Manual
%
% OCTOBER 2018

# NAME

**tpm2_policysecret**(1) - Enables secret(password/hmac) based authorization to
a policy.

# SYNOPSIS

**tpm2_policysecret** [*OPTIONS*] _AUTH\_VALUE_

# DESCRIPTION

**tpm2_policysecret**(1) Enables secret (password/hmac) based authorization to a
 policy. The secret is the auth value of any TPM object (NV/Hierarchy/Loaded/
 Persistent).

# OPTIONS

  * **-c**, **--context**=_OBJECT_CONTEXT_:

    A context object specifier of a transient/permanent/persistent object. Either
    a file path of a object context blob or a loaded/persistent/permanent handle
    id. See section "Context Object Format". As an argument, it takes the auth
    value of the associated TPM object, a single dash - can be used to read the
    auth value from stdin. The argument follows the "authorization formatting
    standards", see section "Authorization Formatting".

  * **-S**, **--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-o**, **--policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

Associate auth value of a sealing object to the owner hierarchy password.
* Start a trial auth session and run **tpm2_policysecret** to create policy that
can only be satisfied if owner hierarchy auth value is supplied.
* Start a real policy session and provide the owner hierarchy auth value.
* Provide the session input where in the policysecret for owner hierarchy auth
was satisfied to the unseal tool.
* If the policy was satisfied unsealing should succeed.

## Generate a policy that binds to the secret of the auth object:
* TPM_RH_OWNER=0x40000001
* tpm2_startauthsession -S session.ctx
* tpm2_policysecret -S session.ctx -c $TPM_RH_OWNER -o secret.policy
* tpm2_flushcontext -S session.ctx

## Create a TPM object like a sealing object with the policy:
* tpm2_createprimary -Q -a o -g sha256 -G rsa -o prim.ctx
* tpm2_create -Q -g sha256 -u sealing_key.pub -r sealing_key.priv -i- -C prim.ctx
-L secret.policy <<< "SEALED-SECRET"
tpm2_load -C prim.ctx -u sealing_key.pub -r sealing_key.priv -n sealing_key.name -o sealing_key.ctx

## Satisfy the policy and unseal the secret:
* tpm2_startauthsession -a -S session.ctx
* tpm2_policysecret -S session.ctx -c $TPM_RH_OWNER -o secret.policy
* unsealed=`tpm2_unseal -p "session:session.ctx" -c sealing_key.ctx`
* echo $unsealed
* tpm2_flushcontext -S session.ctx

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
